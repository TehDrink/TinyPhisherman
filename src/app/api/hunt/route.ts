/**
 * POST /api/hunt
 * Feature B: Brand protection — typosquat discovery + visual clone detection.
 *
 * Body: { domain: string }   e.g. "google.com"
 * Returns: text/event-stream of HuntProgressEvent, ending with a result event.
 */

import { NextRequest } from "next/server";
import { visitWithAgent } from "@/lib/tinyfish";
import { analyzeDOM, compareScreenshots } from "@/lib/llm";
import { discoverTyposquatCandidates, lexicalSimilarity } from "@/lib/typosquat";
import { runPassiveChecks } from "@/lib/passive-checks";
import { calcVariantThreatLevel } from "@/lib/threat-level";
import { triageWithUrlscan } from "@/lib/urlscan";
import type {
  HuntResult,
  TyposquatVariant,
  PassiveChecks,
  ThreatLevel,
  UrlscanVerdict,
} from "@/types";

const MAX_VARIANTS = Number(process.env.HUNT_MAX_VARIANTS ?? "8");
const MAX_CANDIDATES = Number(process.env.HUNT_MAX_CANDIDATES ?? "20");
const TINYFISH_CONCURRENCY = 4;

export type HuntProgressEvent =
  | { type: "progress"; pct: number; stage: string; message: string }
  | { type: "result"; data: HuntResult }
  | { type: "error"; error: string };

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const domain = (body as { domain?: unknown })?.domain;

  if (!domain || typeof domain !== "string") {
    return new Response(
      `data: ${JSON.stringify({ type: "error", error: "Missing or invalid `domain` field." })}\n\n`,
      { status: 400, headers: sseHeaders() }
    );
  }

  const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0];
  const originalUrl = `https://${cleanDomain}`;
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const emit = (event: HuntProgressEvent) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
        } catch {
          // Client disconnected — ignore
        }
      };

      try {
        // ── Stage 1: Discovery ─────────────────────────────────────────────
        emit({ type: "progress", pct: 5, stage: "discovery", message: "Generating lookalike candidates…" });

        const [originalPassive, discovery] = await Promise.all([
          runPassiveChecks(originalUrl),
          discoverTyposquatCandidates(cleanDomain),
        ]);

        emit({
          type: "progress",
          pct: 15,
          stage: "discovery",
          message: `Found ${discovery.candidates.length} candidates via ${discovery.method}.`,
        });

        // ── Stage 2: Original baseline ─────────────────────────────────────
        const captureBaseline = shouldCaptureOriginalWithTinyfish(originalPassive);
        if (captureBaseline) {
          emit({ type: "progress", pct: 18, stage: "baseline", message: `Capturing baseline screenshot of ${cleanDomain}…` });
        }

        const originalAgent = captureBaseline
          ? await visitWithAgent(originalUrl, { interact: false })
          : {
              url: originalUrl,
              screenshot: "",
              domText: "",
              finalUrl: originalPassive.finalResolvedUrl ?? originalUrl,
              statusCode: originalPassive.httpStatusCode ?? 0,
              pageTitle: "",
              hasLoginForm: false,
              formFields: [] as string[],
              formAction: null,
              offDomainSubmit: false,
              externalLinks: [] as string[],
            };

        // ── Stage 3: Passive triage ────────────────────────────────────────
        const slicedCandidates = discovery.candidates.slice(0, MAX_CANDIDATES);
        emit({
          type: "progress",
          pct: 22,
          stage: "passive_triage",
          message: `Running passive checks on ${slicedCandidates.length} candidates…`,
        });

        const candidateIntel = await Promise.all(
          slicedCandidates.map(async (candidate) => {
            const targetUrl = `https://${candidate}`;
            const [passive, urlscan] = await Promise.all([
              runPassiveChecks(targetUrl),
              triageWithUrlscan(targetUrl),
            ]);

            const certIssuedAt = discovery.certIssuedAt.get(candidate);
            const certAgeDays = certIssuedAt
              ? Math.floor((Date.now() - new Date(certIssuedAt).getTime()) / 86_400_000)
              : null;
            const certAgeBonus = certAgeDays !== null && certAgeDays < 30 ? 25 : 0;

            const score =
              lexicalSimilarity(cleanDomain, candidate) +
              (passive.dnsResolved ? 20 : -20) +
              ((passive.domainAgeDays ?? 999) < 30 ? 15 : 0) +
              (passive.hasSSL ? 0 : -10) +
              (urlscan?.verdictMalicious ? 100 : 0) +
              Math.min(urlscan?.verdictScore ?? 0, 40) +
              certAgeBonus;

            return { candidate, passive, urlscan, score, certAgeDays };
          })
        );

        const shortlisted = candidateIntel
          .sort((a, b) => b.score - a.score)
          .slice(0, MAX_VARIANTS);

        const deepScanTargets = shortlisted.filter(({ passive }) =>
          shouldDeployTinyfishForVariant(passive)
        );

        emit({
          type: "progress",
          pct: 38,
          stage: "passive_triage",
          message: `Shortlisted ${shortlisted.length} variants. ${deepScanTargets.length} qualify for TinyFish.`,
        });

        // ── Stage 4: TinyFish visits (with per-domain progress) ────────────
        const variantMap = new Map<string, Awaited<ReturnType<typeof visitWithAgent>> | Error>();

        if (deepScanTargets.length > 0) {
          const total = deepScanTargets.length;
          let completed = 0;

          // Process in batches of TINYFISH_CONCURRENCY
          for (let i = 0; i < deepScanTargets.length; i += TINYFISH_CONCURRENCY) {
            const batch = deepScanTargets.slice(i, i + TINYFISH_CONCURRENCY);

            emit({
              type: "progress",
              pct: Math.round(38 + (completed / total) * 37),
              stage: "tinyfish",
              message: `TinyFish scanning: ${batch.map((b) => b.candidate).join(", ")}`,
            });

            const settled = await Promise.allSettled(
              batch.map((item) => visitWithAgent(`https://${item.candidate}`, { interact: false }))
            );

            settled.forEach((result, idx) => {
              const url = `https://${batch[idx].candidate}`;
              variantMap.set(
                url,
                result.status === "fulfilled" ? result.value : toError(result.reason)
              );
              completed++;
            });
          }
        }

        // ── Stage 5: LLM analysis ──────────────────────────────────────────
        emit({
          type: "progress",
          pct: 76,
          stage: "analysis",
          message: `Running LLM analysis on ${shortlisted.length} variants…`,
        });

        const variantResults: TyposquatVariant[] = await Promise.all(
          shortlisted.map(async ({ candidate: variantDomain, passive, urlscan }) => {
            const variantUrl = `https://${variantDomain}`;
            const agentResult = variantMap.get(variantUrl);
            const eligibleForTinyfish = shouldDeployTinyfishForVariant(passive);

            if (!eligibleForTinyfish) {
              return {
                domain: variantDomain,
                threatLevel: calcPreliminaryThreatLevel(passive, urlscan),
                visualSimilarity: 0,
                manipulationScore: preliminaryManipulationScore(passive, urlscan),
                squatterCategory: "Unknown" as const,
                screenshot: "",
                liveStatus: passive.httpReachable ? "live" as const : passive.dnsResolved ? "unreachable" as const : "parked" as const,
                passiveChecks: passive,
                reasoning: buildTriageOnlyReason(passive),
                evidenceSnippets: [],
                urlscan,
              };
            }

            if (!agentResult || agentResult instanceof Error) {
              return {
                domain: variantDomain,
                threatLevel: calcPreliminaryThreatLevel(passive, urlscan),
                visualSimilarity: 0,
                manipulationScore: preliminaryManipulationScore(passive, urlscan),
                squatterCategory: "Unknown" as const,
                screenshot: "",
                liveStatus: passive.dnsResolved ? "unreachable" as const : "parked" as const,
                passiveChecks: passive,
                reasoning: passive.dnsResolved
                  ? "Variant passed preliminary triage but active TinyFish verification did not complete."
                  : "Variant did not resolve to a live site during passive checks.",
                evidenceSnippets: [],
                urlscan,
              };
            }

            const [llm, visual] = await Promise.all([
              analyzeDOM(
                agentResult.finalUrl ?? variantUrl,
                agentResult.domText,
                agentResult.formFields,
                agentResult.offDomainSubmit,
                {
                  expectedDomain: cleanDomain,
                  domainAgeDays: passive.domainAgeDays,
                  hasSSL: passive.hasSSL,
                  registrar: passive.registrar ?? undefined,
                  urlscanMalicious: urlscan?.verdictMalicious,
                  urlscanScore: urlscan?.verdictScore,
                }
              ),
              compareScreenshots(
                originalAgent.screenshot,
                agentResult.screenshot,
                cleanDomain,
                variantDomain
              ),
            ]);

            const threatLevel = calcVariantThreatLevel(llm, visual.score, passive, urlscan);

            return {
              domain: variantDomain,
              threatLevel,
              visualSimilarity: visual.score,
              manipulationScore: llm.manipulationScore,
              squatterCategory: llm.squatterCategory,
              screenshot: agentResult.screenshot,
              liveStatus: "live" as const,
              reasoning: llm.reasoning,
              passiveChecks: passive,
              finalUrl: agentResult.finalUrl,
              pageTitle: agentResult.pageTitle,
              evidenceSnippets: llm.evidenceSnippets ?? [],
              impersonatedBrand: llm.impersonatedBrand ?? null,
              urlscan,
            };
          })
        );

        emit({ type: "progress", pct: 95, stage: "analysis", message: "Compiling results…" });

        const result: HuntResult = {
          originalDomain: cleanDomain,
          originalScreenshot: originalAgent.screenshot,
          variants: variantResults.sort(compareVariantPriority),
          huntedAt: new Date().toISOString(),
          discoveryMethod: discovery.method,
        };

        emit({ type: "result", data: result });
      } catch (err) {
        console.error("[/api/hunt]", err);
        emit({ type: "error", error: err instanceof Error ? err.message : "Unknown error" });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, { headers: sseHeaders() });
}

function sseHeaders(): HeadersInit {
  return {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "X-Accel-Buffering": "no",
    Connection: "keep-alive",
  };
}

function toError(reason: unknown): Error {
  return reason instanceof Error ? reason : new Error("TinyFish visit failed.");
}

function shouldDeployTinyfishForVariant(passive: PassiveChecks): boolean {
  if (!passive.dnsResolved || !passive.httpReachable) return false;
  return passiveSuspicionScore(passive) >= 15;
}

function passiveSuspicionScore(passive: PassiveChecks): number {
  let score = 0;
  if ((passive.domainAgeDays ?? 999) < 90) score += 12;
  if (!passive.hasSSL) score += 10;
  if ((passive.redirectCount ?? 0) >= 2) score += 8;
  if ((passive.nameservers?.length ?? 0) <= 1) score += 5;
  if (!passive.registrar) score += 4;
  return score;
}

function calcPreliminaryThreatLevel(passive: PassiveChecks, urlscan: UrlscanVerdict | null): ThreatLevel {
  if (urlscan?.verdictMalicious) return "Critical";
  if ((urlscan?.verdictScore ?? 0) >= 70) return "High";
  if (passiveSuspicionScore(passive) >= 15 || (urlscan?.verdictScore ?? 0) >= 35) return "Medium";
  return "Low";
}

function preliminaryManipulationScore(passive: PassiveChecks, urlscan: UrlscanVerdict | null): number {
  return Math.min(100, Math.max(passiveSuspicionScore(passive) * 3, urlscan?.verdictScore ?? 0));
}

function buildTriageOnlyReason(passive: PassiveChecks): string {
  if (!passive.dnsResolved) return "Variant did not resolve during DNS checks, so TinyFish was not deployed.";
  if (!passive.httpReachable) return "Variant resolved in DNS but did not respond over HTTP(S), so TinyFish was not deployed.";
  return "Variant was reachable but did not look suspicious enough in preliminary passive checks to justify TinyFish verification.";
}

function shouldCaptureOriginalWithTinyfish(passive: PassiveChecks): boolean {
  return Boolean(passive.dnsResolved && passive.httpReachable);
}

function compareVariantPriority(a: TyposquatVariant, b: TyposquatVariant): number {
  return variantPriorityScore(b) - variantPriorityScore(a);
}

function variantPriorityScore(variant: TyposquatVariant): number {
  const levelWeight: Record<ThreatLevel, number> = { Critical: 400, High: 300, Medium: 200, Low: 100 };
  const level = levelWeight[variant.threatLevel] ?? 0;
  const liveBonus = variant.liveStatus === "live" ? 40 : variant.liveStatus === "unreachable" ? 10 : 0;
  return level + (variant.visualSimilarity ?? 0) + (variant.manipulationScore ?? 0) + (variant.urlscan?.verdictScore ?? 0) + liveBonus;
}
