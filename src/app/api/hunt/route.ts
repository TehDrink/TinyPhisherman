/**
 * POST /api/hunt
 * Feature B: Brand protection — typosquat discovery + visual clone detection.
 *
 * Body: { domain: string }   e.g. "google.com"
 * Returns: ApiResponse<HuntResult>
 */

import { NextRequest, NextResponse } from "next/server";
import { visitWithAgent, visitMany } from "@/lib/tinyfish";
import { analyzeDOM, compareScreenshots } from "@/lib/llm";
import { discoverTyposquatCandidates, lexicalSimilarity } from "@/lib/typosquat";
import { runPassiveChecks } from "@/lib/passive-checks";
import { calcVariantThreatLevel } from "@/lib/threat-level";
import { triageWithUrlscan } from "@/lib/urlscan";
import type {
  HuntResult,
  TyposquatVariant,
  ApiResponse,
  PassiveChecks,
  ThreatLevel,
  UrlscanVerdict,
} from "@/types";

const MAX_VARIANTS = Number(process.env.HUNT_MAX_VARIANTS ?? "5");
const MAX_CANDIDATES = Number(process.env.HUNT_MAX_CANDIDATES ?? "12");

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { domain } = body as { domain: string };

    if (!domain || typeof domain !== "string") {
      return NextResponse.json<ApiResponse<never>>(
        { ok: false, error: "Missing or invalid `domain` field." },
        { status: 400 }
      );
    }

    // Normalise: strip protocol if present
    const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0];
    const originalUrl = `https://${cleanDomain}`;

    const [originalPassive, discovery] = await Promise.all([
      runPassiveChecks(originalUrl),
      discoverTyposquatCandidates(cleanDomain),
    ]);
    const originalAgent = shouldCaptureOriginalWithTinyfish(originalPassive)
      ? await visitWithAgent(originalUrl, { interact: false })
      : {
          url: originalUrl,
          screenshot: "",
          domText: "",
          finalUrl: originalPassive.finalResolvedUrl ?? originalUrl,
          statusCode: originalPassive.httpStatusCode ?? 0,
          pageTitle: "",
          hasLoginForm: false,
          externalLinks: [],
        };

    const candidateIntel = await Promise.all(
      discovery.candidates.slice(0, MAX_CANDIDATES).map(async (candidate) => {
        const targetUrl = `https://${candidate}`;
        const [passive, urlscan] = await Promise.all([
          runPassiveChecks(targetUrl),
          triageWithUrlscan(targetUrl),
        ]);
        const score =
          lexicalSimilarity(cleanDomain, candidate) +
          (passive.dnsResolved ? 20 : -20) +
          ((passive.domainAgeDays ?? 999) < 30 ? 15 : 0) +
          (passive.hasSSL ? 0 : -10) +
          (urlscan?.verdictMalicious ? 100 : 0) +
          Math.min(urlscan?.verdictScore ?? 0, 40);
        return { candidate, passive, urlscan, score };
      })
    );

    const candidates = candidateIntel
      .sort((a, b) => b.score - a.score)
      .slice(0, MAX_VARIANTS);

    const deepScanTargets = candidates.filter(({ passive }) =>
      shouldDeployTinyfishForVariant(passive)
    );

    const variantMap = await visitMany(
      deepScanTargets.map((item) => `https://${item.candidate}`),
      { interact: false }
    );

    const variantResults: TyposquatVariant[] = await Promise.all(
      candidates.map(async ({ candidate: variantDomain, passive, urlscan }) => {
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
            agentResult.hasLoginForm,
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

    const result: HuntResult = {
      originalDomain: cleanDomain,
      originalScreenshot: originalAgent.screenshot,
      variants: variantResults.sort(compareVariantPriority),
      huntedAt: new Date().toISOString(),
      discoveryMethod: discovery.method,
    };

    return NextResponse.json<ApiResponse<HuntResult>>({ ok: true, data: result });
  } catch (err) {
    console.error("[/api/hunt]", err);
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json<ApiResponse<never>>(
      { ok: false, error: message },
      { status: 500 }
    );
  }
}

function shouldDeployTinyfishForVariant(passive: PassiveChecks): boolean {
  if (!passive.dnsResolved || !passive.httpReachable) {
    return false;
  }

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

function calcPreliminaryThreatLevel(
  passive: PassiveChecks,
  urlscan: UrlscanVerdict | null
): ThreatLevel {
  if (urlscan?.verdictMalicious) return "Critical";
  if ((urlscan?.verdictScore ?? 0) >= 70) return "High";
  if (passiveSuspicionScore(passive) >= 15 || (urlscan?.verdictScore ?? 0) >= 35) {
    return "Medium";
  }
  return "Low";
}

function preliminaryManipulationScore(
  passive: PassiveChecks,
  urlscan: UrlscanVerdict | null
): number {
  return Math.min(100, Math.max(passiveSuspicionScore(passive) * 3, urlscan?.verdictScore ?? 0));
}

function buildTriageOnlyReason(passive: PassiveChecks): string {
  if (!passive.dnsResolved) {
    return "Variant did not resolve during DNS checks, so TinyFish was not deployed.";
  }
  if (!passive.httpReachable) {
    return "Variant resolved in DNS but did not respond over HTTP(S), so TinyFish was not deployed.";
  }
  return "Variant was reachable but did not look suspicious enough in preliminary passive checks to justify TinyFish verification.";
}

function shouldCaptureOriginalWithTinyfish(passive: PassiveChecks): boolean {
  return Boolean(passive.dnsResolved && passive.httpReachable);
}

function compareVariantPriority(a: TyposquatVariant, b: TyposquatVariant): number {
  return variantPriorityScore(b) - variantPriorityScore(a);
}

function variantPriorityScore(variant: TyposquatVariant): number {
  const levelWeight: Record<ThreatLevel, number> = {
    Critical: 400,
    High: 300,
    Medium: 200,
    Low: 100,
  };

  const level = levelWeight[variant.threatLevel] ?? 0;
  const liveBonus = variant.liveStatus === "live" ? 40 : variant.liveStatus === "unreachable" ? 10 : 0;
  return (
    level +
    (variant.visualSimilarity ?? 0) +
    (variant.manipulationScore ?? 0) +
    (variant.urlscan?.verdictScore ?? 0) +
    liveBonus
  );
}
