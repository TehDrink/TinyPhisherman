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
import type { HuntResult, TyposquatVariant, ApiResponse } from "@/types";

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

    // 1. Screenshot the legitimate brand site
    const originalAgent = await visitWithAgent(originalUrl, { interact: false });

    // 2. Discover + rank candidates
    const discovery = await discoverTyposquatCandidates(cleanDomain);
    const candidateIntel = await Promise.all(
      discovery.candidates.slice(0, MAX_CANDIDATES).map(async (candidate) => {
        const passive = await runPassiveChecks(`https://${candidate}`);
        const score =
          lexicalSimilarity(cleanDomain, candidate) +
          (passive.dnsResolved ? 20 : -20) +
          ((passive.domainAgeDays ?? 999) < 30 ? 15 : 0) +
          (passive.hasSSL ? 0 : -10);
        return { candidate, passive, score };
      })
    );

    const candidates = candidateIntel
      .sort((a, b) => b.score - a.score)
      .slice(0, MAX_VARIANTS);

    // 3. Visit all variants in parallel
    const variantMap = await visitMany(
      candidates
        .filter((item) => item.passive.dnsResolved)
        .map((item) => `https://${item.candidate}`),
      { interact: false }
    );

    // 4. For each reachable variant: run LLM analysis + visual compare
    const variantResults: TyposquatVariant[] = await Promise.all(
      candidates.map(async ({ candidate: variantDomain, passive }) => {
        const variantUrl = `https://${variantDomain}`;
        const agentResult = variantMap.get(variantUrl);

        // If the agent couldn't reach it, return a stub
        if (!agentResult || agentResult instanceof Error) {
          return {
            domain: variantDomain,
            threatLevel: "Low" as const,
            visualSimilarity: 0,
            manipulationScore: 0,
            squatterCategory: "Unknown" as const,
            screenshot: "",
            liveStatus: passive.dnsResolved ? "unreachable" as const : "parked" as const,
            passiveChecks: passive,
            reasoning: passive.dnsResolved
              ? "Variant resolved but active verification did not complete."
              : "Variant did not resolve to a live site during passive checks.",
            evidenceSnippets: [],
          };
        }

        const [llm, visual] = await Promise.all([
          analyzeDOM(
            agentResult.finalUrl ?? variantUrl,
            agentResult.domText,
            agentResult.hasLoginForm
          ),
          compareScreenshots(
            originalAgent.screenshot,
            agentResult.screenshot,
            cleanDomain,
            variantDomain
          ),
        ]);

        const threatLevel = calcVariantThreatLevel(llm, visual.score, passive);

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
        };
      })
    );

    const result: HuntResult = {
      originalDomain: cleanDomain,
      originalScreenshot: originalAgent.screenshot,
      variants: variantResults.sort((a, b) => b.visualSimilarity - a.visualSimilarity),
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
