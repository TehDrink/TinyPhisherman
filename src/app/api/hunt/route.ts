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
import { generateTyposquats } from "@/lib/typosquat";
import { calcVariantThreatLevel } from "@/lib/threat-level";
import type { HuntResult, TyposquatVariant, ApiResponse } from "@/types";

// For MVP we scan at most 5 variants to keep latency manageable
const MAX_VARIANTS = 5;

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

    // 2. Generate + pick top-N typosquat candidates
    const candidates = generateTyposquats(cleanDomain).slice(0, MAX_VARIANTS);

    // 3. Visit all variants in parallel
    const variantMap = await visitMany(
      candidates.map((d) => `https://${d}`),
      { interact: false }
    );

    // 4. For each reachable variant: run LLM analysis + visual compare
    const variantResults: TyposquatVariant[] = await Promise.all(
      candidates.map(async (variantDomain) => {
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
            liveStatus: "unreachable" as const,
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

        const threatLevel = calcVariantThreatLevel(llm, visual.score);

        return {
          domain: variantDomain,
          threatLevel,
          visualSimilarity: visual.score,
          manipulationScore: llm.manipulationScore,
          squatterCategory: llm.squatterCategory,
          screenshot: agentResult.screenshot,
          liveStatus: "live" as const,
        };
      })
    );

    const result: HuntResult = {
      originalDomain: cleanDomain,
      originalScreenshot: originalAgent.screenshot,
      variants: variantResults.sort((a, b) => b.visualSimilarity - a.visualSimilarity),
      huntedAt: new Date().toISOString(),
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
