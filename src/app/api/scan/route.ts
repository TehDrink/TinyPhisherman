/**
 * POST /api/scan
 * Feature A: Active single-URL phishing scanner.
 *
 * Body: { url: string }
 * Returns: ApiResponse<ScanResult>
 */

import { NextRequest, NextResponse } from "next/server";
import { visitWithAgent } from "@/lib/tinyfish";
import { analyzeDOM } from "@/lib/llm";
import { runPassiveChecks } from "@/lib/passive-checks";
import { calcThreatLevel } from "@/lib/threat-level";
import type { ScanResult, ApiResponse } from "@/types";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { url } = body as { url: string };

    if (!url || typeof url !== "string") {
      return NextResponse.json<ApiResponse<never>>(
        { ok: false, error: "Missing or invalid `url` field." },
        { status: 400 }
      );
    }

    // Normalise URL
    const target = url.startsWith("http") ? url : `https://${url}`;

    // 1. Deploy TinyFish agent
    const agentResult = await visitWithAgent(target, { interact: true });

    // 2. Passive checks
    const passive = await runPassiveChecks(target);

    // 3. LLM analysis
    const llm = await analyzeDOM(
      agentResult.finalUrl ?? target,
      agentResult.domText,
      agentResult.hasLoginForm
    );

    // 4. Threat level
    const threatLevel = calcThreatLevel(llm, passive, agentResult.hasLoginForm);

    const result: ScanResult = {
      url: target,
      threatLevel,
      manipulationScore: llm.manipulationScore,
      squatterCategory: llm.squatterCategory,
      passiveChecks: passive,
      screenshot: agentResult.screenshot,
      reasoning: llm.reasoning,
      redFlags: llm.redFlags,
      scannedAt: new Date().toISOString(),
      finalUrl: agentResult.finalUrl ?? passive.finalResolvedUrl ?? target,
      pageTitle: agentResult.pageTitle,
      externalLinks: agentResult.externalLinks,
      impersonatedBrand: llm.impersonatedBrand ?? null,
      credentialIntent: llm.credentialIntent ?? false,
      evidenceSnippets: llm.evidenceSnippets ?? [],
    };

    return NextResponse.json<ApiResponse<ScanResult>>({ ok: true, data: result });
  } catch (err) {
    console.error("[/api/scan]", err);
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json<ApiResponse<never>>(
      { ok: false, error: message },
      { status: 500 }
    );
  }
}
