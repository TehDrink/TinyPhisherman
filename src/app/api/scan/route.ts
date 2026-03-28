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

export async function GET(req: NextRequest) {
  const url = req.nextUrl.searchParams.get("url") ?? "";
  const timeoutMs = toOptionalNumber(req.nextUrl.searchParams.get("timeoutMs"));
  const useTinyfish = toOptionalBoolean(req.nextUrl.searchParams.get("useTinyfish"), true);
  return handleScan(url, timeoutMs, useTinyfish);
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { url, timeoutMs, useTinyfish } = body as {
      url: string;
      timeoutMs?: number;
      useTinyfish?: boolean;
    };
    return handleScan(url, timeoutMs, useTinyfish ?? true);
  } catch (err) {
    console.error("[/api/scan]", err);
    return NextResponse.json<ApiResponse<never>>(
      { ok: false, error: "Invalid JSON body." },
      { status: 400 }
    );
  }
}

async function handleScan(url: string, timeoutMs?: number, useTinyfish = true) {
  if (!url || typeof url !== "string") {
    return NextResponse.json<ApiResponse<never>>(
      { ok: false, error: "Missing or invalid `url` field." },
      { status: 400 }
    );
  }

  try {
    const result = await scanUrl(url, timeoutMs, useTinyfish);
    return NextResponse.json<ApiResponse<ScanResult>>({ ok: true, data: result });
  } catch (err) {
    console.error("[/api/scan]", err);
    const message = err instanceof Error ? err.message : "Unknown error";
    const status = isTimeoutError(err) ? 504 : 500;
    return NextResponse.json<ApiResponse<never>>({ ok: false, error: message }, { status });
  }
}

async function scanUrl(
  url: string,
  timeoutMs: number | undefined,
  useTinyfish: boolean
): Promise<ScanResult> {
  // Normalise URL
  const target = url.startsWith("http") ? url : `https://${url}`;

  // 1. Deploy TinyFish agent (optional)
  const agentResult = useTinyfish
    ? await visitWithAgent(target, { interact: true, timeoutMs })
    : {
        url: target,
        screenshot: "",
        domText: "",
        finalUrl: target,
        statusCode: 0,
        pageTitle: "",
        hasLoginForm: false,
        externalLinks: [],
      };

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

  return {
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
}

function toOptionalNumber(value: string | null): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function toOptionalBoolean(value: string | null, fallback: boolean): boolean {
  if (value === null || value === undefined) return fallback;
  if (value === "true" || value === "1") return true;
  if (value === "false" || value === "0") return false;
  return fallback;
}

function isTimeoutError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  return err.name === "AbortError" || err.message.toLowerCase().includes("timed out");
}
