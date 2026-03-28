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
import { triageWithUrlscan } from "@/lib/urlscan";
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
  const target = url.startsWith("http") ? url : `https://${url}`;
  const testedUrls = deriveVariants(target);

  const [passive, urlscanHttps, urlscanHttp] = await Promise.all([
    runPassiveChecks(target),
    triageWithUrlscan(testedUrls.httpsUrl),
    testedUrls.httpUrl !== testedUrls.httpsUrl
      ? triageWithUrlscan(testedUrls.httpUrl)
      : Promise.resolve(null),
  ]);

  const urlscan = pickWorseUrlscan(urlscanHttps, urlscanHttp);
  const shouldRunTinyfish = useTinyfish && isReachableForTinyfish(passive);
  const tinyfishSkipReason = !useTinyfish
    ? "TinyFish exploration was disabled for this scan."
    : shouldRunTinyfish
      ? null
      : "TinyFish exploration was skipped because the site was not reachable during preliminary checks.";
  const agentResult = shouldRunTinyfish
    ? await visitWithAgent(target, { interact: true, timeoutMs })
    : {
        url: target,
        screenshot: "",
        domText: "",
        finalUrl: passive.finalResolvedUrl ?? target,
        statusCode: passive.httpStatusCode ?? 0,
        pageTitle: urlscan?.pageTitle ?? "",
        hasLoginForm: false,
        formFields: [] as string[],
        formAction: null,
        offDomainSubmit: false,
        externalLinks: [] as string[],
      };
  const llm = await analyzeDOM(
    agentResult.finalUrl ?? target,
    agentResult.domText,
    agentResult.formFields,
    agentResult.offDomainSubmit,
  );

  const threatLevel = calcThreatLevel(llm, passive, agentResult.offDomainSubmit, urlscan);

  return {
    url: target,
    threatLevel,
    manipulationScore: llm.manipulationScore,
    squatterCategory: llm.squatterCategory,
    passiveChecks: passive,
    screenshot: agentResult.screenshot,
    reasoning: tinyfishSkipReason ? `${llm.reasoning} ${tinyfishSkipReason}` : llm.reasoning,
    redFlags: llm.redFlags,
    scannedAt: new Date().toISOString(),
    finalUrl: agentResult.finalUrl ?? passive.finalResolvedUrl ?? target,
    pageTitle: agentResult.pageTitle,
    externalLinks: agentResult.externalLinks,
    impersonatedBrand: llm.impersonatedBrand ?? null,
    credentialIntent: llm.credentialIntent ?? false,
    evidenceSnippets: llm.evidenceSnippets ?? [],
    urlscan,
    testedUrls: [testedUrls.httpsUrl, testedUrls.httpUrl].filter(
      (entry, index, list) => list.indexOf(entry) === index
    ),
  };
}

function isReachableForTinyfish(passive: ScanResult["passiveChecks"]): boolean {
  return Boolean(passive?.dnsResolved && passive?.httpReachable);
}

function deriveVariants(raw: string): { httpUrl: string; httpsUrl: string } {
  const trimmed = raw.trim();
  const withoutProtocol = trimmed.replace(/^https?:\/\//i, "");
  return {
    httpUrl: `http://${withoutProtocol}`,
    httpsUrl: `https://${withoutProtocol}`,
  };
}

function pickWorseUrlscan<T extends { verdictMalicious: boolean; verdictScore: number }>(
  a: T | null,
  b: T | null
): T | null {
  if (!a) return b;
  if (!b) return a;
  if (a.verdictMalicious && !b.verdictMalicious) return a;
  if (b.verdictMalicious && !a.verdictMalicious) return b;
  return a.verdictScore >= b.verdictScore ? a : b;
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
