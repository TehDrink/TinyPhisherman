import { NextRequest, NextResponse } from "next/server";
import { getStreamingPreviewUrl } from "@/lib/tinyfish";
import type { ApiResponse } from "@/types";

interface PreviewData {
  runId: string;
  streamingUrl: string;
}

export async function GET(req: NextRequest) {
  const url = req.nextUrl.searchParams.get("url") ?? "";
  const timeoutMs = toOptionalNumber(req.nextUrl.searchParams.get("timeoutMs"));

  if (!url || typeof url !== "string") {
    return NextResponse.json<ApiResponse<never>>(
      { ok: false, error: "Missing or invalid `url` field." },
      { status: 400 }
    );
  }

  const target = url.startsWith("http") ? url : `https://${url}`;

  try {
    const preview = await getStreamingPreviewUrl(target, { interact: true, timeoutMs });
    return NextResponse.json<ApiResponse<PreviewData>>({ ok: true, data: preview });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    const status = isTimeoutError(err) ? 504 : 500;
    return NextResponse.json<ApiResponse<never>>({ ok: false, error: message }, { status });
  }
}

function toOptionalNumber(value: string | null): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function isTimeoutError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  return err.name === "AbortError" || err.message.toLowerCase().includes("timed out");
}
