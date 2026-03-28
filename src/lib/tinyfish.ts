/**
 * TinyFish Web Agent Client
 * Uses the documented sync automation API and asks TinyFish to return
 * structured JSON that matches the fields this app needs.
 */

import { TinyFish, EventType } from "@tiny-fish/sdk";
import type { TinyFishResult } from "@/types";

const TINYFISH_API_URL = process.env.TINYFISH_API_URL ?? "https://agent.tinyfish.ai";
const TINYFISH_API_KEY = process.env.TINYFISH_API_KEY ?? "";
const DEFAULT_TIMEOUT_MS = 180_000;

interface TinyFishRunResponse {
  run_id: string | null;
  status: "COMPLETED" | "FAILED";
  started_at: string | null;
  finished_at: string | null;
  num_of_steps: number | null;
  result?: unknown;
  resultJson?: unknown;
  error?: {
    code?: string;
    message?: string;
  } | null;
}

interface TinyFishStructuredResult {
  final_url?: string;
  page_title?: string;
  dom_text?: string;
  has_login_form?: boolean;
  external_links?: string[];
  screenshot?: string;
}

/**
 * Sends the TinyFish agent to a URL using the documented sync automation API.
 * The goal instructs TinyFish to browse and return strict JSON.
 */
export async function visitWithAgent(
  url: string,
  options: { interact?: boolean; timeoutMs?: number } = {}
): Promise<TinyFishResult> {
  if (!TINYFISH_API_KEY) {
    throw new Error("Missing TINYFISH_API_KEY.");
  }

  const timeoutMs = resolveTimeoutMs(options.timeoutMs);
  let res: Response;

  try {
    res = await fetch(`${TINYFISH_API_URL}/v1/automation/run`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": TINYFISH_API_KEY,
      },
      body: JSON.stringify({
        url,
        goal: buildGoal(url, options.interact ?? true),
        browser_profile: options.interact ? "stealth" : "lite",
        api_integration: "tinyphisherman",
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    if (isAbortError(err)) {
      throw new Error(`TinyFish request timed out after ${Math.round(timeoutMs / 1000)}s.`);
    }
    throw err;
  }

  const data: TinyFishRunResponse = await res.json().catch(() => ({
    run_id: null,
    status: "FAILED",
    started_at: null,
    finished_at: null,
    num_of_steps: null,
    result: null,
    error: { message: "TinyFish returned invalid JSON." },
  }));

  if (!res.ok) {
    const message = data.error?.message ?? `TinyFish API error ${res.status}`;
    throw new Error(message);
  }

  if (data.status !== "COMPLETED") {
    throw new Error(data.error?.message ?? "TinyFish run failed.");
  }

  const result = normalizeResult(data.resultJson ?? data.result);

  return {
    url,
    screenshot: result.screenshot ?? "",
    domText: result.dom_text ?? "",
    finalUrl: result.final_url ?? url,
    statusCode: 200,
    pageTitle: result.page_title ?? "",
    hasLoginForm: Boolean(result.has_login_form),
    externalLinks: Array.isArray(result.external_links) ? result.external_links : [],
  };
}

/**
 * Starts a streaming run and returns the live preview URL as soon as it appears.
 * Uses the TinyFish SDK SSE stream. The streaming URL is safe to expose client-side.
 */
export async function getStreamingPreviewUrl(
  url: string,
  options: { interact?: boolean; timeoutMs?: number } = {}
): Promise<{ runId: string; streamingUrl: string }> {
  if (!TINYFISH_API_KEY) {
    throw new Error("Missing TINYFISH_API_KEY.");
  }

  const timeoutMs = resolveTimeoutMs(options.timeoutMs ?? 20_000);
  const client = new TinyFish();

  const stream = await client.agent.stream({
    url,
    goal: buildGoal(url, options.interact ?? true),
    browser_profile: options.interact ? "stealth" : "lite",
    api_integration: "tinyphisherman",
  });

  const timeoutAt = Date.now() + timeoutMs;

  for await (const event of stream as AsyncIterable<any>) {
    if (event?.type === EventType.STREAMING_URL || event?.type === "STREAMING_URL") {
      const streamingUrl = event.streaming_url ?? event.streamingUrl ?? "";
      const runId = event.run_id ?? event.runId ?? "";
      if (streamingUrl) {
        return { runId, streamingUrl };
      }
    }

    if (event?.type === EventType.COMPLETE || event?.type === "COMPLETE") {
      break;
    }

    if (Date.now() > timeoutAt) {
      break;
    }
  }

  throw new Error("Timed out waiting for TinyFish streaming URL.");
}

/**
 * Visits multiple URLs in parallel (capped at 4 concurrent).
 */
export async function visitMany(
  urls: string[],
  options: { interact?: boolean } = {}
): Promise<Map<string, TinyFishResult | Error>> {
  const CONCURRENCY = 4;
  const results = new Map<string, TinyFishResult | Error>();

  for (let i = 0; i < urls.length; i += CONCURRENCY) {
    const batch = urls.slice(i, i + CONCURRENCY);
    const settled = await Promise.allSettled(
      batch.map((targetUrl) => visitWithAgent(targetUrl, options))
    );
    settled.forEach((item, idx) => {
      results.set(
        batch[idx],
        item.status === "fulfilled" ? item.value : toError(item.reason)
      );
    });
  }

  return results;
}

function buildGoal(url: string, interact: boolean): string {
  const interactionInstructions = interact
    ? [
        "Act as a phishing investigator imitating a cautious victim.",
        "Explore the landing page and relevant internal flows.",
        "Click suspicious calls to action, login buttons, reset-password links, or payment prompts when visible.",
        "If a form appears, inspect it and you may type obviously fake bait values like test@example.com, fake passwords, or dummy names.",
        "Do not use real secrets, do not complete irreversible purchases, and do not intentionally submit harmful payloads.",
      ].join(" ")
    : [
        "Act as a phishing investigator.",
        "Observe the page without aggressive interaction.",
        "Inspect visible forms, links, branding, and phishing cues.",
      ].join(" ");

  return [
    interactionInstructions,
    `Target URL: ${url}.`,
    "Return strict JSON only with this exact shape:",
    "{",
    '  "final_url": "string",',
    '  "page_title": "string",',
    '  "dom_text": "string",',
    '  "has_login_form": true,',
    '  "external_links": ["string"],',
    '  "screenshot": "string"',
    "}",
    "Rules:",
    "- final_url must be the final loaded page URL.",
    "- dom_text should contain the most relevant visible text for phishing analysis, truncated if needed.",
    "- has_login_form should be true if the page asks for credentials, OTP, payment info, or account recovery data.",
    "- external_links should include outbound or suspicious destinations when visible.",
    "- screenshot should be a base64 PNG string if available, otherwise an empty string.",
    "- If a field cannot be determined, return a safe empty value instead of adding extra keys.",
  ].join("\n");
}

function normalizeResult(value: unknown): TinyFishStructuredResult {
  if (!value || typeof value !== "object") {
    return {};
  }

  const candidate = value as Record<string, unknown>;
  return {
    final_url: asString(candidate.final_url),
    page_title: asString(candidate.page_title),
    dom_text: asString(candidate.dom_text),
    has_login_form: typeof candidate.has_login_form === "boolean" ? candidate.has_login_form : false,
    external_links: asStringArray(candidate.external_links),
    screenshot: asString(candidate.screenshot),
  };
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((item): item is string => typeof item === "string");
}

function toError(reason: unknown): Error {
  return reason instanceof Error ? reason : new Error("TinyFish visit failed.");
}

function resolveTimeoutMs(explicit?: number): number {
  const envValue = Number(process.env.TINYFISH_TIMEOUT_MS);
  const base =
    Number.isFinite(envValue) && envValue > 0 ? Math.floor(envValue) : DEFAULT_TIMEOUT_MS;
  const chosen = Number.isFinite(explicit) && (explicit ?? 0) > 0 ? explicit! : base;
  return Math.max(10_000, Math.floor(chosen));
}

function isAbortError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  return err.name === "AbortError" || err.message.toLowerCase().includes("aborted");
}
