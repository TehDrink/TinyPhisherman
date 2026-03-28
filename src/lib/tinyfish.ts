/**
 * TinyFish Web Agent Client
 * Wraps the TinyFish API to navigate suspicious URLs, bypass anti-bot, and return DOM + screenshots.
 */

import type { TinyFishResult } from "@/types";

const TINYFISH_API_URL = process.env.TINYFISH_API_URL ?? "https://api.tinyfish.io";
const TINYFISH_API_KEY = process.env.TINYFISH_API_KEY ?? "";

interface TinyFishRunTaskResponse {
  screenshot: string;       // base64 PNG
  dom_text: string;
  final_url: string;
  status_code: number;
  page_title: string;
  has_login_form: boolean;
  external_links: string[];
}

/**
 * Sends the TinyFish agent to a URL. It navigates, optionally interacts
 * (fills dummy creds, clicks buttons), then returns a snapshot.
 */
export async function visitWithAgent(
  url: string,
  options: { interact?: boolean } = {}
): Promise<TinyFishResult> {
  const res = await fetch(`${TINYFISH_API_URL}/v1/run`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${TINYFISH_API_KEY}`,
    },
    body: JSON.stringify({
      url,
      // Tell the agent to interact with the page (click CTAs, fill dummy creds)
      // so phishing flows are triggered even on lazy-loaded sites.
      interact: options.interact ?? true,
      screenshot: true,
      dom_text: true,
      timeout_ms: 30_000,
    }),
    signal: AbortSignal.timeout(60_000),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "(empty)");
    throw new Error(`TinyFish API error ${res.status}: ${body}`);
  }

  const data: TinyFishRunTaskResponse = await res.json();

  return {
    url,
    screenshot: data.screenshot,
    domText: data.dom_text,
    finalUrl: data.final_url,
    statusCode: data.status_code,
    pageTitle: data.page_title,
    hasLoginForm: data.has_login_form,
    externalLinks: data.external_links ?? [],
  };
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
      batch.map((url) => visitWithAgent(url, options))
    );
    settled.forEach((r, idx) => {
      results.set(
        batch[idx],
        r.status === "fulfilled" ? r.value : r.reason as Error
      );
    });
  }

  return results;
}
