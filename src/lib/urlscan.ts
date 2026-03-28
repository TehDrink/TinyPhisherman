import type { UrlscanVerdict } from "@/types";

const BASE = "https://urlscan.io/api/v1";
const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY ?? "";
const URLSCAN_LOOKBACK_DAYS = Number(process.env.URLSCAN_LOOKBACK_DAYS ?? "7");
const URLSCAN_SCAN_TIMEOUT_MS = Number(process.env.URLSCAN_SCAN_TIMEOUT_MS ?? "60000");

export async function searchUrlscan(input: string): Promise<UrlscanVerdict | null> {
  const domain = toHostname(input);

  try {
    const res = await fetch(
      `${BASE}/search/?q=domain:${encodeURIComponent(domain)}&size=1`,
      { headers: buildHeaders(), signal: AbortSignal.timeout(15000), cache: "no-store" }
    );

    if (!res.ok) return null;

    const data = (await res.json()) as {
      results?: Array<{ _id?: string; task?: { time?: string } }>;
    };
    const hit = data.results?.[0];
    if (!hit?._id) return null;

    if (isExpired(hit.task?.time ?? null, URLSCAN_LOOKBACK_DAYS)) {
      return null;
    }

    const verdict = await fetchResult(hit._id);
    if (verdict) {
      verdict.scannedAt = hit.task?.time ?? verdict.scannedAt ?? null;
    }
    return verdict;
  } catch {
    return null;
  }
}

export async function scanWithUrlscan(input: string): Promise<UrlscanVerdict | null> {
  const url = normalizeUrl(input);

  try {
    const uuid = await submitScan(url);
    if (!uuid) return null;
    return await pollResult(uuid);
  } catch {
    return null;
  }
}

export async function triageWithUrlscan(
  input: string,
  options: { submitIfMissing?: boolean } = {}
): Promise<UrlscanVerdict | null> {
  const existing = await searchUrlscan(input);
  if (existing || !options.submitIfMissing) return existing;
  return scanWithUrlscan(input);
}

function normalizeUrl(input: string): string {
  return input.startsWith("http") ? input : `https://${input}`;
}

function toHostname(input: string): string {
  return new URL(normalizeUrl(input)).hostname;
}

function buildHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  if (URLSCAN_API_KEY) headers["API-Key"] = URLSCAN_API_KEY;
  return headers;
}

async function submitScan(url: string): Promise<string | null> {
  const headers = buildHeaders();
  headers["Content-Type"] = "application/json";

  const res = await fetch(`${BASE}/scan/`, {
    method: "POST",
    headers,
    body: JSON.stringify({ url, visibility: "public" }),
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) return null;

  const data = (await res.json()) as { uuid?: string };
  return data.uuid ?? null;
}

async function pollResult(uuid: string): Promise<UrlscanVerdict | null> {
  const deadline = Date.now() + URLSCAN_SCAN_TIMEOUT_MS;
  await sleep(10000);

  while (Date.now() < deadline) {
    const result = await fetchResult(uuid);
    if (result) return result;
    await sleep(4000);
  }

  return null;
}

async function fetchResult(uuid: string): Promise<UrlscanVerdict | null> {
  const res = await fetch(`${BASE}/result/${uuid}/`, {
    headers: buildHeaders(),
    signal: AbortSignal.timeout(15000),
    cache: "no-store",
  });

  if (res.status === 404 || !res.ok) return null;

  const data = (await res.json()) as UrlscanRaw;
  return parseResult(uuid, data);
}

function parseResult(uuid: string, data: UrlscanRaw): UrlscanVerdict {
  const page = data.page ?? {};
  const lists = data.lists ?? {};
  const stats = data.stats ?? {};
  const verdicts = data.verdicts?.overall ?? {};

  return {
    scanUuid: uuid,
    screenshotUrl: uuid ? `https://urlscan.io/screenshots/${uuid}.png` : null,
    verdictMalicious: Boolean(verdicts.malicious),
    verdictScore: Number(verdicts.score ?? 0),
    ipAddress: page.ip ?? null,
    country: page.country ?? null,
    server: page.server ?? null,
    hosting: page.asnname ?? null,
    domainsContacted: Array.isArray(lists.domains) ? lists.domains.slice(0, 20) : [],
    ipsContacted: Array.isArray(lists.ips) ? lists.ips.slice(0, 20) : [],
    httpTransactions: Number(stats.uniqIPs ?? 0),
    pageTitle: page.title ?? null,
    scannedAt: data.task?.time ?? null,
  };
}

function isExpired(value: string | null, lookbackDays: number): boolean {
  if (!value) return false;
  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) return false;
  return Date.now() - timestamp > lookbackDays * 24 * 60 * 60 * 1000;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface UrlscanRaw {
  task?: { time?: string };
  page?: {
    ip?: string;
    country?: string;
    server?: string;
    asnname?: string;
    title?: string;
  };
  lists?: {
    ips?: string[];
    domains?: string[];
  };
  stats?: {
    uniqIPs?: number;
  };
  verdicts?: {
    overall?: {
      malicious?: boolean;
      score?: number;
    };
  };
}
