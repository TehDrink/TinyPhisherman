/**
 * Passive checks — mocked for MVP.
 * Replace with real WHOIS / SSL / redirect-chain calls later.
 */

import type { PassiveChecks } from "@/types";

function seededRandom(seed: string): number {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (Math.imul(31, h) + seed.charCodeAt(i)) | 0;
  return Math.abs(h) / 2147483647;
}

export function runPassiveChecks(url: string): PassiveChecks {
  const r = seededRandom(url);
  return {
    domainAgeDays: Math.floor(r * 365),     // 0-364 days → new = suspicious
    hasSSL: url.startsWith("https"),
    redirectCount: Math.floor(r * 4),        // 0-3
    registrar: ["GoDaddy", "Namecheap", "Tucows", "PDR Ltd."][Math.floor(r * 4)],
  };
}
