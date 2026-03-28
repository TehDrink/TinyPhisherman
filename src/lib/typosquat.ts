import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { discoverCirclCandidates } from "@/lib/circl";
import { discoverViaCertTransparency } from "@/lib/certstream";

const execFileAsync = promisify(execFile);

/**
 * Generates common typosquatted domain variants for a given domain.
 * Produces up to ~20 candidates; caller should trim to desired count.
 */
export function generateTyposquats(domain: string): string[] {
  const parts = domain.split(".");
  const tld = parts.slice(-1)[0];
  const name = parts.slice(0, -1).join(".");

  const variants = new Set<string>();

  for (let i = 0; i < name.length; i++) {
    const v = name.slice(0, i) + name.slice(i + 1);
    if (v) variants.add(`${v}.${tld}`);
  }

  for (let i = 0; i < name.length - 1; i++) {
    const v = name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2);
    variants.add(`${v}.${tld}`);
  }

  for (let i = 0; i < name.length; i++) {
    const v = name.slice(0, i) + name[i] + name[i] + name.slice(i + 1);
    variants.add(`${v}.${tld}`);
  }

  const homoglyphs: Record<string, string> = {
    a: "4",
    e: "3",
    i: "1",
    o: "0",
    s: "5",
    l: "1",
  };
  for (const [char, sub] of Object.entries(homoglyphs)) {
    if (name.includes(char)) variants.add(`${name.replace(char, sub)}.${tld}`);
  }

  for (const affix of ["secure-", "login-", "-verify", "-online", "-official"]) {
    variants.add(affix.startsWith("-") ? `${name}${affix}.${tld}` : `${affix}${name}.${tld}`);
  }

  for (const altTld of ["com", "net", "org", "co", "io"].filter((value) => value !== tld)) {
    variants.add(`${name}.${altTld}`);
  }

  variants.delete(domain);
  return Array.from(variants).slice(0, 20);
}

export async function discoverTyposquatCandidates(domain: string): Promise<{
  method: string;
  candidates: string[];
  // Domains discovered via CT logs carry a cert issuance date so the hunt
  // route can boost their ranking (recently-issued = higher risk).
  certIssuedAt: Map<string, string>;
}> {
  const dnstwistPath = process.env.DNSTWIST_PATH ?? "dnstwist";
  const methods = new Set<string>();

  // Run all passive discovery sources in parallel — they are independent.
  const [circlCandidates, ctResults] = await Promise.all([
    discoverCirclCandidates(domain),
    discoverViaCertTransparency(domain),
  ]);

  const discovered = new Set<string>();
  const certIssuedAt = new Map<string, string>();

  for (const c of circlCandidates) {
    if (c !== domain) {
      discovered.add(c);
      methods.add("circl");
    }
  }

  for (const { domain: ctDomain, certIssuedAt: issuedAt } of ctResults) {
    if (ctDomain !== domain) {
      discovered.add(ctDomain);
      if (issuedAt) certIssuedAt.set(ctDomain, issuedAt);
      methods.add("crt.sh");
    }
  }

  try {
    const { stdout } = await execFileAsync(dnstwistPath, ["--json", domain], {
      timeout: 15000,
      maxBuffer: 2_000_000,
    });
    const parsed = JSON.parse(stdout) as Array<{ domain?: string; fqdn?: string }>;
    for (const entry of parsed) {
      const candidate = entry.domain ?? entry.fqdn ?? "";
      if (candidate && candidate !== domain) {
        discovered.add(candidate);
        methods.add("dnstwist");
      }
    }
  } catch {
    // dnstwist unavailable — CT + CIRCL results are sufficient.
  }

  if (discovered.size > 0) {
    return {
      method: Array.from(methods).join("+"),
      candidates: Array.from(discovered),
      certIssuedAt,
    };
  }

  return {
    method: "heuristic",
    candidates: generateTyposquats(domain),
    certIssuedAt: new Map(),
  };
}

export function lexicalSimilarity(a: string, b: string): number {
  const distance = levenshtein(a, b);
  const maxLen = Math.max(a.length, b.length, 1);
  return Math.round((1 - distance / maxLen) * 100);
}

function levenshtein(a: string, b: string): number {
  const rows = a.length + 1;
  const cols = b.length + 1;
  const matrix = Array.from({ length: rows }, () => Array<number>(cols).fill(0));

  for (let i = 0; i < rows; i++) matrix[i][0] = i;
  for (let j = 0; j < cols; j++) matrix[0][j] = j;

  for (let i = 1; i < rows; i++) {
    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }

  return matrix[a.length][b.length];
}
