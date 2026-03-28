import dns from "node:dns/promises";
import tls from "node:tls";
import type { PassiveChecks } from "@/types";

const TIMEOUT_MS = 5000;

export async function runPassiveChecks(input: string): Promise<PassiveChecks> {
  const hostname = toHostname(input);
  const url = normalizeUrl(input);

  const [dnsInfo, tlsInfo, rdapInfo, redirectInfo] = await Promise.all([
    lookupDns(hostname),
    url.protocol === "https:" ? lookupTls(hostname) : Promise.resolve(null),
    lookupRdap(hostname),
    traceRedirects(url.toString()),
  ]);

  return {
    domainAgeDays: rdapInfo?.domainAgeDays ?? null,
    hasSSL: Boolean(tlsInfo),
    redirectCount: redirectInfo.redirectCount,
    httpReachable: redirectInfo.reachable,
    httpStatusCode: redirectInfo.statusCode,
    registrar: rdapInfo?.registrar ?? null,
    dnsResolved: dnsInfo.dnsResolved,
    ipAddresses: dnsInfo.ipAddresses,
    hasMX: dnsInfo.hasMX,
    nameservers: dnsInfo.nameservers,
    tlsIssuer: tlsInfo?.issuer ?? null,
    tlsValidFrom: tlsInfo?.validFrom ?? null,
    tlsValidTo: tlsInfo?.validTo ?? null,
    finalResolvedUrl: redirectInfo.finalUrl,
  };
}

function normalizeUrl(input: string): URL {
  return new URL(input.startsWith("http") ? input : `https://${input}`);
}

function toHostname(input: string): string {
  return normalizeUrl(input).hostname;
}

async function lookupDns(hostname: string): Promise<{
  dnsResolved: boolean;
  ipAddresses: string[];
  hasMX: boolean;
  nameservers: string[];
}> {
  const [a, aaaa, mx, ns, cname] = await Promise.allSettled([
    dns.resolve4(hostname),
    dns.resolve6(hostname),
    dns.resolveMx(hostname),
    dns.resolveNs(hostname),
    dns.resolveCname(hostname),
  ]);

  const ipAddresses = [
    ...(a.status === "fulfilled" ? a.value : []),
    ...(aaaa.status === "fulfilled" ? aaaa.value : []),
    ...(cname.status === "fulfilled" ? cname.value : []),
  ];

  return {
    dnsResolved: ipAddresses.length > 0,
    ipAddresses,
    hasMX: mx.status === "fulfilled" && mx.value.length > 0,
    nameservers: ns.status === "fulfilled" ? ns.value : [],
  };
}

async function lookupTls(hostname: string): Promise<{
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
} | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        if (!cert || Object.keys(cert).length === 0) {
          resolve(null);
          return;
        }

        resolve({
          issuer: pickIssuerValue(cert.issuer),
          validFrom: cert.valid_from ?? null,
          validTo: cert.valid_to ?? null,
        });
      }
    );

    socket.setTimeout(TIMEOUT_MS, () => {
      socket.destroy();
      resolve(null);
    });
    socket.on("error", () => resolve(null));
  });
}

function pickIssuerValue(
  issuer: Record<string, string | string[] | undefined> | undefined
): string | null {
  if (!issuer) return null;
  const value = issuer.O ?? issuer.CN;
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value[0] ?? null;
  return null;
}

async function lookupRdap(hostname: string): Promise<{
  domainAgeDays: number | null;
  registrar: string | null;
} | null> {
  try {
    const res = await fetch(`https://rdap.org/domain/${hostname}`, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { accept: "application/json, application/rdap+json" },
      cache: "no-store",
    });
    if (!res.ok) return null;

    const data = (await res.json()) as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
    };

    const created = data.events?.find((event) =>
      /registration|created/i.test(event.eventAction ?? "")
    )?.eventDate;

    const domainAgeDays = created
      ? Math.max(0, Math.floor((Date.now() - new Date(created).getTime()) / 86400000))
      : null;

    return {
      domainAgeDays,
      registrar: extractRegistrar(data.entities ?? []),
    };
  } catch {
    return null;
  }
}

function extractRegistrar(
  entities: Array<{ roles?: string[]; vcardArray?: unknown[] }>
): string | null {
  const registrarEntity = entities.find((entity) => entity.roles?.includes("registrar"));
  if (!registrarEntity || !Array.isArray(registrarEntity.vcardArray)) return null;
  const fields = registrarEntity.vcardArray[1];
  if (!Array.isArray(fields)) return null;

  for (const field of fields) {
    if (Array.isArray(field) && field[0] === "fn" && typeof field[3] === "string") {
      return field[3];
    }
  }

  return null;
}

async function traceRedirects(url: string): Promise<{
  redirectCount: number;
  finalUrl: string | null;
  reachable: boolean;
  statusCode: number | null;
}> {
  let current = url;
  let redirectCount = 0;

  for (let i = 0; i < 5; i++) {
    try {
      const res = await fetch(current, {
        method: "HEAD",
        redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT_MS),
        cache: "no-store",
      });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (!location) break;
        current = new URL(location, current).toString();
        redirectCount += 1;
        continue;
      }

      return {
        redirectCount,
        finalUrl: current,
        reachable: res.status >= 200 && res.status < 500,
        statusCode: res.status,
      };
    } catch {
      break;
    }
  }

  return { redirectCount, finalUrl: current, reachable: false, statusCode: null };
}
