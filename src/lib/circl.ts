export async function discoverCirclCandidates(domain: string): Promise<string[]> {
  try {
    const res = await fetch(
      `https://typosquatting-finder.circl.lu/${encodeURIComponent(domain)}`,
      {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(20000),
        cache: "no-store",
      }
    );

    if (!res.ok) return [];

    const data = (await res.json()) as Array<{
      domain?: string;
      "domain-name"?: string;
      "dns-a"?: string | string[];
      dns_a?: string | string[];
    }>;

    return data
      .filter((item) => item?.["dns-a"] || item?.dns_a)
      .map((item) => item.domain ?? item["domain-name"] ?? "")
      .filter(Boolean);
  } catch {
    return [];
  }
}
