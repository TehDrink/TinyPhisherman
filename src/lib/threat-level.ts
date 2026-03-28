import type { LLMAnalysis, PassiveChecks, ThreatLevel, UrlscanVerdict } from "@/types";

export function calcThreatLevel(
  llm: LLMAnalysis,
  passive: PassiveChecks,
  offDomainSubmit: boolean,
  urlscan?: UrlscanVerdict | null
): ThreatLevel {
  if (urlscan?.verdictMalicious) {
    return "Critical";
  }

  if (llm.squatterCategory === "Credential Harvester") {
    return "Critical";
  }

  if (
    llm.squatterCategory === "Malware Drop" ||
    llm.manipulationScore > 75 ||
    ((passive.domainAgeDays ?? 999) < 14 && (offDomainSubmit || llm.credentialIntent)) ||
    (urlscan?.verdictScore ?? 0) >= 70
  ) {
    return "High";
  }

  if (
    llm.manipulationScore >= 40 ||
    (!passive.hasSSL && passive.redirectCount > 1) ||
    ((passive.domainAgeDays ?? 999) < 45 && passive.dnsResolved) ||
    (urlscan?.verdictScore ?? 0) >= 35
  ) {
    return "Medium";
  }

  return "Low";
}

export function calcVariantThreatLevel(
  llm: LLMAnalysis,
  visualSimilarity: number,
  passive?: PassiveChecks,
  urlscan?: UrlscanVerdict | null
): ThreatLevel {
  if (urlscan?.verdictMalicious) {
    return "Critical";
  }

  if (visualSimilarity > 80) {
    return "Critical";
  }

  if (llm.squatterCategory === "Credential Harvester") {
    return "Critical";
  }

  if (llm.squatterCategory === "Malware Drop") {
    return "High";
  }

  if (llm.squatterCategory === "Parked/Ads") {
    return "Low";
  }

  if (llm.manipulationScore > 75 || visualSimilarity > 60) {
    return "High";
  }

  if (
    llm.manipulationScore >= 45 ||
    visualSimilarity > 40 ||
    ((passive?.domainAgeDays ?? 999) < 30 && passive?.dnsResolved) ||
    (urlscan?.verdictScore ?? 0) >= 35
  ) {
    return "Medium";
  }

  return "Low";
}
