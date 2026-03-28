import type { LLMAnalysis, PassiveChecks, ThreatLevel } from "@/types";

export function calcThreatLevel(
  llm: LLMAnalysis,
  passive: PassiveChecks,
  hasLoginForm: boolean
): ThreatLevel {
  if (llm.squatterCategory === "Credential Harvester") {
    return "Critical";
  }

  if (
    llm.squatterCategory === "Malware Drop" ||
    llm.manipulationScore > 75 ||
    ((passive.domainAgeDays ?? 999) < 14 && (hasLoginForm || llm.credentialIntent))
  ) {
    return "High";
  }

  if (
    llm.manipulationScore >= 40 ||
    (!passive.hasSSL && passive.redirectCount > 1) ||
    ((passive.domainAgeDays ?? 999) < 45 && passive.dnsResolved)
  ) {
    return "Medium";
  }

  return "Low";
}

export function calcVariantThreatLevel(
  llm: LLMAnalysis,
  visualSimilarity: number,
  passive?: PassiveChecks
): ThreatLevel {
  if (visualSimilarity > 80 || llm.squatterCategory === "Credential Harvester") {
    return "Critical";
  }

  if (
    llm.squatterCategory === "Malware Drop" ||
    visualSimilarity > 60 ||
    llm.manipulationScore > 75
  ) {
    return "High";
  }

  if (
    visualSimilarity > 40 ||
    llm.manipulationScore >= 45 ||
    ((passive?.domainAgeDays ?? 999) < 30 && passive?.dnsResolved)
  ) {
    return "Medium";
  }

  return "Low";
}
