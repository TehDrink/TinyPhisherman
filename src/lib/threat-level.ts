import type { LLMAnalysis, PassiveChecks, ThreatLevel } from "@/types";

/**
 * Calculates the final threat level from all available signals.
 *
 * Rules (in priority order):
 * 1. Critical  → manipulation > 75  OR  squatter = "Credential Harvester"/"Malware Drop"
 * 2. High      → manipulation 61-75  OR  domain age < 30 days + login form
 * 3. Medium    → manipulation 31-60  OR  no SSL + redirect > 2
 * 4. Low       → everything else
 */
export function calcThreatLevel(
  llm: LLMAnalysis,
  passive: PassiveChecks,
  hasLoginForm: boolean
): ThreatLevel {
  if (
    llm.manipulationScore > 75 ||
    llm.squatterCategory === "Credential Harvester" ||
    llm.squatterCategory === "Malware Drop"
  ) {
    return "Critical";
  }

  if (
    llm.manipulationScore > 60 ||
    ((passive.domainAgeDays ?? 999) < 30 && hasLoginForm)
  ) {
    return "High";
  }

  if (
    llm.manipulationScore > 30 ||
    (!passive.hasSSL && passive.redirectCount > 2)
  ) {
    return "Medium";
  }

  return "Low";
}

/**
 * Same logic for typosquat variants — additionally considers visual similarity.
 */
export function calcVariantThreatLevel(
  llm: LLMAnalysis,
  visualSimilarity: number
): ThreatLevel {
  if (visualSimilarity > 80) return "Critical";
  if (llm.manipulationScore > 75 || llm.squatterCategory === "Credential Harvester") {
    return "Critical";
  }
  if (visualSimilarity > 60 || llm.manipulationScore > 60) return "High";
  if (visualSimilarity > 40 || llm.manipulationScore > 30) return "Medium";
  return "Low";
}
