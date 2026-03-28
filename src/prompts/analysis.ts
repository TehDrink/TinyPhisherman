export function buildPhishingAnalysisSystemPrompt(): string {
  return [
    "You are a senior phishing analyst with a low false-positive tolerance.",
    "Your job is to classify whether a page is actively malicious — not merely suspicious or unusual.",
    "",
    "SCORING CALIBRATION for manipulation_score (0–100):",
    "  0–20  : Legitimate-looking site. No meaningful phishing signals.",
    "  21–40 : Minor anomalies (generic login form on a low-reputation domain). Needs more evidence.",
    "  41–60 : Moderate concern. Lookalike branding or suspicious URL pattern, but no smoking gun.",
    "  61–80 : Strong phishing indicators. Credential harvesting behavior or clear brand impersonation.",
    "  81–100: Near-certain phishing. Domain/brand mismatch + credential form + urgency language.",
    "",
    "RULES TO AVOID FALSE POSITIVES:",
    "  - A login form alone does NOT raise the score. Only flag it if the domain is suspicious or off-brand.",
    "  - Brand words in footers ('Powered by Google', 'Verified by Visa') do NOT constitute brand impersonation.",
    "  - Generic layouts (white background, navbar, hero image) are NOT visual similarity evidence.",
    "  - A domain registered recently is a weak signal only — pair it with content evidence before raising the score.",
    "  - Parked domains with ads should be Parked/Ads, not Credential Harvester.",
    "  - If the page content matches what you'd expect from the legitimate domain, default to Unknown.",
    "",
    "RULES TO AVOID FALSE NEGATIVES:",
    "  - Domain/brand mismatch with a credential form is a strong signal — score 70+.",
    "  - Punycode or homoglyph domains impersonating a brand are near-certain phishing.",
    "  - Urgency language ('Your account will be suspended') combined with a credential form is strong evidence.",
    "",
    "Return strict JSON only.",
  ].join("\n");
}

export function buildPhishingAnalysisUserPrompt(input: {
  url: string;
  hostname: string;
  registrableDomain: string;
  pathname: string;
  expectedLegitimateDomain?: string | null;
  formFields: string[];
  offDomainSubmit: boolean;
  suspiciousSignals: string[];
  domText: string;
  // optional passive-check context
  domainAgeDays?: number | null;
  hasSSL?: boolean;
  registrar?: string | null;
  urlscanMalicious?: boolean;
  urlscanScore?: number | null;
}): string {
  const passiveLines = [
    `Domain age: ${typeof input.domainAgeDays === "number" ? `${input.domainAgeDays} days` : "unknown"}`,
    `SSL present: ${input.hasSSL === true ? "yes" : input.hasSSL === false ? "no" : "unknown"}`,
    `Registrar: ${input.registrar ?? "unknown"}`,
    input.urlscanMalicious != null
      ? `URLscan verdict: ${input.urlscanMalicious ? "MALICIOUS" : "clean"} (score ${input.urlscanScore ?? "n/a"})`
      : null,
  ]
    .filter(Boolean)
    .join("\n");

  const formSummary = input.formFields.length > 0
    ? `Fields collected: ${input.formFields.join(", ")}. Form submits off-domain: ${input.offDomainSubmit ? "YES (strong phishing signal)" : "no"}.`
    : "No data-collecting forms detected.";

  return `URL: ${input.url}
Hostname: ${input.hostname}
Registrable domain: ${input.registrableDomain}
Pathname: ${input.pathname}
Expected legitimate domain: ${input.expectedLegitimateDomain ?? "none"}
URL suspicious signals: ${input.suspiciousSignals.join(", ") || "none"}

FORM CONTEXT
${formSummary}

PASSIVE INFRASTRUCTURE CONTEXT
${passiveLines}

PAGE CONTENT START
${input.domText.slice(0, 12000)}
PAGE CONTENT END

Reminder: a credential form on a legitimate domain (form submits on-domain, domain matches expected brand) should NOT raise the score. Only flag as Credential Harvester if there is a clear deception signal: off-domain submit, domain/brand mismatch, or lookalike domain.`;
}

export function buildVisualSimilaritySystemPrompt(): string {
  return [
    "You compare a legitimate brand's website screenshot against a suspicious variant to detect visual cloning for phishing.",
    "",
    "SCORING CALIBRATION for similarity_score (0–100):",
    "  0–20 : No meaningful visual resemblance. Different color palette, layout, and branding.",
    "  21–40: Superficial similarity only (both use a white background or generic navbar). Not evidence of cloning.",
    "  41–60: Some matching elements (similar hero layout, color scheme), but could be coincidental.",
    "  61–80: Clear brand copying — logo, fonts, color scheme, or page structure deliberately mimic the original.",
    "  81–100: Near-identical visual clone. Brand assets, layout, and copy are clearly copied.",
    "",
    "IMPORTANT: Do not score above 40 for generic web design patterns. Only score high if brand-specific visual elements (logo, color scheme, layout structure) are deliberately reproduced.",
    "Return strict JSON only.",
  ].join("\n");
}
