import type { EvidenceSnippet, LLMAnalysis, SquatterCategory } from "@/types";
import { lexicalSimilarity } from "@/lib/typosquat";
import {
  buildPhishingAnalysisSystemPrompt,
  buildPhishingAnalysisUserPrompt,
  buildVisualSimilaritySystemPrompt,
} from "@/prompts/analysis";

const OPENAI_API_KEY = process.env.OPENAI_API_KEY ?? "";
const OPENAI_MODEL = process.env.OPENAI_MODEL ?? "gpt-4.1-mini";

interface AnalysisOutput {
  manipulation_score: number;
  squatter_category: SquatterCategory;
  reasoning: string;
  red_flags: string[];
  impersonated_brand: string | null;
  credential_intent: boolean;
  evidence_snippets: EvidenceSnippet[];
}

interface SimilarityOutput {
  similarity_score: number;
  reasoning: string;
}

interface AnalysisContextInput {
  expectedDomain?: string;
  domainAgeDays?: number | null;
  hasSSL?: boolean;
  registrar?: string | null;
  urlscanMalicious?: boolean;
  urlscanScore?: number | null;
}

interface UrlContext {
  hostname: string;
  registrableDomain: string;
  pathname: string;
  expectedRegistrableDomain: string | null;
  suspiciousSignals: string[];
  suspiciousScore: number;
  rawIpHost: boolean;
  deepSubdomain: boolean;
  hasPunycode: boolean;
  hasAuthKeyword: boolean;
  isExactExpectedDomain: boolean;
  isLookalikeToExpected: boolean;
}

const SENSITIVE_FIELDS = new Set(["password", "otp", "credit_card", "cvv", "ssn"]);

export async function analyzeDOM(
  url: string,
  domText: string,
  formFields: string[],
  offDomainSubmit: boolean,
  context: AnalysisContextInput = {}
): Promise<LLMAnalysis> {
  const hasLoginForm = formFields.some((f) => SENSITIVE_FIELDS.has(f));
  const fallback = heuristicAnalysis(url, domText, hasLoginForm, offDomainSubmit, context);
  const urlContext = inspectUrl(url, context.expectedDomain);
  if (!OPENAI_API_KEY) return fallback;

  try {
    const parsed = await openAIJson<AnalysisOutput>({
      schemaName: "phishing_dom_analysis",
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          manipulation_score: { type: "integer" },
          squatter_category: {
            type: "string",
            enum: ["Parked/Ads", "Credential Harvester", "Malware Drop", "Unknown"],
          },
          reasoning: { type: "string" },
          red_flags: { type: "array", items: { type: "string" } },
          impersonated_brand: { type: ["string", "null"] },
          credential_intent: { type: "boolean" },
          evidence_snippets: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              properties: {
                text: { type: "string" },
                reason: { type: "string" },
              },
              required: ["text", "reason"],
            },
          },
        },
        required: [
          "manipulation_score",
          "squatter_category",
          "reasoning",
          "red_flags",
          "impersonated_brand",
          "credential_intent",
          "evidence_snippets",
        ],
      },
      systemPrompt: buildPhishingAnalysisSystemPrompt(),
      userContent: buildPhishingAnalysisUserPrompt({
        url,
        hostname: urlContext.hostname,
        registrableDomain: urlContext.registrableDomain,
        pathname: urlContext.pathname,
        expectedLegitimateDomain: urlContext.expectedRegistrableDomain,
        formFields,
        offDomainSubmit,
        suspiciousSignals: urlContext.suspiciousSignals,
        domText,
        domainAgeDays: context.domainAgeDays,
        hasSSL: context.hasSSL,
        registrar: context.registrar,
        urlscanMalicious: context.urlscanMalicious,
        urlscanScore: context.urlscanScore,
      }),
    });

    const normalized = normalizeAnalysis(
      {
        manipulationScore: clamp(parsed.manipulation_score),
        squatterCategory: parsed.squatter_category ?? fallback.squatterCategory,
        reasoning: parsed.reasoning || fallback.reasoning,
        redFlags: sanitizeStringArray(parsed.red_flags, fallback.redFlags),
        impersonatedBrand: parsed.impersonated_brand ?? fallback.impersonatedBrand ?? null,
        credentialIntent:
          typeof parsed.credential_intent === "boolean"
            ? parsed.credential_intent
            : fallback.credentialIntent,
        evidenceSnippets: sanitizeEvidence(parsed.evidence_snippets, fallback.evidenceSnippets ?? []),
      },
      urlContext,
      offDomainSubmit
    );

    return normalized;
  } catch {
    return fallback;
  }
}

export async function compareScreenshots(
  originalBase64: string,
  variantBase64: string,
  originalDomain: string,
  variantDomain: string
): Promise<{ score: number; reasoning: string }> {
  if (!originalBase64 || !variantBase64) {
    return {
      score: 0,
      reasoning: `Screenshot comparison unavailable for ${variantDomain}; one or both screenshots were missing.`,
    };
  }

  const fallback = {
    score: lexicalSimilarity(originalDomain, variantDomain),
    reasoning: "Using domain similarity fallback because model-based screenshot comparison was unavailable.",
  };

  if (!OPENAI_API_KEY) return fallback;

  try {
    const parsed = await openAIJson<SimilarityOutput>({
      schemaName: "visual_similarity",
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          similarity_score: { type: "integer" },
          reasoning: { type: "string" },
        },
        required: ["similarity_score", "reasoning"],
      },
      systemPrompt: buildVisualSimilaritySystemPrompt(),
      userContent: [
        { type: "text", text: `Original domain: ${originalDomain}` },
        { type: "image_url", image_url: { url: `data:image/png;base64,${originalBase64}` } },
        { type: "text", text: `Variant domain: ${variantDomain}` },
        { type: "image_url", image_url: { url: `data:image/png;base64,${variantBase64}` } },
      ],
    });

    return {
      score: clamp(parsed.similarity_score),
      reasoning: parsed.reasoning || fallback.reasoning,
    };
  } catch {
    return fallback;
  }
}

async function openAIJson<T>({
  schemaName,
  schema,
  systemPrompt,
  userContent,
}: {
  schemaName: string;
  schema: object;
  systemPrompt: string;
  userContent: string | Array<Record<string, unknown>>;
}): Promise<T> {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_API_KEY}`,
    },
    signal: AbortSignal.timeout(30000),
    body: JSON.stringify({
      model: OPENAI_MODEL,
      response_format: {
        type: "json_schema",
        json_schema: {
          name: schemaName,
          strict: true,
          schema,
        },
      },
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userContent },
      ],
    }),
  });

  if (!res.ok) {
    throw new Error(`OpenAI error ${res.status}`);
  }

  const data = (await res.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error("Missing model content");
  return JSON.parse(content) as T;
}

function heuristicAnalysis(
  url: string,
  domText: string,
  hasLoginForm: boolean,
  offDomainSubmit: boolean,
  context: AnalysisContextInput
): LLMAnalysis {
  const text = domText.toLowerCase();
  const urlContext = inspectUrl(url, context.expectedDomain);
  const redFlags: string[] = [];
  const evidenceSnippets: EvidenceSnippet[] = [];
  let score = 2 + urlContext.suspiciousScore;

  score += addSignal(text, /\b(urgent|immediately|act now|verify now|suspended|locked)\b/g, 12, redFlags, "Urgency language");
  score += addSignal(text, /\b(password|otp|2fa|security code|credit card|wallet phrase|seed phrase)\b/g, 18, redFlags, "Sensitive credential request");
  score += addSignal(text, /\b(download|install|update browser|apk|setup\.exe)\b/g, 20, redFlags, "Potential malware delivery language");
  score += addSignal(text, /\b(microsoft|google|apple|paypal|amazon|coinbase|outlook|office 365)\b/g, 10, redFlags, "Possible brand impersonation");

  const impersonatedBrand = detectBrand(`${url} ${text}`);
  const domainMatchesBrand = impersonatedBrand
    ? doesDomainMatchBrand(urlContext.registrableDomain, urlContext.hostname, impersonatedBrand)
    : false;
  const deceptiveBrandMismatch = Boolean(
    impersonatedBrand && !domainMatchesBrand && !urlContext.isExactExpectedDomain
  );

  // hasLoginForm = true only for password/OTP/payment fields (SENSITIVE_FIELDS).
  // A form that only collects email/name/phone is a lead-gen form — normal on ad-farming
  // pages and should NOT trigger the same scoring as a credential harvester.
  const hasLeadGenFormOnly = offDomainSubmit && !hasLoginForm;

  if (offDomainSubmit && hasLoginForm) {
    // Sensitive credentials (password/OTP/payment) going to a different domain — strong signal.
    score += 30;
    redFlags.push("Sensitive credentials submitted to a different domain");
  } else if (hasLeadGenFormOnly) {
    // Email/name going off-domain is typical ad-network lead capture — minimal signal.
    score += 3;
  } else if (hasLoginForm) {
    // Sensitive form on-domain: only suspicious if there's a brand/domain mismatch.
    if (deceptiveBrandMismatch || urlContext.isLookalikeToExpected || urlContext.suspiciousScore >= 18) {
      score += 20;
      redFlags.push("Credential form on a suspicious or off-brand domain");
    }
  }

  if (impersonatedBrand) {
    evidenceSnippets.push({
      text: impersonatedBrand,
      reason: "Recognized brand terms appear in the page content or URL.",
    });
    if (deceptiveBrandMismatch) {
      redFlags.push(`Brand mismatch: content references ${impersonatedBrand} on a different domain`);
    }
  }

  const credentialIntent =
    hasLoginForm || /\b(password|otp|sign in|login|verify identity|credit card)\b/.test(text);

  if (credentialIntent) {
    evidenceSnippets.push({
      text: firstMatch(text, /\b(password|otp|sign in|login|verify identity|credit card)\b/),
      reason: "The page appears to request credentials or sensitive verification data.",
    });
  }

  if (urlContext.suspiciousSignals.length > 0) {
    evidenceSnippets.push({
      text: urlContext.hostname,
      reason: `Hostname signals: ${urlContext.suspiciousSignals.join(", ")}.`,
    });
  }

  if (domainMatchesBrand && !deceptiveBrandMismatch && !urlContext.isLookalikeToExpected) {
    score -= 16;
  }

  const squatterCategory = categorize(
    text,
    hasLoginForm,
    urlContext,
    credentialIntent,
    deceptiveBrandMismatch
  );
  return {
    manipulationScore: clamp(score),
    squatterCategory,
    reasoning: buildReasoning(
      clamp(score),
      squatterCategory,
      credentialIntent,
      impersonatedBrand,
      urlContext,
      deceptiveBrandMismatch
    ),
    redFlags: Array.from(new Set(redFlags)).slice(0, 6),
    impersonatedBrand,
    credentialIntent,
    evidenceSnippets: evidenceSnippets.slice(0, 5),
  };
}

function addSignal(
  text: string,
  regex: RegExp,
  points: number,
  redFlags: string[],
  label: string
): number {
  const matches = text.match(regex);
  if (!matches?.length) return 0;
  redFlags.push(label);
  return Math.min(matches.length * points, points * 2);
}

function categorize(
  text: string,
  hasLoginForm: boolean,
  urlContext: UrlContext,
  credentialIntent: boolean,
  deceptiveBrandMismatch: boolean
): SquatterCategory {
  if (/\b(download|install|setup\.exe|apk|update browser)\b/.test(text)) {
    return "Malware Drop";
  }

  const looksParked = /\b(domain for sale|buy this domain|parking|sponsored listings|sponsored results|related searches)\b/.test(text);
  const hasDeceptiveContext = deceptiveBrandMismatch || urlContext.isLookalikeToExpected || urlContext.suspiciousScore >= 18;

  // Parked/ad-farming page: classify as Parked/Ads unless there is BOTH a sensitive
  // credential form AND a deceptive brand/domain signal. A lead-gen form (email/name)
  // inside an ad unit on a parked page is not phishing.
  if (looksParked && !(hasLoginForm && hasDeceptiveContext)) {
    return "Parked/Ads";
  }

  if (
    credentialIntent &&
    hasLoginForm &&   // must actually have sensitive fields, not just text mentions
    hasDeceptiveContext
  ) {
    return "Credential Harvester";
  }

  // credentialIntent from text alone (e.g. "login" mentioned in an ad) without a
  // real sensitive form is not enough to classify as Credential Harvester.
  if (
    credentialIntent &&
    !hasLoginForm &&
    (deceptiveBrandMismatch || urlContext.isLookalikeToExpected)
  ) {
    return "Credential Harvester";
  }

  return "Unknown";
}

function buildReasoning(
  score: number,
  category: SquatterCategory,
  credentialIntent: boolean,
  impersonatedBrand: string | null,
  urlContext: UrlContext,
  deceptiveBrandMismatch: boolean
): string {
  const parts = [
    `The page scored ${score}/100 for phishing manipulation signals.`,
    `It was categorized as ${category}.`,
    credentialIntent ? "Sensitive input requests were detected." : "No strong sensitive input request was detected.",
  ];
  if (impersonatedBrand) parts.push(`Possible impersonated brand: ${impersonatedBrand}.`);
  if (deceptiveBrandMismatch) parts.push("The referenced brand does not align with the observed domain.");
  if (urlContext.suspiciousSignals.length > 0) {
    parts.push(`URL signals: ${urlContext.suspiciousSignals.join(", ")}.`);
  }
  return parts.join(" ");
}

function detectBrand(text: string): string | null {
  const brands = ["microsoft", "google", "apple", "paypal", "amazon", "coinbase", "outlook", "office 365"];
  return brands.find((brand) => text.includes(brand)) ?? null;
}

function firstMatch(text: string, regex: RegExp): string {
  return text.match(regex)?.[0] ?? "Suspicious credential request";
}

function sanitizeStringArray(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) return fallback;
  return value.filter((item): item is string => typeof item === "string").slice(0, 6);
}

function sanitizeEvidence(value: unknown, fallback: EvidenceSnippet[]): EvidenceSnippet[] {
  if (!Array.isArray(value)) return fallback;
  const items = value.filter(
    (item): item is EvidenceSnippet =>
      Boolean(
        item &&
          typeof item === "object" &&
          "text" in item &&
          "reason" in item &&
          typeof (item as { text: unknown }).text === "string" &&
          typeof (item as { reason: unknown }).reason === "string"
      )
  );
  return items.slice(0, 5);
}

function clamp(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

function normalizeAnalysis(
  analysis: LLMAnalysis,
  urlContext: UrlContext,
  hasLoginForm: boolean
): LLMAnalysis {
  const category = adjustCategory(
    analysis.squatterCategory,
    analysis.impersonatedBrand ?? null,
    urlContext,
    Boolean(analysis.credentialIntent || hasLoginForm)
  );

  let manipulationScore = analysis.manipulationScore;
  if (
    category !== "Credential Harvester" &&
    analysis.squatterCategory === "Credential Harvester" &&
    urlContext.suspiciousScore < 18
  ) {
    manipulationScore = Math.max(0, manipulationScore - 18);
  }

  const redFlags = [...analysis.redFlags];
  if (urlContext.suspiciousSignals.length > 0 && redFlags.length < 6) {
    redFlags.push(`Suspicious URL signals: ${urlContext.suspiciousSignals.join(", ")}`);
  }

  return {
    ...analysis,
    manipulationScore: clamp(manipulationScore),
    squatterCategory: category,
    redFlags: Array.from(new Set(redFlags)).slice(0, 6),
  };
}

function adjustCategory(
  category: SquatterCategory,
  impersonatedBrand: string | null,
  urlContext: UrlContext,
  credentialIntent: boolean
): SquatterCategory {
  if (category === "Malware Drop" || category === "Parked/Ads") {
    return category;
  }

  const domainMatchesBrand = impersonatedBrand
    ? doesDomainMatchBrand(urlContext.registrableDomain, urlContext.hostname, impersonatedBrand)
    : false;

  if (
    category === "Credential Harvester" &&
    credentialIntent &&
    !urlContext.isLookalikeToExpected &&
    !urlContext.rawIpHost &&
    !urlContext.hasPunycode &&
    urlContext.suspiciousScore < 18 &&
    (domainMatchesBrand || urlContext.isExactExpectedDomain)
  ) {
    return "Unknown";
  }

  return category;
}

function inspectUrl(url: string, expectedDomain?: string): UrlContext {
  const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
  const hostname = parsed.hostname.toLowerCase();
  const registrableDomain = toRegistrableDomain(hostname);
  const expectedRegistrableDomain = expectedDomain
    ? toRegistrableDomain(expectedDomain.toLowerCase())
    : null;
  const labels = hostname.split(".").filter(Boolean);
  const suspiciousSignals: string[] = [];
  let suspiciousScore = 0;

  const rawIpHost = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
  const hasPunycode = hostname.includes("xn--");
  const deepSubdomain = labels.length >= 4;
  const hyphenCount = (hostname.match(/-/g) ?? []).length;
  const hasAuthKeyword = /\b(login|signin|verify|secure|account|auth|wallet|support|update|recover)\b/.test(
    hostname.replace(/\./g, " ")
  );

  if (rawIpHost) {
    suspiciousSignals.push("raw IP host");
    suspiciousScore += 24;
  }
  if (hasPunycode) {
    suspiciousSignals.push("punycode hostname");
    suspiciousScore += 20;
  }
  if (deepSubdomain) {
    suspiciousSignals.push("deep subdomain chain");
    suspiciousScore += 8;
  }
  if (hyphenCount >= 2) {
    suspiciousSignals.push("multiple hyphens");
    suspiciousScore += 8;
  }
  if (hasAuthKeyword) {
    suspiciousSignals.push("credential-themed hostname");
    suspiciousScore += 10;
  }
  if (parsed.pathname.length > 40 || /\/(verify|login|signin|security|update|recover|auth)\b/i.test(parsed.pathname)) {
    suspiciousSignals.push("credential-themed path");
    suspiciousScore += 6;
  }

  const isExactExpectedDomain = Boolean(
    expectedRegistrableDomain && registrableDomain === expectedRegistrableDomain
  );
  const isLookalikeToExpected = Boolean(
    expectedRegistrableDomain &&
      registrableDomain !== expectedRegistrableDomain &&
      lexicalSimilarity(registrableDomain, expectedRegistrableDomain) >= 65
  );

  if (isLookalikeToExpected) {
    suspiciousSignals.push("lookalike to expected domain");
    suspiciousScore += 18;
  }

  return {
    hostname,
    registrableDomain,
    pathname: parsed.pathname || "/",
    expectedRegistrableDomain,
    suspiciousSignals,
    suspiciousScore,
    rawIpHost,
    deepSubdomain,
    hasPunycode,
    hasAuthKeyword,
    isExactExpectedDomain,
    isLookalikeToExpected,
  };
}

function toRegistrableDomain(input: string): string {
  const hostname = input.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
  const labels = hostname.split(".").filter(Boolean);
  if (labels.length <= 2) return hostname;

  const joinedLastTwo = labels.slice(-2).join(".");
  const joinedLastThree = labels.slice(-3).join(".");
  const secondLevelTlds = new Set([
    "co.uk",
    "com.sg",
    "com.au",
    "co.jp",
    "com.br",
    "co.in",
    "com.my",
    "com.hk",
  ]);

  if (secondLevelTlds.has(joinedLastTwo)) {
    return joinedLastThree;
  }

  return joinedLastTwo;
}

function doesDomainMatchBrand(
  registrableDomain: string,
  hostname: string,
  brand: string
): boolean {
  const normalizedBrand = brand.toLowerCase();
  const brandTokens: Record<string, string[]> = {
    microsoft: ["microsoft", "microsoftonline", "live", "outlook"],
    google: ["google", "gmail", "gstatic", "youtube"],
    apple: ["apple", "icloud"],
    paypal: ["paypal"],
    amazon: ["amazon", "aws"],
    coinbase: ["coinbase"],
    outlook: ["outlook", "office", "live", "microsoft"],
    "office 365": ["office", "microsoft", "live"],
  };

  const tokens = brandTokens[normalizedBrand] ?? [normalizedBrand.replace(/\s+/g, "")];
  return tokens.some(
    (token) => registrableDomain.includes(token) || hostname.includes(token)
  );
}
