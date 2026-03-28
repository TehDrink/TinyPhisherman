import type { EvidenceSnippet, LLMAnalysis, SquatterCategory } from "@/types";
import { lexicalSimilarity } from "@/lib/typosquat";

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

export async function analyzeDOM(
  url: string,
  domText: string,
  hasLoginForm: boolean
): Promise<LLMAnalysis> {
  const fallback = heuristicAnalysis(url, domText, hasLoginForm);
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
      systemPrompt:
        "You are a phishing analyst. Score urgency, fear, authority impersonation, credential requests, and malware-delivery behavior. Return strict JSON only.",
      userContent: `URL: ${url}
Has login form: ${hasLoginForm}

PAGE CONTENT START
${domText.slice(0, 12000)}
PAGE CONTENT END`,
    });

    return {
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
    };
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
      systemPrompt:
        "You compare legitimate and suspicious website screenshots for phishing similarity. Return strict JSON only.",
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

function heuristicAnalysis(url: string, domText: string, hasLoginForm: boolean): LLMAnalysis {
  const text = domText.toLowerCase();
  const redFlags: string[] = [];
  const evidenceSnippets: EvidenceSnippet[] = [];
  let score = 5;

  score += addSignal(text, /\b(urgent|immediately|act now|verify now|suspended|locked)\b/g, 12, redFlags, "Urgency language");
  score += addSignal(text, /\b(password|otp|2fa|security code|credit card|wallet phrase|seed phrase)\b/g, 18, redFlags, "Sensitive credential request");
  score += addSignal(text, /\b(download|install|update browser|apk|setup\.exe)\b/g, 20, redFlags, "Potential malware delivery language");
  score += addSignal(text, /\b(microsoft|google|apple|paypal|amazon|coinbase|outlook|office 365)\b/g, 10, redFlags, "Possible brand impersonation");

  if (hasLoginForm) {
    score += 20;
    redFlags.push("Login or sensitive input form detected");
  }

  const impersonatedBrand = detectBrand(`${url} ${text}`);
  if (impersonatedBrand) {
    evidenceSnippets.push({
      text: impersonatedBrand,
      reason: "Recognized brand terms appear in the page content or URL.",
    });
  }

  const credentialIntent =
    hasLoginForm || /\b(password|otp|sign in|login|verify identity|credit card)\b/.test(text);

  if (credentialIntent) {
    evidenceSnippets.push({
      text: firstMatch(text, /\b(password|otp|sign in|login|verify identity|credit card)\b/),
      reason: "The page appears to request credentials or sensitive verification data.",
    });
  }

  const squatterCategory = categorize(text, hasLoginForm);
  return {
    manipulationScore: clamp(score),
    squatterCategory,
    reasoning: buildReasoning(clamp(score), squatterCategory, credentialIntent, impersonatedBrand),
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

function categorize(text: string, hasLoginForm: boolean): SquatterCategory {
  if (/\b(download|install|setup\.exe|apk|update browser)\b/.test(text)) {
    return "Malware Drop";
  }
  if (hasLoginForm || /\b(password|otp|sign in|login|credit card|verify identity)\b/.test(text)) {
    return "Credential Harvester";
  }
  if (/\b(domain for sale|buy this domain|parking|sponsored listings|ads)\b/.test(text)) {
    return "Parked/Ads";
  }
  return "Unknown";
}

function buildReasoning(
  score: number,
  category: SquatterCategory,
  credentialIntent: boolean,
  impersonatedBrand: string | null
): string {
  const parts = [
    `The page scored ${score}/100 for phishing manipulation signals.`,
    `It was categorized as ${category}.`,
    credentialIntent ? "Sensitive input requests were detected." : "No strong sensitive input request was detected.",
  ];
  if (impersonatedBrand) parts.push(`Possible impersonated brand: ${impersonatedBrand}.`);
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
