/**
 * LLM Analysis Module — uses Claude Opus 4.6 to assess phishing risk.
 *
 * Two exports:
 *  - analyzeDOM       → manipulation score + category + reasoning
 *  - compareScreenshots → visual similarity score (0-100)
 */

import Anthropic from "@anthropic-ai/sdk";
import type { LLMAnalysis, SquatterCategory } from "@/types";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ── Schemas returned by the LLM ───────────────────────────────────────────────

interface AnalysisOutput {
  manipulation_score: number;
  squatter_category: SquatterCategory;
  reasoning: string;
  red_flags: string[];
}

interface SimilarityOutput {
  similarity_score: number;
  reasoning: string;
}

// ── DOM Text Analysis ─────────────────────────────────────────────────────────

/**
 * Sends the scraped DOM text to Claude and asks it to rate psychological
 * manipulation tactics, categorise the site, and list red flags.
 */
export async function analyzeDOM(
  url: string,
  domText: string,
  hasLoginForm: boolean
): Promise<LLMAnalysis> {
  const truncated = domText.slice(0, 12_000); // keep prompt cost reasonable

  const response = await client.messages.create({
    model: "claude-opus-4-6",
    max_tokens: 1024,
    thinking: { type: "adaptive" },
    system: `You are a cybersecurity expert specializing in phishing and social engineering.
Analyze the provided webpage content and return a JSON object with exactly this shape:
{
  "manipulation_score": <integer 0-100>,
  "squatter_category": <"Parked/Ads" | "Credential Harvester" | "Malware Drop" | "Unknown">,
  "reasoning": "<2-3 sentence explanation>",
  "red_flags": ["<flag1>", "<flag2>", ...]
}

Scoring guide for manipulation_score:
- 0-30:  Benign or parked page, no manipulation tactics
- 31-60: Mild urgency/marketing language, minor concerns
- 61-75: Moderate concern — impersonation hints, urgency, suspicious form
- 76-100: High threat — explicit credential harvesting, fear/authority tactics, brand spoofing

squatter_category rules:
- "Parked/Ads":            Page is mostly ads or a domain-parking page
- "Credential Harvester":  Page actively asks for login/payment info
- "Malware Drop":          Page tries to install software, drive-by downloads
- "Unknown":               Insufficient content to categorise

Respond ONLY with the JSON object. No markdown fences.`,
    messages: [
      {
        role: "user",
        content: `URL: ${url}
Has login form: ${hasLoginForm}

--- PAGE CONTENT START ---
${truncated}
--- PAGE CONTENT END ---`,
      },
    ],
  });

  // Extract text from potentially interleaved thinking+text blocks
  const text = response.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("");

  const parsed: AnalysisOutput = JSON.parse(text);

  return {
    manipulationScore: Math.min(100, Math.max(0, parsed.manipulation_score)),
    squatterCategory: parsed.squatter_category ?? "Unknown",
    reasoning: parsed.reasoning ?? "",
    redFlags: parsed.red_flags ?? [],
  };
}

// ── Visual Similarity Check ───────────────────────────────────────────────────

/**
 * Compares two base64 PNG screenshots using Claude's vision.
 * Returns a 0-100 visual similarity score.
 */
export async function compareScreenshots(
  originalBase64: string,
  variantBase64: string,
  originalDomain: string,
  variantDomain: string
): Promise<{ score: number; reasoning: string }> {
  const response = await client.messages.create({
    model: "claude-opus-4-6",
    max_tokens: 512,
    system: `You are a visual analyst detecting typosquatting attacks.
Compare two website screenshots and return a JSON object:
{
  "similarity_score": <integer 0-100>,
  "reasoning": "<1-2 sentences>"
}

Scoring guide:
- 0-30:   Completely different layouts/branding
- 31-60:  Some similarities but clearly different
- 61-80:  Suspicious similarities — similar colours, layout, or logo
- 81-100: Near-identical clone — strong typosquatting indicator

Respond ONLY with the JSON object. No markdown fences.`,
    messages: [
      {
        role: "user",
        content: [
          {
            type: "text",
            text: `Original site (${originalDomain}):`,
          },
          {
            type: "image",
            source: { type: "base64", media_type: "image/png", data: originalBase64 },
          },
          {
            type: "text",
            text: `Suspect variant (${variantDomain}):`,
          },
          {
            type: "image",
            source: { type: "base64", media_type: "image/png", data: variantBase64 },
          },
          {
            type: "text",
            text: "Rate the visual similarity and explain your reasoning.",
          },
        ],
      },
    ],
  });

  const text = response.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("");

  const parsed: SimilarityOutput = JSON.parse(text);

  return {
    score: Math.min(100, Math.max(0, parsed.similarity_score)),
    reasoning: parsed.reasoning ?? "",
  };
}
