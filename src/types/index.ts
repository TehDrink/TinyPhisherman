// ── Shared enums ──────────────────────────────────────────────────────────────

export type ThreatLevel = "Low" | "Medium" | "High" | "Critical";

export type SquatterCategory =
  | "Parked/Ads"
  | "Credential Harvester"
  | "Malware Drop"
  | "Unknown";

// ── TinyFish raw results ───────────────────────────────────────────────────────

export interface TinyFishResult {
  url: string;
  screenshot: string; // base64 PNG
  domText: string;
  finalUrl: string; // after redirects
  statusCode: number;
  pageTitle: string;
  hasLoginForm: boolean;
  externalLinks: string[];
}

// ── LLM analysis ──────────────────────────────────────────────────────────────

export interface LLMAnalysis {
  manipulationScore: number; // 0–100
  squatterCategory: SquatterCategory;
  reasoning: string;
  redFlags: string[];
}

// ── Passive checks (mocked) ────────────────────────────────────────────────────

export interface PassiveChecks {
  domainAgeDays: number | null;
  hasSSL: boolean;
  redirectCount: number;
  registrar: string | null;
}

// ── Feature A: Single scan ────────────────────────────────────────────────────

export interface ScanRequest {
  url: string;
}

export interface ScanResult {
  url: string;
  threatLevel: ThreatLevel;
  manipulationScore: number;
  squatterCategory: SquatterCategory;
  passiveChecks: PassiveChecks;
  screenshot: string; // base64 PNG
  reasoning: string;
  redFlags: string[];
  scannedAt: string; // ISO timestamp
}

// ── Feature B: Brand hunt ─────────────────────────────────────────────────────

export interface HuntRequest {
  domain: string; // e.g. "google.com"
}

export interface TyposquatVariant {
  domain: string;
  threatLevel: ThreatLevel;
  visualSimilarity: number; // 0–100
  manipulationScore: number;
  squatterCategory: SquatterCategory;
  screenshot: string; // base64 PNG
  liveStatus: "live" | "parked" | "unreachable";
}

export interface HuntResult {
  originalDomain: string;
  originalScreenshot: string; // base64 PNG
  variants: TyposquatVariant[];
  huntedAt: string; // ISO timestamp
}

// ── API response wrappers ──────────────────────────────────────────────────────

export interface ApiSuccess<T> {
  ok: true;
  data: T;
}

export interface ApiError {
  ok: false;
  error: string;
}

export type ApiResponse<T> = ApiSuccess<T> | ApiError;
