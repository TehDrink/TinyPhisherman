// ── Shared enums ──────────────────────────────────────────────────────────────

export type ThreatLevel = "Low" | "Medium" | "High" | "Critical";

export type SquatterCategory =
  | "Parked/Ads"
  | "Credential Harvester"
  | "Malware Drop"
  | "Unknown";

export interface EvidenceSnippet {
  text: string;
  reason: string;
}

export interface PassiveChecks {
  domainAgeDays: number | null;
  hasSSL: boolean;
  redirectCount: number;
  registrar: string | null;
  dnsResolved?: boolean;
  ipAddresses?: string[];
  hasMX?: boolean;
  nameservers?: string[];
  tlsIssuer?: string | null;
  tlsValidFrom?: string | null;
  tlsValidTo?: string | null;
  finalResolvedUrl?: string | null;
}

// ── TinyFish raw results ───────────────────────────────────────────────────────

export interface TinyFishResult {
  url: string;
  screenshot: string;
  domText: string;
  finalUrl: string;
  statusCode: number;
  pageTitle: string;
  hasLoginForm: boolean;
  externalLinks: string[];
}

// ── LLM analysis ──────────────────────────────────────────────────────────────

export interface LLMAnalysis {
  manipulationScore: number;
  squatterCategory: SquatterCategory;
  reasoning: string;
  redFlags: string[];
  impersonatedBrand?: string | null;
  credentialIntent?: boolean;
  evidenceSnippets?: EvidenceSnippet[];
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
  screenshot: string;
  reasoning: string;
  redFlags: string[];
  scannedAt: string;
  finalUrl?: string;
  pageTitle?: string;
  externalLinks?: string[];
  impersonatedBrand?: string | null;
  credentialIntent?: boolean;
  evidenceSnippets?: EvidenceSnippet[];
}

// ── Feature B: Brand hunt ─────────────────────────────────────────────────────

export interface HuntRequest {
  domain: string;
}

export interface TyposquatVariant {
  domain: string;
  threatLevel: ThreatLevel;
  visualSimilarity: number;
  manipulationScore: number;
  squatterCategory: SquatterCategory;
  screenshot: string;
  liveStatus: "live" | "parked" | "unreachable";
  reasoning?: string;
  passiveChecks?: PassiveChecks;
  finalUrl?: string;
  pageTitle?: string;
  evidenceSnippets?: EvidenceSnippet[];
  impersonatedBrand?: string | null;
}

export interface HuntResult {
  originalDomain: string;
  originalScreenshot: string;
  variants: TyposquatVariant[];
  huntedAt: string;
  discoveryMethod?: "dnstwist" | "heuristic";
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
