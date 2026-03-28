"use client";

import { useMemo, useState } from "react";

type Tone = "low" | "medium" | "high" | "critical";

type EvidenceSnippet = { text: string; reason: string };

type PassiveChecks = {
  domainAgeDays?: number | null;
  hasSSL?: boolean;
  redirectCount?: number;
  registrar?: string | null;
  dnsResolved?: boolean;
  ipAddresses?: string[];
  hasMX?: boolean;
  nameservers?: string[];
  tlsIssuer?: string | null;
  tlsValidFrom?: string | null;
  tlsValidTo?: string | null;
  finalResolvedUrl?: string | null;
};

type ScanResult = {
  url?: string;
  threatLevel?: string;
  manipulationScore?: number;
  squatterCategory?: string;
  passiveChecks?: PassiveChecks;
  screenshot?: string;
  reasoning?: string;
  redFlags?: string[];
  scannedAt?: string;
  finalUrl?: string;
  pageTitle?: string;
  externalLinks?: string[];
  impersonatedBrand?: string | null;
  credentialIntent?: boolean;
  evidenceSnippets?: EvidenceSnippet[];
  visualSimilarity?: number;
};

type ScanApiResponse =
  | { ok: true; data: ScanResult }
  | { ok: false; error: string };

const scanEvidenceFallback = [
  "Form action posts to off-domain",
  "Domain registered 9 days ago",
  "Hidden iframe on submit",
  "Brand assets hotlinked",
  "TLS hostname mismatch",
];

const generateResults = [
  { domain: "tinyfish-login-secure.com", risk: "High" },
  { domain: "tinyfish-verify.io", risk: "High" },
  { domain: "support-tinyf1sh.com", risk: "Medium" },
  { domain: "tinyfish-account-check.net", risk: "Medium" },
  { domain: "login-tinyfishhelp.com", risk: "Medium" },
];

function toneFromThreat(level?: string): Tone {
  const value = level?.toLowerCase();
  if (value === "critical") return "critical";
  if (value === "high") return "high";
  if (value === "medium") return "medium";
  if (value === "low") return "low";
  return "medium";
}

function toneFromScore(score?: number): Tone {
  if (typeof score !== "number") return "medium";
  if (score >= 90) return "critical";
  if (score >= 76) return "high";
  if (score >= 41) return "medium";
  return "low";
}

function toneFromSquatter(category?: string): Tone {
  if (category === "Credential Harvester") return "critical";
  if (category === "Malware Drop") return "high";
  if (category === "Parked/Ads") return "low";
  return "medium";
}

function toneFromSimilarity(similarity?: number): Tone {
  if (typeof similarity !== "number") return "medium";
  if (similarity >= 80) return "critical";
  if (similarity >= 60) return "high";
  if (similarity >= 40) return "medium";
  return "low";
}

function ThreatBadge({ label, tone }: { label: string; tone: Tone }) {
  return <span className={`threat-badge tone-${tone}`}>{label}</span>;
}

function ScanPanel({
  scanUrl,
  setScanUrl,
  onScan,
  loading,
  error,
  result,
  previewUrl,
  previewLoading,
  previewError,
  useTinyfish,
  setUseTinyfish,
}: {
  scanUrl: string;
  setScanUrl: (value: string) => void;
  onScan: () => void;
  loading: boolean;
  error: string | null;
  result: ScanResult | null;
  previewUrl: string | null;
  previewLoading: boolean;
  previewError: string | null;
  useTinyfish: boolean;
  setUseTinyfish: (value: boolean) => void;
}) {
  const threatLabel = result?.threatLevel ?? "Unknown";
  const threatTone = toneFromThreat(threatLabel);

  const evidenceList = result?.evidenceSnippets?.length
    ? result.evidenceSnippets.map((item) => item.text)
    : result?.redFlags?.length
      ? result.redFlags
      : scanEvidenceFallback;

  const passive = result?.passiveChecks ?? {};
  const passiveSignals = [
    { label: "SSL", value: passive.hasSSL ? "Yes" : "No" },
    { label: "DNS", value: passive.dnsResolved ? "Resolved" : "No" },
    {
      label: "Redirects",
      value:
        typeof passive.redirectCount === "number"
          ? String(passive.redirectCount)
          : "N/A",
    },
    { label: "MX", value: passive.hasMX ? "Yes" : "No" },
  ];

  const metrics = [
    {
      label: "LLM Manipulation Score",
      value:
        typeof result?.manipulationScore === "number"
          ? result.manipulationScore
          : "N/A",
      unit: typeof result?.manipulationScore === "number" ? "/100" : undefined,
      tone: toneFromScore(result?.manipulationScore),
      note: ">75 is highly suspicious",
    },
    {
      label: "Visual Similarity",
      value:
        typeof result?.visualSimilarity === "number"
          ? result.visualSimilarity
          : "Not computed",
      unit: typeof result?.visualSimilarity === "number" ? "%" : undefined,
      tone: toneFromSimilarity(result?.visualSimilarity),
      note: ">80% is Critical in Feature B",
    },
    {
      label: "Squatter Categorization",
      value: result?.squatterCategory ?? "Unknown",
      tone: toneFromSquatter(result?.squatterCategory),
      note: "LLM category for live site",
    },
  ];

  const screenshotSrc =
    result?.screenshot && result.screenshot.length > 0
      ? `data:image/png;base64,${result.screenshot}`
      : null;

  return (
    <div className="panel-grid">
      <div className="card">
        <h3>Scan a suspicious link</h3>
        <label className="field" htmlFor="scan-url">
          URL to verify
        </label>
        <input
          id="scan-url"
          type="text"
          placeholder="https://secure-tinyfish-login.com"
          value={scanUrl}
          onChange={(event) => setScanUrl(event.target.value)}
        />
        <div className="options">
          <label>
            <input
              type="checkbox"
              checked={useTinyfish}
              onChange={(event) => setUseTinyfish(event.target.checked)}
            />
            Run TinyFish exploration
          </label>
          <label>
            <input type="checkbox" defaultChecked />
            Run passive DNS + WHOIS checks
          </label>
        </div>
        <button className="btn" type="button" onClick={onScan} disabled={loading}>
          {loading ? "Scanning..." : "Verify link"}
        </button>
        {error ? <p className="status error">{error}</p> : null}
        <p className="help">
          Runs in a sandbox with fake credentials. No user data is exposed.
        </p>
      </div>

      <div className="card">
        <div className="result-head">
          <div>
            <p className="eyebrow">Threat level</p>
            <h3>{threatLabel} threat</h3>
          </div>
          <ThreatBadge label={threatLabel} tone={threatTone} />
        </div>

        {result?.finalUrl ? <p className="status">Final URL: {result.finalUrl}</p> : null}

        <div className="result-block">
          <h4>Live browser preview</h4>
          {previewUrl ? (
            <div className="preview-frame">
              <iframe
                title="TinyFish live preview"
                src={previewUrl}
                sandbox="allow-scripts allow-same-origin"
                referrerPolicy="no-referrer"
              />
            </div>
          ) : !useTinyfish ? (
            <p className="status">TinyFish exploration is turned off.</p>
          ) : previewLoading ? (
            <p className="status">Starting live preview…</p>
          ) : (
            <p className="status">Run a scan to see the live preview.</p>
          )}
          {previewError ? <p className="status error">{previewError}</p> : null}
        </div>

        <div className="result-block">
          <h4>Threat metrics</h4>
          <div className="metric-grid">
            {metrics.map((metric) => (
              <div key={metric.label} className="metric">
                <div>
                  <p className="metric-label">{metric.label}</p>
                  <p className="metric-note">{metric.note}</p>
                </div>
                <div className={`metric-value tone-${metric.tone}`}>
                  {metric.value}
                  {metric.unit ? <span className="metric-unit">{metric.unit}</span> : null}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="result-block">
          <h4>Evidence</h4>
          <ul className="simple-list">
            {evidenceList.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          {result?.reasoning ? <p className="status">Why: {result.reasoning}</p> : null}
        </div>

        <div className="result-block">
          <h4>Passive checks</h4>
          <div className="signal-grid">
            {passiveSignals.map((signal) => (
              <div key={signal.label} className="signal">
                <span>{signal.label}</span>
                <strong>{signal.value}</strong>
              </div>
            ))}
          </div>
        </div>

        <div className="result-block">
          <h4>Screenshot</h4>
          <div className="shot-row">
            {screenshotSrc ? (
              <img className="shot-image" src={screenshotSrc} alt="Scan screenshot" />
            ) : (
              <>
                <span>Landing page</span>
                <span>Login form</span>
                <span>Redirect chain</span>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function GeneratePanel() {
  return (
    <div className="panel-grid">
      <div className="card">
        <h3>Generate phishing lookalikes</h3>
        <label className="field" htmlFor="legit-url">
          Legit domain to protect
        </label>
        <input id="legit-url" type="text" placeholder="https://tinyfish.io" />
        <div className="options">
          <label>
            <input type="checkbox" defaultChecked />
            Typosquatting + homographs
          </label>
          <label>
            <input type="checkbox" defaultChecked />
            TLD and keyword variants
          </label>
        </div>
        <button className="btn" type="button">
          Generate candidates
        </button>
        <p className="help">We validate live hosts in parallel.</p>
      </div>

      <div className="card">
        <div className="result-head">
          <div>
            <p className="eyebrow">High-risk candidates</p>
            <h3>5 lookalike domains</h3>
          </div>
          <span className="pill">Needs review</span>
        </div>
        <div className="table">
          <div className="table-head">
            <span>Domain</span>
            <span>Risk</span>
          </div>
          {generateResults.map((row) => (
            <div key={row.domain} className="table-row">
              <span className="mono">{row.domain}</span>
              <span>{row.risk}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function Home() {
  const [activeCase, setActiveCase] = useState("scan");
  const [scanUrl, setScanUrl] = useState("");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [useTinyfish, setUseTinyfish] = useState(true);

  const introCopy = useMemo(() => {
    if (activeCase === "scan") {
      return "Paste a suspicious link and get a clear threat level with evidence.";
    }
    return "Generate lookalike domains and validate which ones are live.";
  }, [activeCase]);

  const handleScan = async () => {
    const target = scanUrl.trim();
    if (!target) {
      setScanError("Please enter a URL to scan.");
      return;
    }

    setScanLoading(true);
    setScanError(null);
    setPreviewUrl(null);
    setPreviewError(null);
    setPreviewLoading(useTinyfish);

    if (useTinyfish) {
      void (async () => {
        try {
          const res = await fetch(`/api/scan/preview?url=${encodeURIComponent(target)}`);
          const json = (await res.json()) as
            | { ok: true; data: { streamingUrl: string } }
            | { ok: false; error: string };

          if (!res.ok || !json.ok) {
            throw new Error("error" in json ? json.error : "Preview failed.");
          }

          setPreviewUrl(json.data.streamingUrl);
        } catch (err) {
          setPreviewError(err instanceof Error ? err.message : "Preview failed.");
        } finally {
          setPreviewLoading(false);
        }
      })();
    }

    try {
      const res = await fetch(
        `/api/scan?url=${encodeURIComponent(target)}&useTinyfish=${useTinyfish ? "true" : "false"}`
      );
      const json = (await res.json()) as ScanApiResponse;

      if (!res.ok || !json.ok) {
        throw new Error("error" in json ? json.error : "Scan failed.");
      }

      setScanResult(json.data);
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Scan failed.");
    } finally {
      setScanLoading(false);
    }
  };

  return (
    <div className="page">
      <header className="site-header">
        <div className="brand">
          <img className="brand-mark" src="/favicon.png" alt="TinyPhisherman icon" />
          <div>
            <h1>TinyPhisherman</h1>
            <p className="tagline">Phishing website detector</p>
          </div>
        </div>
      </header>

      <main>
        <section className="intro">
          <h2>Check links safely before anyone clicks.</h2>
          <p>{introCopy}</p>
          <div className="pill-row">
            <span className="pill">Elder-friendly</span>
            <span className="pill">No real credentials</span>
            <span className="pill">Evidence-first</span>
          </div>
        </section>

        <section className="tabs" role="tablist" aria-label="Use case selector">
          <button
            className={`tab ${activeCase === "scan" ? "active" : ""}`}
            type="button"
            role="tab"
            aria-selected={activeCase === "scan"}
            onClick={() => setActiveCase("scan")}
          >
            Check suspicious link
          </button>
          <button
            className={`tab ${activeCase === "generate" ? "active" : ""}`}
            type="button"
            role="tab"
            aria-selected={activeCase === "generate"}
            onClick={() => setActiveCase("generate")}
          >
            Reverse engineer phishing
          </button>
        </section>

        <section>
          {activeCase === "scan" ? (
            <ScanPanel
              scanUrl={scanUrl}
              setScanUrl={setScanUrl}
              onScan={handleScan}
              loading={scanLoading}
              error={scanError}
              result={scanResult}
              previewUrl={previewUrl}
              previewLoading={previewLoading}
              previewError={previewError}
              useTinyfish={useTinyfish}
              setUseTinyfish={setUseTinyfish}
            />
          ) : (
            <GeneratePanel />
          )}
        </section>

        <section className="footer-note">
          <p>
            TinyPhisherman is a hackathon prototype. Always verify findings before
            taking action.
          </p>
        </section>
      </main>
    </div>
  );
}
