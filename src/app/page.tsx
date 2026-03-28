"use client";

import { useEffect, useMemo, useState } from "react";

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

type TyposquatVariant = {
  domain?: string;
  threatLevel?: string;
  visualSimilarity?: number;
  manipulationScore?: number;
  squatterCategory?: string;
  screenshot?: string;
  liveStatus?: string;
  reasoning?: string;
  passiveChecks?: PassiveChecks;
  finalUrl?: string;
  pageTitle?: string;
  evidenceSnippets?: EvidenceSnippet[];
  impersonatedBrand?: string | null;
};

type HuntResult = {
  originalDomain?: string;
  originalScreenshot?: string;
  variants?: TyposquatVariant[];
  huntedAt?: string;
  discoveryMethod?: string;
};

type HuntApiResponse =
  | { ok: true; data: HuntResult }
  | { ok: false; error: string };

type ActivityItem = {
  label: string;
  detail: string;
  status: "pending" | "active" | "done" | "error";
};

const scanEvidenceFallback = [
  "Form action posts to off-domain",
  "Domain registered 9 days ago",
  "Hidden iframe on submit",
  "Brand assets hotlinked",
  "TLS hostname mismatch",
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

function formatDate(value?: string | null) {
  if (!value) return "Not yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function summarizePassiveChecks(passive?: PassiveChecks) {
  if (!passive) return "Passive infrastructure checks pending.";

  const fragments = [
    passive.dnsResolved ? "DNS resolved" : "DNS unresolved",
    passive.hasSSL ? "HTTPS served" : "No valid SSL",
    typeof passive.redirectCount === "number"
      ? `${passive.redirectCount} redirects`
      : "Redirect path unknown",
  ];

  return fragments.join(" • ");
}

function ThreatBadge({ label, tone }: { label: string; tone: Tone }) {
  return <span className={`threat-badge tone-${tone}`}>{label}</span>;
}

function MetricCard({
  label,
  note,
  value,
  unit,
  tone,
}: {
  label: string;
  note: string;
  value: string | number;
  unit?: string;
  tone: Tone;
}) {
  return (
    <div className="metric">
      <div>
        <p className="metric-label">{label}</p>
        <p className="metric-note">{note}</p>
      </div>
      <div className={`metric-value tone-${tone}`}>
        {value}
        {unit ? <span className="metric-unit">{unit}</span> : null}
      </div>
    </div>
  );
}

function ActivityFeed({
  title,
  progress,
  items,
  activeTarget,
}: {
  title: string;
  progress: number;
  items: ActivityItem[];
  activeTarget?: string | null;
}) {
  return (
    <div className="card activity-card">
      <div className="activity-head">
        <div>
          <p className="eyebrow">TinyFish activity</p>
          <h3>{title}</h3>
        </div>
        <span className="progress-chip">{progress}%</span>
      </div>
      <div className="activity-bar">
        <span style={{ width: `${progress}%` }} />
      </div>
      {activeTarget ? <p className="status">Target: {activeTarget}</p> : null}
      <div className="activity-list">
        {items.map((item) => (
          <div key={item.label} className={`activity-item status-${item.status}`}>
            <span className="activity-dot" />
            <div>
              <p className="activity-label">{item.label}</p>
              <p className="activity-detail">{item.detail}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EvidenceCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="card evidence-card">
      <h4>{title}</h4>
      {children}
    </div>
  );
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
  const passive = result?.passiveChecks ?? {};
  const screenshotSrc =
    result?.screenshot && result.screenshot.length > 0
      ? `data:image/png;base64,${result.screenshot}`
      : null;

  const evidenceList = result?.evidenceSnippets?.length
    ? result.evidenceSnippets.map((item) => item.text)
    : result?.redFlags?.length
      ? result.redFlags
      : scanEvidenceFallback;

  const activityItems = useMemo<ActivityItem[]>(() => {
    const items: ActivityItem[] = [
      {
        label: "Preview tunnel",
        detail: !useTinyfish
          ? "Live browser stream is disabled."
          : previewError
            ? previewError
            : previewUrl
              ? "Remote browser stream is attached."
              : previewLoading
                ? "Booting remote browser session."
                : "Waiting for scan to start.",
        status: !useTinyfish
          ? "pending"
          : previewError
            ? "error"
            : previewUrl
              ? "done"
              : previewLoading
                ? "active"
                : "pending",
      },
      {
        label: "Victim simulation",
        detail: loading
          ? "TinyFish is exploring forms, buttons, and internal links."
          : result
            ? "Interaction pass completed with evidence captured."
            : "No interaction run yet.",
        status: loading ? "active" : result ? "done" : "pending",
      },
      {
        label: "Threat reasoning",
        detail: error
          ? error
          : result?.reasoning
            ? result.reasoning
            : "LLM scoring and passive analysis will land here.",
        status: error ? "error" : result ? "done" : loading ? "active" : "pending",
      },
    ];

    return items;
  }, [error, loading, previewError, previewLoading, previewUrl, result, useTinyfish]);

  const progress = useMemo(() => {
    if (error) return 100;
    if (result) return 100;
    if (loading && previewLoading) return 45;
    if (loading) return 72;
    if (previewLoading) return 24;
    return 8;
  }, [error, loading, previewLoading, result]);

  return (
    <div className="workspace">
      <aside className="workspace-rail">
        <div className="card control-card">
          <div className="section-head">
            <div>
              <p className="eyebrow">Verify URL</p>
              <h3>Investigate a suspicious page</h3>
            </div>
            <ThreatBadge label={threatLabel} tone={threatTone} />
          </div>
          <label className="field" htmlFor="scan-url">
            Suspicious URL
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
              Active TinyFish exploration
            </label>
            <label>
              <input type="checkbox" checked readOnly />
              Passive DNS, TLS, and registration checks
            </label>
          </div>
          <button className="btn" type="button" onClick={onScan} disabled={loading}>
            {loading ? "Running verification..." : "Verify link"}
          </button>
          {error ? <p className="status error">{error}</p> : null}
          <div className="inline-stat-grid">
            <div className="inline-stat">
              <span>Last scan</span>
              <strong>{formatDate(result?.scannedAt)}</strong>
            </div>
            <div className="inline-stat">
              <span>Final URL</span>
              <strong>{result?.finalUrl ?? "Pending"}</strong>
            </div>
          </div>
          <p className="help">
            TinyFish uses fake bait credentials and bounded interaction only.
          </p>
        </div>

        <ActivityFeed
          title="Live verification pipeline"
          progress={progress}
          items={activityItems}
          activeTarget={scanUrl || result?.url || null}
        />

        <EvidenceCard title="Passive posture">
          <div className="signal-grid compact-grid">
            <div className="signal">
              <span>DNS</span>
              <strong>{passive.dnsResolved ? "Resolved" : "Unknown"}</strong>
            </div>
            <div className="signal">
              <span>HTTPS</span>
              <strong>{passive.hasSSL ? "Present" : "Unknown"}</strong>
            </div>
            <div className="signal">
              <span>Redirects</span>
              <strong>
                {typeof passive.redirectCount === "number" ? passive.redirectCount : "N/A"}
              </strong>
            </div>
            <div className="signal">
              <span>Registrar</span>
              <strong>{passive.registrar ?? "Unknown"}</strong>
            </div>
          </div>
          <p className="status">{summarizePassiveChecks(result?.passiveChecks)}</p>
        </EvidenceCard>
      </aside>

      <div className="workspace-main">
        <div className="hero-card card">
          <div className="hero-copy">
            <p className="eyebrow">Threat summary</p>
            <h3>{result?.pageTitle ?? "Waiting for a page to analyze"}</h3>
            <p>
              {result?.reasoning ??
                "Run TinyPhisherman against a suspicious link to collect active browsing evidence, passive domain signals, and a final triage verdict."}
            </p>
          </div>
          <div className="hero-metrics">
            <MetricCard
              label="Manipulation score"
              note="Urgency, authority, and credential pressure"
              value={typeof result?.manipulationScore === "number" ? result.manipulationScore : "N/A"}
              unit={typeof result?.manipulationScore === "number" ? "/100" : undefined}
              tone={toneFromScore(result?.manipulationScore)}
            />
            <MetricCard
              label="Visual similarity"
              note="Used when clone evidence is available"
              value={typeof result?.visualSimilarity === "number" ? result.visualSimilarity : "Not run"}
              unit={typeof result?.visualSimilarity === "number" ? "%" : undefined}
              tone={toneFromSimilarity(result?.visualSimilarity)}
            />
            <MetricCard
              label="Categorization"
              note="LLM classification of the live site"
              value={result?.squatterCategory ?? "Unknown"}
              tone={toneFromSquatter(result?.squatterCategory)}
            />
          </div>
        </div>

        <div className="content-grid">
          <EvidenceCard title="TinyFish live browser">
            {previewUrl ? (
              <div className="preview-frame large-frame">
                <iframe
                  title="TinyFish live preview"
                  src={previewUrl}
                  sandbox="allow-scripts allow-same-origin"
                  referrerPolicy="no-referrer"
                />
              </div>
            ) : !useTinyfish ? (
              <p className="status">Live TinyFish preview is disabled for this run.</p>
            ) : previewLoading ? (
              <p className="status">TinyFish is launching a remote browser.</p>
            ) : (
              <p className="status">Start a scan to attach the TinyFish stream.</p>
            )}
            {previewError ? <p className="status error">{previewError}</p> : null}
          </EvidenceCard>

          <EvidenceCard title="Captured screenshot">
            <div className="shot-stage">
              {screenshotSrc ? (
                <img className="shot-image shot-image-large" src={screenshotSrc} alt="Scan screenshot" />
              ) : (
                <p className="status">No screenshot captured yet.</p>
              )}
            </div>
            {result?.finalUrl ? <p className="status">Final destination: {result.finalUrl}</p> : null}
          </EvidenceCard>
        </div>

        <div className="content-grid dense-grid">
          <EvidenceCard title="Red flags">
            <ul className="simple-list">
              {evidenceList.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </EvidenceCard>

          <EvidenceCard title="Brand and credential signals">
            <div className="detail-list">
              <div className="detail-item">
                <span>Impersonated brand</span>
                <strong>{result?.impersonatedBrand ?? "Unknown"}</strong>
              </div>
              <div className="detail-item">
                <span>Credential intent</span>
                <strong>{result?.credentialIntent ? "Yes" : "Not confirmed"}</strong>
              </div>
              <div className="detail-item">
                <span>External links</span>
                <strong>{result?.externalLinks?.length ?? 0}</strong>
              </div>
            </div>
          </EvidenceCard>
        </div>

        <EvidenceCard title="Passive infrastructure details">
          <div className="detail-grid">
            <div className="detail-item">
              <span>Registrar</span>
              <strong>{passive.registrar ?? "Unknown"}</strong>
            </div>
            <div className="detail-item">
              <span>Domain age</span>
              <strong>
                {typeof passive.domainAgeDays === "number"
                  ? `${passive.domainAgeDays} days`
                  : "Unknown"}
              </strong>
            </div>
            <div className="detail-item">
              <span>TLS issuer</span>
              <strong>{passive.tlsIssuer ?? "Unknown"}</strong>
            </div>
            <div className="detail-item">
              <span>Resolved IPs</span>
              <strong>{passive.ipAddresses?.join(", ") || "Unknown"}</strong>
            </div>
          </div>
        </EvidenceCard>
      </div>
    </div>
  );
}

function GeneratePanel({
  domain,
  setDomain,
  onHunt,
  loading,
  error,
  result,
}: {
  domain: string;
  setDomain: (value: string) => void;
  onHunt: () => void;
  loading: boolean;
  error: string | null;
  result: HuntResult | null;
}) {
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewTarget, setPreviewTarget] = useState<string | null>(null);
  const [enablePreview, setEnablePreview] = useState(true);

  const variants = result?.variants ?? [];
  const total = variants.length;
  const liveCount = variants.filter((item) => item.liveStatus === "live").length;
  const criticalCount = variants.filter(
    (item) => item.threatLevel?.toLowerCase() === "critical"
  ).length;
  const topVariant = variants[0];
  const topVariantTone = toneFromThreat(topVariant?.threatLevel);
  const originalShot =
    result?.originalScreenshot && result.originalScreenshot.length > 0
      ? `data:image/png;base64,${result.originalScreenshot}`
      : null;

  const startPreview = async (target: string) => {
    setPreviewTarget(target);
    setPreviewUrl(null);
    setPreviewError(null);
    setPreviewLoading(true);

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
  };

  useEffect(() => {
    if (!enablePreview || !topVariant?.domain) {
      setPreviewUrl(null);
      setPreviewError(null);
      setPreviewLoading(false);
      setPreviewTarget(null);
      return;
    }

    let cancelled = false;

    const run = async () => {
      setPreviewTarget(topVariant.domain ?? null);
      setPreviewUrl(null);
      setPreviewError(null);
      setPreviewLoading(true);

      try {
        const res = await fetch(`/api/scan/preview?url=${encodeURIComponent(topVariant.domain ?? "")}`);
        const json = (await res.json()) as
          | { ok: true; data: { streamingUrl: string } }
          | { ok: false; error: string };

        if (!res.ok || !json.ok) {
          throw new Error("error" in json ? json.error : "Preview failed.");
        }

        if (!cancelled) {
          setPreviewUrl(json.data.streamingUrl);
        }
      } catch (err) {
        if (!cancelled) {
          setPreviewError(err instanceof Error ? err.message : "Preview failed.");
        }
      } finally {
        if (!cancelled) {
          setPreviewLoading(false);
        }
      }
    };

    void run();

    return () => {
      cancelled = true;
    };
  }, [enablePreview, topVariant?.domain]);

  const activityItems = useMemo<ActivityItem[]>(() => {
    const items: ActivityItem[] = [
      {
        label: "Candidate generation",
        detail: loading
          ? "Enumerating typos, homographs, and TLD lookalikes."
          : result
            ? `Discovery completed via ${result.discoveryMethod ?? "fallback logic"}.`
            : "Waiting for a protected domain.",
        status: loading ? "active" : result ? "done" : "pending",
      },
      {
        label: "Passive triage",
        detail: loading
          ? "Ranking live domains by DNS, age, and TLS signals."
          : result
            ? `${liveCount} live variants remained after triage.`
            : "No shortlist yet.",
        status: loading ? "active" : result ? "done" : "pending",
      },
      {
        label: "TinyFish verification",
        detail: previewError
          ? previewError
          : previewLoading
            ? `Streaming preview for ${previewTarget ?? "shortlisted domain"}.`
            : topVariant?.domain
              ? `Most suspicious variant: ${topVariant.domain}.`
              : "Shortlisted variants will be verified here.",
        status: previewError
          ? "error"
          : previewLoading
            ? "active"
            : topVariant?.domain
              ? "done"
              : loading
                ? "active"
                : "pending",
      },
    ];

    return items;
  }, [liveCount, loading, previewError, previewLoading, previewTarget, result, topVariant?.domain]);

  const progress = useMemo(() => {
    if (error) return 100;
    if (result) return 100;
    if (previewLoading) return 85;
    if (loading) return 55;
    return 8;
  }, [error, loading, previewLoading, result]);

  return (
    <div className="workspace">
      <aside className="workspace-rail">
        <div className="card control-card">
          <div className="section-head">
            <div>
              <p className="eyebrow">Proactive hunt</p>
              <h3>Reverse engineer phishing variants</h3>
            </div>
            <span className="pill">Auto chain</span>
          </div>
          <label className="field" htmlFor="legit-url">
            Legitimate domain
          </label>
          <input
            id="legit-url"
            type="text"
            placeholder="https://dbs.com.sg"
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
          />
          <div className="options">
            <label>
              <input type="checkbox" checked readOnly />
              `dnstwist` candidate generation
            </label>
            <label>
              <input type="checkbox" checked readOnly />
              TinyFish verification on shortlisted live variants
            </label>
          </div>
          <button className="btn" type="button" onClick={onHunt} disabled={loading}>
            {loading ? "Running hunt..." : "Hunt lookalikes"}
          </button>
          {error ? <p className="status error">{error}</p> : null}
          <div className="inline-stat-grid">
            <div className="inline-stat">
              <span>Variants found</span>
              <strong>{total}</strong>
            </div>
            <div className="inline-stat">
              <span>Critical</span>
              <strong>{criticalCount}</strong>
            </div>
          </div>
          <label className="preview-toggle">
            <input
              type="checkbox"
              checked={enablePreview}
              onChange={(event) => setEnablePreview(event.target.checked)}
            />
            Auto preview top live variant
          </label>
        </div>

        <ActivityFeed
          title="Hunt pipeline"
          progress={progress}
          items={activityItems}
          activeTarget={previewTarget ?? domain}
        />

        <EvidenceCard title="Ranked hunt summary">
          <div className="signal-grid compact-grid">
            <div className="signal">
              <span>Discovery</span>
              <strong>{result?.discoveryMethod ?? "Pending"}</strong>
            </div>
            <div className="signal">
              <span>Live</span>
              <strong>{liveCount}</strong>
            </div>
            <div className="signal">
              <span>Critical</span>
              <strong>{criticalCount}</strong>
            </div>
            <div className="signal">
              <span>Last run</span>
              <strong>{formatDate(result?.huntedAt)}</strong>
            </div>
          </div>
        </EvidenceCard>
      </aside>

      <div className="workspace-main">
        <div className="hero-card card">
          <div className="hero-copy">
            <p className="eyebrow">Top candidate</p>
            <h3>{topVariant?.domain ?? "No suspicious variant shortlisted yet"}</h3>
            <p>
              {topVariant?.reasoning ??
                "Run a hunt to generate lookalike domains, screen them with passive checks, and verify the most suspicious live variants with TinyFish."}
            </p>
          </div>
          <div className="hero-metrics">
            <MetricCard
              label="Threat"
              note="Final triage level for the top variant"
              value={topVariant?.threatLevel ?? "Pending"}
              tone={topVariantTone}
            />
            <MetricCard
              label="Visual similarity"
              note="Clone confidence against the protected brand"
              value={
                typeof topVariant?.visualSimilarity === "number"
                  ? topVariant.visualSimilarity
                  : "N/A"
              }
              unit={typeof topVariant?.visualSimilarity === "number" ? "%" : undefined}
              tone={toneFromSimilarity(topVariant?.visualSimilarity)}
            />
            <MetricCard
              label="Category"
              note="LLM classification for the verified site"
              value={topVariant?.squatterCategory ?? "Unknown"}
              tone={toneFromSquatter(topVariant?.squatterCategory)}
            />
          </div>
        </div>

        <div className="content-grid">
          <EvidenceCard title="TinyFish live preview">
            {previewUrl ? (
              <div className="preview-frame large-frame">
                <iframe
                  title="TinyFish hunt preview"
                  src={previewUrl}
                  sandbox="allow-scripts allow-same-origin"
                  referrerPolicy="no-referrer"
                />
              </div>
            ) : !enablePreview ? (
              <p className="status">Preview is disabled.</p>
            ) : previewLoading ? (
              <p className="status">TinyFish is attaching a remote browser to the top candidate.</p>
            ) : (
              <p className="status">Run a hunt to stream the most suspicious candidate.</p>
            )}
            {previewTarget ? <p className="status">Previewing: {previewTarget}</p> : null}
            {previewError ? <p className="status error">{previewError}</p> : null}
          </EvidenceCard>

          <EvidenceCard title="Protected brand snapshot">
            <div className="shot-stage">
              {originalShot ? (
                <img
                  className="shot-image shot-image-large"
                  src={originalShot}
                  alt="Original brand screenshot"
                />
              ) : (
                <p className="status">No baseline brand snapshot captured yet.</p>
              )}
            </div>
            <p className="status">
              Protected domain: {(result?.originalDomain ?? domain) || "Pending"}
            </p>
          </EvidenceCard>
        </div>

        <EvidenceCard title="Ranked suspicious variants">
          {variants.length ? (
            <div className="table variant-table">
              <div className="table-head">
                <span>Domain</span>
                <span>Threat</span>
                <span>Similarity</span>
                <span>Category</span>
                <span>Status</span>
                <span>Preview</span>
              </div>
              {variants.map((item, index) => (
                <div key={item.domain ?? `variant-${index}`} className="table-row">
                  <span className="mono">{item.domain ?? "Unknown"}</span>
                  <span className={`tone-${toneFromThreat(item.threatLevel)}`}>
                    {item.threatLevel ?? "—"}
                  </span>
                  <span>
                    {typeof item.visualSimilarity === "number"
                      ? `${item.visualSimilarity}%`
                      : "—"}
                  </span>
                  <span>{item.squatterCategory ?? "Unknown"}</span>
                  <span>{item.liveStatus ?? "Unknown"}</span>
                  <span>
                    <button
                      className="btn btn-ghost"
                      type="button"
                      disabled={!item.domain || !enablePreview || previewLoading}
                      onClick={() => item.domain && startPreview(item.domain)}
                    >
                      Stream
                    </button>
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="status">No variants yet. Run a hunt to populate the shortlist.</p>
          )}
        </EvidenceCard>
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
  const [huntDomain, setHuntDomain] = useState("");
  const [huntResult, setHuntResult] = useState<HuntResult | null>(null);
  const [huntError, setHuntError] = useState<string | null>(null);
  const [huntLoading, setHuntLoading] = useState(false);

  const introCopy = useMemo(() => {
    if (activeCase === "scan") {
      return "A horizontal analyst console for URL verification, with live TinyFish streaming, active evidence capture, and immediate triage.";
    }
    return "An automatic chained hunt that generates typosquats, filters them, and sends the most suspicious live variants to TinyFish.";
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
    setScanResult(null);

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

  const handleHunt = async () => {
    const target = huntDomain.trim();
    if (!target) {
      setHuntError("Please enter a domain to protect.");
      return;
    }

    setHuntLoading(true);
    setHuntError(null);
    setHuntResult(null);

    try {
      const res = await fetch("/api/hunt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: target }),
      });
      const json = (await res.json()) as HuntApiResponse;

      if (!res.ok || !json.ok) {
        throw new Error("error" in json ? json.error : "Hunt failed.");
      }

      setHuntResult(json.data);
    } catch (err) {
      setHuntError(err instanceof Error ? err.message : "Hunt failed.");
    } finally {
      setHuntLoading(false);
    }
  };

  return (
    <div className="page">
      <header className="site-header">
        <div className="brand">
          <img className="brand-mark" src="/favicon.png" alt="TinyPhisherman icon" />
          <div>
            <h1>TinyPhisherman</h1>
            <p className="tagline">Proactive phishing verification with TinyFish</p>
          </div>
        </div>
        <div className="header-strip">
          <span className="pill">Horizontal triage</span>
          <span className="pill">Active TinyFish stream</span>
          <span className="pill">Evidence first</span>
        </div>
      </header>

      <main>
        <section className="intro">
          <h2>Operate like an analyst, not a static checker.</h2>
          <p>{introCopy}</p>
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
            Hunt phishing infrastructure
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
            <GeneratePanel
              domain={huntDomain}
              setDomain={setHuntDomain}
              onHunt={handleHunt}
              loading={huntLoading}
              error={huntError}
              result={huntResult}
            />
          )}
        </section>

        <section className="footer-note">
          <p>
            TinyPhisherman is a hackathon prototype. Use the active evidence as triage input, not
            an automatic takedown decision.
          </p>
        </section>
      </main>
    </div>
  );
}
