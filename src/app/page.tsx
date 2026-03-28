"use client";

import { useMemo, useState } from "react";

const scanEvidence = [
  "Form action posts to off-domain",
  "Domain registered 9 days ago",
  "Hidden iframe on submit",
  "Brand assets hotlinked",
  "TLS hostname mismatch"
];

const passiveSignals = [
  { label: "WHOIS", value: "9 days" },
  { label: "DNSSEC", value: "Off" },
  { label: "MX", value: "None" },
  { label: "Blocklists", value: "2 hits" }
];

const generateResults = [
  { domain: "tinyfish-login-secure.com", risk: "High" },
  { domain: "tinyfish-verify.io", risk: "High" },
  { domain: "support-tinyf1sh.com", risk: "Medium" },
  { domain: "tinyfish-account-check.net", risk: "Medium" },
  { domain: "login-tinyfishhelp.com", risk: "Medium" }
];

const threatLevel = { label: "Critical", tone: "critical" };

const threatMetrics = [
  {
    label: "LLM Manipulation Score",
    value: 82,
    unit: "/100",
    tone: "high",
    note: ">75 is highly suspicious"
  },
  {
    label: "Visual Similarity",
    value: 86,
    unit: "%",
    tone: "critical",
    note: ">80% is Critical in Feature B"
  },
  {
    label: "Squatter Categorization",
    value: "Credential Harvester",
    tone: "critical",
    note: "Critical threat class"
  }
];

function ThreatBadge({ label, tone }: { label: string; tone: string }) {
  return <span className={`threat-badge tone-${tone}`}>{label}</span>;
}

function ScanPanel() {
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
        />
        <div className="options">
          <label>
            <input type="checkbox" defaultChecked />
            Run TinyFish active exploration
          </label>
          <label>
            <input type="checkbox" defaultChecked />
            Run passive DNS + WHOIS checks
          </label>
        </div>
        <button className="btn" type="button">
          Verify link
        </button>
        <p className="help">
          Runs in a sandbox with fake credentials. No user data is exposed.
        </p>
      </div>

      <div className="card">
        <div className="result-head">
          <div>
            <p className="eyebrow">Threat level</p>
            <h3>{threatLevel.label} threat</h3>
          </div>
          <ThreatBadge label={threatLevel.label} tone={threatLevel.tone} />
        </div>
        <div className="result-block">
          <h4>Threat metrics</h4>
          <div className="metric-grid">
            {threatMetrics.map((metric) => (
              <div key={metric.label} className="metric">
                <div>
                  <p className="metric-label">{metric.label}</p>
                  <p className="metric-note">{metric.note}</p>
                </div>
                <div className={`metric-value tone-${metric.tone}`}>
                  {metric.value}
                  {metric.unit ? (
                    <span className="metric-unit">{metric.unit}</span>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="result-block">
          <h4>Evidence</h4>
          <ul className="simple-list">
            {scanEvidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
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
          <h4>Screenshots</h4>
          <div className="shot-row">
            <span>Landing page</span>
            <span>Login form</span>
            <span>Redirect chain</span>
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

  const introCopy = useMemo(() => {
    if (activeCase === "scan") {
      return "Paste a suspicious link and get a clear threat level with evidence.";
    }

    return "Generate lookalike domains and validate which ones are live.";
  }, [activeCase]);

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

        <section>{activeCase === "scan" ? <ScanPanel /> : <GeneratePanel />}</section>

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
