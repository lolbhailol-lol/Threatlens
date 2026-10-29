import { useEffect, useState } from "react";
import { api } from "./lib.js";

// ✓ = yes, ~ = partial, ✗ = no
const COMPARISON = {
  columns: ["ThreatLens", "Single-source free tools", "Community intel platforms", "Enterprise TI platforms"],
  examples: ["", "VirusTotal, AbuseIPDB, Shodan (each on its own)", "e.g. AlienVault OTX", "e.g. Recorded Future, ThreatConnect"],
  rows: [
    ["Reputation + abuse + exposure + WHOIS + geo in one view", "✓", "✗", "~", "✓"],
    ["One risk score that explains every point", "✓", "✗", "✗", "~"],
    ["Flags brand-new phishing domains with no reputation history", "✓", "✗", "✗", "~"],
    ["MITRE ATT&CK mapping of the evidence", "✓", "✗", "~", "✓"],
    ["Generates firewall / IDS / SIEM / YARA rules", "✓", "✗", "~", "~"],
    ["Extracts defanged IOCs from emails and reports", "✓", "✗", "~", "✓"],
    ["Self-hosted: scan history never leaves your machine", "✓", "✗", "✗", "✗"],
    ["Cost", "Free, open source", "Free tiers, rate-limited", "Free", "Enterprise licence"],
  ],
};

const PILLARS = [
  {
    title: "Explains, not just scores",
    text: "Every point in the risk score is traced to a source and a reason, so an analyst can defend a block decision to their manager.",
  },
  {
    title: "Catches zero-day phishing",
    text: "An offline look-alike engine spots paypa1.com, rnicrosoft.com, punycode clones and DGA names, even before any feed has seen them.",
  },
  {
    title: "From intel to action in one click",
    text: "Each verdict comes with MITRE ATT&CK techniques, a response playbook and deployable Suricata, Sigma, YARA, Splunk, KQL and firewall rules.",
  },
  {
    title: "Free, private, self-hosted",
    text: "API keys and scan history stay on your own machine. Built for students, small SOCs and colleges that can't afford enterprise licences.",
  },
];

const MANUAL = [
  "Open VirusTotal, search, read 90 engine verdicts",
  "Open AbuseIPDB, check reports and categories",
  "Open Shodan for open ports and CVEs",
  "Run WHOIS to check domain age",
  "Look up geolocation and hosting provider",
  "Decide a verdict yourself",
  "Map it to MITRE ATT&CK by hand",
  "Write the firewall / SIEM rule from scratch",
  "Write up the incident report",
];

function Mark({ v }) {
  if (v === "✓") return <span className="mark mark-yes" aria-label="Yes">✓</span>;
  if (v === "✗") return <span className="mark mark-no" aria-label="No">✗</span>;
  if (v === "~") return <span className="mark mark-partial" aria-label="Partial">~</span>;
  return <span>{v}</span>;
}

export default function About({ onTry }) {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    api("/api/stats").then(setStats).catch(() => {});
  }, []);

  const threats = stats ? (stats.byLevel.Malicious || 0) + (stats.byLevel.Suspicious || 0) : 0;

  return (
    <div className="about">
      <section className="hero">
        <span className="eyebrow">The problem</span>
        <h2>Checking one suspicious IP shouldn't take nine browser tabs.</h2>
        <p>
          Threat intelligence is scattered across many tools. Each shows one slice and none of them tell you what to
          <em> do</em>. Enterprise platforms that join it all up are priced for large companies. ThreatLens brings that
          workflow to everyone: <strong>one search, five sources, one explainable verdict, ready-to-deploy defences.</strong>
        </p>
      </section>

      <div className="workflow">
        <section className="panel">
          <header className="panel-head">
            <h3>Without ThreatLens</h3>
            <span className="panel-source">{MANUAL.length} manual steps</span>
          </header>
          <ol className="manual-steps">
            {MANUAL.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
        </section>
        <section className="panel panel-highlight">
          <header className="panel-head">
            <h3>With ThreatLens</h3>
            <span className="panel-source">1 step</span>
          </header>
          <p className="one-step">Paste the indicator. Get everything above in one report.</p>
          {stats?.avgDurationMs && (
            <p className="proof">
              Measured on this machine: <strong>{(stats.avgDurationMs / 1000).toFixed(1)} s</strong> average per full analysis
              across {stats.totalScans} scans.
            </p>
          )}
          <button className="btn" onClick={() => onTry("hxxps://secure-login-paypa1[.]com/verify")}>
            Try it: a phishing URL VirusTotal has never seen
          </button>
        </section>
      </div>

      <div className="pillars">
        {PILLARS.map((p, i) => (
          <section key={p.title} className="pillar">
            <span className="pillar-num">0{i + 1}</span>
            <h3>{p.title}</h3>
            <p>{p.text}</p>
          </section>
        ))}
      </div>

      <section className="panel">
        <header className="panel-head">
          <h3>How ThreatLens compares</h3>
          <span className="panel-source">✓ yes · ~ partial · ✗ no</span>
        </header>
        <div className="table-scroll compare-scroll">
          <table className="compare">
            <thead>
              <tr>
                <th>Capability</th>
                {COMPARISON.columns.map((c, i) => (
                  <th key={c} className={i === 0 ? "us" : ""}>
                    {c}
                    {COMPARISON.examples[i] && <span>{COMPARISON.examples[i]}</span>}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {COMPARISON.rows.map(([cap, ...vals]) => (
                <tr key={cap}>
                  <td>{cap}</td>
                  {vals.map((v, i) => (
                    <td key={i} className={i === 0 ? "us" : ""}>
                      <Mark v={v} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="method">
          Based on the publicly available free tiers of each category. Enterprise products vary by plan. ThreatLens builds on
          VirusTotal, AbuseIPDB and Shodan data rather than replacing them: the value is in combining, explaining and acting on it.
        </p>
      </section>

      {stats && stats.totalScans > 0 && (
        <div className="stat-row">
          <div className="stat-tile"><span>Indicators analysed</span><strong>{stats.uniqueIndicators}</strong></div>
          <div className="stat-tile"><span>Threats identified</span><strong style={{ color: "#F0506E" }}>{threats}</strong></div>
          <div className="stat-tile"><span>Intelligence sources</span><strong>5 + 1 offline</strong></div>
          <div className="stat-tile"><span>Rule formats generated</span><strong>8</strong></div>
        </div>
      )}

      <section className="panel">
        <header className="panel-head">
          <h3>Built with</h3>
        </header>
        <div className="chips">
          {["Python", "FastAPI", "asyncio", "httpx", "SQLite", "React 18", "Vite", "Recharts", "VirusTotal API v3", "AbuseIPDB API v2",
            "Shodan InternetDB", "RDAP", "ip-api", "MITRE ATT&CK"].map((t) => (
            <span key={t} className="chip">{t}</span>
          ))}
        </div>
      </section>
    </div>
  );
}
