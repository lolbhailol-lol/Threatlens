import { useState } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { C, LEVEL_COLOR, TYPE_NAME, scoreColor, defang, downloadFile, timeAgo } from "./lib.js";
import { RiskGauge, Panel, Rows, Note, LevelBadge } from "./components.jsx";
import { buildRules } from "./rules.js";

const TONE_COLOR = { bad: C.malicious, warn: C.suspicious, good: C.clean };
const TONE_ICON = { bad: "▲", warn: "●", good: "✓" };

/* ---------- Result panels ---------- */

function VirusTotalPanel({ vt }) {
  if (!vt) return null;
  if (vt.error) return <Panel title="Antivirus engines" source="VirusTotal"><Note tone="bad">{vt.error}</Note></Panel>;
  if (vt.notFound)
    return (
      <Panel title="Antivirus engines" source="VirusTotal">
        <Note>VirusTotal has no record of this indicator yet.</Note>
      </Panel>
    );

  const s = vt.stats;
  const data = [
    { name: "Malicious", value: s.malicious || 0, color: C.malicious },
    { name: "Suspicious", value: s.suspicious || 0, color: C.suspicious },
    { name: "Harmless", value: s.harmless || 0, color: C.clean },
    { name: "Undetected", value: s.undetected || 0, color: C.muted },
  ];
  const total = data.reduce((a, d) => a + d.value, 0);
  const flagged = (s.malicious || 0) + (s.suspicious || 0);

  return (
    <Panel title="Antivirus engines" source="VirusTotal">
      <div className="donut-wrap">
        <div className="donut">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={data.filter((d) => d.value > 0)} dataKey="value" innerRadius="68%" outerRadius="100%" stroke="#111C2F" strokeWidth={2} isAnimationActive={false}>
                {data.filter((d) => d.value > 0).map((d) => (
                  <Cell key={d.name} fill={d.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "#16233A", border: "1px solid #2B3D5C", borderRadius: 8, color: "#E6EDF7" }} itemStyle={{ color: "#E6EDF7" }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="donut-center">
            <strong style={{ color: flagged ? C.malicious : C.clean }}>{flagged}</strong>
            <span>of {total} flag it</span>
          </div>
        </div>
        <ul className="legend">
          {data.map((d) => (
            <li key={d.name}>
              <span className="swatch" style={{ background: d.color }} />
              {d.name}
              <b>{d.value}</b>
            </li>
          ))}
        </ul>
      </div>
      <Rows
        items={[
          { label: "Malware family", value: vt.threatLabel },
          { label: "Community reputation", value: vt.reputation },
        ]}
      />
      {vt.link && (
        <a className="ext-link" href={vt.link} target="_blank" rel="noreferrer">
          Open full report on VirusTotal ↗
        </a>
      )}
    </Panel>
  );
}

function AbusePanel({ abuse }) {
  if (!abuse) return null;
  if (abuse.error) return <Panel title="Abuse reports" source="AbuseIPDB"><Note tone="bad">{abuse.error}</Note></Panel>;
  const color = scoreColor(abuse.score);
  return (
    <Panel title="Abuse reports" source="AbuseIPDB">
      <div className="meter">
        <div className="meter-top">
          <span>Abuse confidence</span>
          <strong style={{ color }}>{abuse.score}%</strong>
        </div>
        <div className="meter-track">
          <div className="meter-fill" style={{ width: `${abuse.score}%`, background: color }} />
        </div>
      </div>
      <Rows
        items={[
          { label: "Reports (90 days)", value: abuse.totalReports },
          { label: "Unique reporters", value: abuse.distinctUsers },
          { label: "ISP", value: abuse.isp },
          { label: "Usage type", value: abuse.usageType },
          { label: "Tor exit node", value: abuse.isTor ? "Yes" : "No" },
          { label: "Last reported", value: abuse.lastReportedAt ? new Date(abuse.lastReportedAt).toLocaleString() : "Never" },
        ]}
      />
      {abuse.categories?.length > 0 && (
        <div className="kv-block cat-block">
          <span className="kv-label">Reported attack types</span>
          <ul className="cat-bars">
            {abuse.categories.slice(0, 6).map((c) => (
              <li key={c.name}>
                <span className="cat-name">{c.name}</span>
                <span className="cat-track">
                  <span style={{ width: `${(c.count / abuse.categories[0].count) * 100}%` }} />
                </span>
                <b>{c.count}</b>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  );
}

function ShodanPanel({ shodan }) {
  if (!shodan) return null;
  if (shodan.error) return <Panel title="Attack surface" source="Shodan"><Note tone="bad">{shodan.error}</Note></Panel>;
  if (shodan.notFound)
    return (
      <Panel title="Attack surface" source="Shodan">
        <Note>Shodan has not seen any open services on this host.</Note>
      </Panel>
    );
  return (
    <Panel title="Attack surface" source="Shodan">
      <div className="kv-block">
        <span className="kv-label">Open ports ({shodan.ports.length})</span>
        <div className="chips">
          {shodan.ports.length ? shodan.ports.map((p) => <span key={p} className="chip mono">{p}</span>) : <span className="muted">None seen</span>}
        </div>
      </div>
      <div className="kv-block">
        <span className="kv-label">Known vulnerabilities ({shodan.vulns.length})</span>
        <div className="chips">
          {shodan.vulns.length ? (
            shodan.vulns.slice(0, 18).map((v) => (
              <a key={v} className="chip chip-bad mono" href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" rel="noreferrer">
                {v}
              </a>
            ))
          ) : (
            <span className="muted">None reported</span>
          )}
          {shodan.vulns.length > 18 && <span className="muted">+{shodan.vulns.length - 18} more</span>}
        </div>
      </div>
      <Rows
        items={[
          { label: "Hostnames", value: shodan.hostnames.slice(0, 3).join(", ") },
          { label: "Tags", value: shodan.tags.join(", ") },
          { label: "Software", value: shodan.cpes.slice(0, 3).map((c) => c.replace("cpe:/", "")).join(", "), mono: true },
        ]}
      />
    </Panel>
  );
}

function WhoisPanel({ whois }) {
  if (!whois) return null;
  if (whois.error || whois.notFound)
    return (
      <Panel title="Domain registration" source="RDAP / WHOIS">
        <Note>{whois.error || "No registration data available for this domain."}</Note>
      </Panel>
    );
  const date = (d) => (d ? new Date(d).toLocaleDateString() : null);
  const young = whois.ageDays !== null && whois.ageDays < 180;
  return (
    <Panel title="Domain registration" source="RDAP / WHOIS">
      {whois.ageDays !== null && (
        <div className="age">
          <strong style={{ color: whois.ageDays < 30 ? C.malicious : young ? C.suspicious : C.clean }}>
            {whois.ageDays >= 365 ? `${(whois.ageDays / 365).toFixed(1)} years` : `${whois.ageDays} days`}
          </strong>
          <span>domain age{young ? ", newly registered domains are a common phishing signal" : ""}</span>
        </div>
      )}
      <Rows
        items={[
          { label: "Domain", value: whois.domain, mono: true },
          { label: "Registrar", value: whois.registrar },
          { label: "Registered", value: date(whois.created) },
          { label: "Expires", value: date(whois.expires) },
          { label: "Name servers", value: whois.nameservers.join(", "), mono: true },
        ]}
      />
    </Panel>
  );
}

function GeoPanel({ geo, ip }) {
  if (!geo) return null;
  if (geo.error) return <Panel title="Location" source="ip-api"><Note>{geo.error}</Note></Panel>;
  const bbox = `${geo.lon - 2},${geo.lat - 1.5},${geo.lon + 2},${geo.lat + 1.5}`;
  return (
    <Panel title="Location" source="ip-api">
      <iframe
        className="map"
        title={`Map showing location of ${ip}`}
        loading="lazy"
        src={`https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${geo.lat},${geo.lon}`}
      />
      <Rows
        items={[
          { label: "City", value: [geo.city, geo.regionName].filter(Boolean).join(", ") },
          { label: "Country", value: geo.country },
          { label: "Organisation", value: geo.org || geo.isp },
          { label: "AS", value: geo.as },
          { label: "Hosting / datacenter", value: geo.hosting ? "Yes" : "No" },
          { label: "Proxy / VPN", value: geo.proxy ? "Yes" : "No" },
        ]}
      />
    </Panel>
  );
}

function DetailsPanel({ vt }) {
  if (!vt || !vt.details || vt.details.length === 0) return null;
  return (
    <Panel title="Indicator details" source="VirusTotal">
      <Rows items={vt.details.map((d) => ({ ...d, mono: d.label === "SHA-256" || d.label === "Final URL" }))} />
    </Panel>
  );
}

function DetectionsPanel({ vt }) {
  if (!vt || !vt.detections || vt.detections.length === 0) return null;
  return (
    <Panel title={`Engines that flagged it (${vt.detections.length})`} source="VirusTotal" wide className="print-break">
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Engine</th>
              <th>Verdict</th>
              <th>Detection name</th>
            </tr>
          </thead>
          <tbody>
            {vt.detections.slice(0, 60).map((d) => (
              <tr key={d.engine}>
                <td>{d.engine}</td>
                <td>
                  <span className="tag" style={{ color: d.category === "malicious" ? C.malicious : C.suspicious }}>
                    {d.category}
                  </span>
                </td>
                <td className="mono">{d.result}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function PhishingPanel({ phishing }) {
  if (!phishing) return null;
  return (
    <Panel title="Phishing & look-alike analysis" source="Offline engine">
      {phishing.findings.length ? (
        <>
          {phishing.lookalike && (
            <div className="lookalike">
              <span>Impersonating</span>
              <strong>{phishing.lookalike}</strong>
            </div>
          )}
          <ul className="factors">
            {phishing.findings.map((f) => (
              <li key={f.text}>
                <span className="factor-icon" style={{ color: TONE_COLOR[f.severity] }} aria-hidden="true">{TONE_ICON[f.severity]}</span>
                <span className="factor-text">{f.text}</span>
                <b className="factor-pts" style={{ color: TONE_COLOR[f.severity] }}>+{f.points}</b>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <Note>No brand impersonation, typosquatting, punycode, DGA or lure-word patterns found.</Note>
      )}
      <p className="method">
        Runs locally with no API call, so it catches brand-new phishing domains that no reputation feed has seen yet.
      </p>
    </Panel>
  );
}

function MitrePanel({ mitre }) {
  if (!mitre?.length) return null;
  return (
    <Panel title="MITRE ATT&CK mapping" source={`${mitre.length} techniques`}>
      <ul className="mitre">
        {mitre.map((t) => (
          <li key={t.id}>
            <a href={t.url} target="_blank" rel="noreferrer" className="mitre-id mono">{t.id}</a>
            <div>
              <strong>{t.name}</strong>
              <span className="mitre-tactic">{t.tactic}</span>
              <p>{t.reason}</p>
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function RulesPanel({ data }) {
  const rules = buildRules(data);
  const [active, setActive] = useState(0);
  const [copied, setCopied] = useState(false);
  if (!rules.length) return null;
  const rule = rules[Math.min(active, rules.length - 1)];

  function copy() {
    navigator.clipboard.writeText(rule.code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <Panel title="Detection & response rules" source="Ready to deploy" wide className="print-break">
      <div className="bulk-bar rule-bar">
        <div className="filters" role="tablist" aria-label="Rule format">
          {rules.map((r, i) => (
            <button key={r.tool} role="tab" aria-selected={i === active} className={`filter ${i === active ? "active" : ""}`} onClick={() => setActive(i)}>
              {r.tool}
            </button>
          ))}
        </div>
        <button className="btn-ghost push-right no-print" onClick={copy}>{copied ? "Copied ✓" : "Copy rule"}</button>
      </div>
      <pre className="code"><code>{rule.code}</code></pre>
      <p className="method">
        Generated from this report. Review before deploying, especially blocks on shared infrastructure such as CDNs or Tor.
      </p>
    </Panel>
  );
}

/* ---------- Explainability: why this score? ---------- */

function FactorsPanel({ risk }) {
  if (!risk.factors?.length) return null;
  return (
    <Panel title="Why this score?" source="Risk engine">
      <ul className="factors">
        {risk.factors.map((f, i) => (
          <li key={i}>
            <span className="factor-icon" style={{ color: TONE_COLOR[f.tone] }} aria-hidden="true">
              {TONE_ICON[f.tone]}
            </span>
            <span className="factor-text">
              <span className="factor-source">{f.source}</span>
              {f.text}
            </span>
            {f.points > 0 && (
              <b className="factor-pts" style={{ color: TONE_COLOR[f.tone] }}>
                {f.base ? `${f.points}/100` : `+${f.points}`}
              </b>
            )}
          </li>
        ))}
      </ul>
      <p className="method">
        Score = highest reputation score (VirusTotal or AbuseIPDB){risk.bonus ? ` + ${risk.bonus} context points` : ""}, capped at 100.
        ≥60 Malicious · ≥20 Suspicious · else Clean.
      </p>
    </Panel>
  );
}

function AnalystPanel({ risk }) {
  if (!risk.summary) return null;
  return (
    <Panel title="Analyst summary" source="Auto-generated">
      <p className="summary-text">{risk.summary}</p>
      <h4 className="sub-head">Recommended actions</h4>
      <ol className="actions">
        {risk.actions.map((a) => (
          <li key={a}>{a}</li>
        ))}
      </ol>
    </Panel>
  );
}

/* ---------- Report ---------- */

export default function Report({ data, onRefresh }) {
  const { risk } = data;
  const color = LEVEL_COLOR[risk.level];
  const [copied, setCopied] = useState(false);

  function copyDefanged() {
    navigator.clipboard.writeText(defang(data.query)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  function downloadJSON() {
    const name = `threatlens-report-${data.query.replace(/[^a-z0-9.]/gi, "_").slice(0, 40)}.json`;
    downloadFile(name, JSON.stringify(data, null, 2), "application/json");
  }

  return (
    <div className="results">
      <div className="print-only print-title">
        <h1>ThreatLens Threat Intelligence Report</h1>
        <p>Generated {new Date().toLocaleString()}</p>
      </div>

      <section className="summary panel panel-wide">
        <RiskGauge score={risk.score} level={risk.level} />
        <div className="summary-body">
          <div className="summary-meta">
            <span className="chip">{TYPE_NAME[data.type]}</span>
            {data.resolvedIP && data.resolvedIP !== data.query && <span className="chip mono">resolves to {data.resolvedIP}</span>}
            {data.durationMs && (
              <span className="chip chip-accent">⚡ {data.sourcesQueried} sources in {(data.durationMs / 1000).toFixed(1)} s</span>
            )}
            {data.cached && <span className="chip" title="Served from the local cache to save API quota">cached · {timeAgo(data.checkedAt)}</span>}
          </div>
          <h2 className="mono summary-query">{data.query}</h2>
          <p className="verdict">
            <LevelBadge level={risk.level} />
          </p>
          <div className="sub-scores">
            <span>VirusTotal: <b style={{ color: scoreColor(risk.vtScore) }}>{risk.vtScore ?? "n/a"}</b></span>
            <span>AbuseIPDB: <b style={{ color: scoreColor(risk.abuseScore) }}>{risk.abuseScore ?? "n/a"}</b></span>
            {risk.bonus > 0 && <span>Context: <b style={{ color }}>+{risk.bonus}</b></span>}
            <span>Checked {new Date(data.checkedAt).toLocaleString()}</span>
          </div>
        </div>
        <div className="summary-actions no-print">
          <button className="btn-ghost" onClick={() => window.print()}>Export PDF</button>
          <button className="btn-ghost" onClick={downloadJSON}>Download JSON</button>
          <button className="btn-ghost" onClick={copyDefanged} title="Copy as hxxp://evil[.]com so it can't be clicked by accident">
            {copied ? "Copied ✓" : "Copy defanged IOC"}
          </button>
          {data.cached && <button className="btn-ghost" onClick={onRefresh}>Re-scan live</button>}
        </div>
      </section>

      <div className="grid">
        <AnalystPanel risk={risk} />
        <FactorsPanel risk={risk} />
        <MitrePanel mitre={data.mitre} />
        <PhishingPanel phishing={data.phishing} />
        <VirusTotalPanel vt={data.virustotal} />
        <AbusePanel abuse={data.abuseipdb} />
        <ShodanPanel shodan={data.shodan} />
        <WhoisPanel whois={data.whois} />
        <GeoPanel geo={data.geo} ip={data.resolvedIP} />
        <DetailsPanel vt={data.virustotal} />
        <RulesPanel data={data} />
        <DetectionsPanel vt={data.virustotal} />
      </div>
    </div>
  );
}
