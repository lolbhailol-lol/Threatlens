import { useEffect, useState } from "react";
import { TYPE_NAME, detectType, api } from "./lib.js";
import { StatusDot, Note, Spinner } from "./components.jsx";
import Report from "./Report.jsx";
import Bulk from "./Bulk.jsx";
import Dashboard from "./Dashboard.jsx";
import About from "./About.jsx";

const EXAMPLES = [
  { label: "8.8.8.8 (Google DNS)", value: "8.8.8.8" },
  { label: "google.com", value: "google.com" },
  { label: "EICAR test virus hash", value: "44d88612fea8a8f36de82e1278abb02f" },
  { label: "Tor exit node", value: "185.220.101.1" },
  { label: "Zero-day phishing URL", value: "hxxps://secure-login-paypa1[.]com/verify" },
];

const TABS = [
  { id: "investigate", label: "Investigate" },
  { id: "bulk", label: "Bulk scan & IOC extractor" },
  { id: "dashboard", label: "Dashboard & history" },
  { id: "about", label: "Why ThreatLens" },
];

const SOURCES = [
  { name: "VirusTotal", what: "70+ antivirus engines and URL scanners" },
  { name: "AbuseIPDB", what: "Crowd-sourced reports of attacking IPs" },
  { name: "Shodan InternetDB", what: "Open ports and known CVEs" },
  { name: "RDAP / WHOIS", what: "Domain age and registrar" },
  { name: "ip-api", what: "Geolocation, hosting and proxy detection" },
  { name: "Offline engine", what: "Look-alike domains, DGA, MITRE ATT&CK" },
];

export default function App() {
  const [tab, setTab] = useState("investigate");
  const [query, setQuery] = useState("");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState(null);
  const [scans, setScans] = useState(0); // bumps the dashboard to reload after new scans

  useEffect(() => {
    api("/api/health")
      .then(setHealth)
      .catch(() => setHealth({ ok: false }));
  }, []);

  async function lookup(value, refresh = false) {
    const q = (value ?? query).trim();
    if (!q) return;
    setQuery(q);
    setTab("investigate");
    if (!detectType(q)) {
      setError("Enter a valid IP address, domain, URL or file hash (MD5, SHA-1 or SHA-256).");
      return;
    }
    setLoading(true);
    setError("");
    try {
      setData(await api(`/api/lookup?q=${encodeURIComponent(q)}${refresh ? "&refresh=1" : ""}`));
      setScans((n) => n + 1);
    } catch (err) {
      setError(err.message);
      setData(null);
    } finally {
      setLoading(false);
    }
  }

  function openReport(report) {
    setData(report);
    setQuery(report.query);
    setError("");
    setTab("investigate");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function openReportId(id) {
    try {
      openReport(await api(`/api/report/${id}`));
    } catch (err) {
      setError(err.message);
      setTab("investigate");
    }
  }

  const typed = detectType(query);

  return (
    <div className="app">
      <header className="topbar no-print">
        <div className="brand">
          <span className="logo" aria-hidden="true">◎</span>
          <div>
            <h1>ThreatLens</h1>
            <p>Cyber threat intelligence platform</p>
          </div>
        </div>
        <div className="status">
          <StatusDot label="Server" on={health?.ok} />
          <StatusDot label="VirusTotal" on={health?.virustotal} />
          <StatusDot label="AbuseIPDB" on={health?.abuseipdb} />
          <StatusDot label="Shodan · RDAP · Geo" on={health?.ok} />
        </div>
      </header>

      <nav className="tabs no-print" role="tablist">
        {TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={tab === t.id} className={`tab ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </nav>

      <main>
        {tab === "investigate" && (
          <>
            <form
              className="search no-print"
              onSubmit={(e) => {
                e.preventDefault();
                lookup();
              }}
            >
              <div className="search-box">
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="IP address, domain, URL or file hash (defanged is fine)"
                  aria-label="Indicator to investigate"
                  spellCheck="false"
                  autoFocus
                />
                {query && <span className="type-hint">{typed ? TYPE_NAME[typed] : "Unrecognised"}</span>}
              </div>
              <button className="btn" type="submit" disabled={loading}>
                {loading ? "Scanning…" : "Investigate"}
              </button>
            </form>

            <div className="examples no-print">
              <span>Try:</span>
              {EXAMPLES.map((ex) => (
                <button key={ex.value} className="example" onClick={() => lookup(ex.value)} disabled={loading}>
                  {ex.label}
                </button>
              ))}
            </div>

            {error && <Note tone="bad">{error}</Note>}
            {loading && <Spinner>Querying 5 intelligence sources in parallel…</Spinner>}
            {!loading && data && <Report data={data} onRefresh={() => lookup(data.query, true)} />}
            {!loading && !data && !error && (
              <div className="empty">
                <h2>Investigate an indicator</h2>
                <p>
                  ThreatLens checks an IP, domain, URL or file hash against five intelligence sources plus an offline phishing
                  engine, then gives one explainable risk score, MITRE ATT&amp;CK mapping, a response playbook and ready-to-deploy
                  detection rules.
                </p>
                <ul className="source-list">
                  {SOURCES.map((s) => (
                    <li key={s.name}>
                      <b>{s.name}</b>
                      <span>{s.what}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}

        {/* Bulk stays mounted so a running batch keeps going while you look at a report */}
        <div hidden={tab !== "bulk"}>
          <Bulk onOpen={openReport} />
        </div>

        {tab === "dashboard" && <Dashboard onOpenId={openReportId} refreshKey={scans} />}
        {tab === "about" && <About onTry={(q) => lookup(q)} />}
      </main>

      <footer className="footer no-print">
        Data from VirusTotal, AbuseIPDB, Shodan InternetDB, RDAP and ip-api.com. Results are cached for 1 hour to save API quota.
      </footer>
    </div>
  );
}
