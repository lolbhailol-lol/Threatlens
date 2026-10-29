import { useRef, useState } from "react";
import { TYPE_NAME, api, downloadFile, toCSV, defang } from "./lib.js";
import { Note, LevelBadge } from "./components.jsx";

const SAMPLE = `URGENT: Your account has been suspended.
Verify now at hxxps://secure-login-paypa1[.]com/verify?id=8812 or your account will be closed.

Indicators from incident #4471:
- C2 server: 185.220.101.1
- Dropper hash: 44d88612fea8a8f36de82e1278abb02f
- Staging domain: example[.]com
- DNS resolver used: 8.8.8.8`;

const MAX_ITEMS = 25;
const VT_GAP_MS = 15500; // VirusTotal free plan: 4 lookups per minute

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export default function Bulk({ onOpen }) {
  const [text, setText] = useState("");
  const [items, setItems] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [results, setResults] = useState({});
  const [running, setRunning] = useState(false);
  const [waitUntil, setWaitUntil] = useState(null);
  const [error, setError] = useState("");
  const [, setTick] = useState(0);
  const stopRef = useRef(false);

  async function extract() {
    setError("");
    try {
      const { indicators } = await api("/api/extract", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      if (!indicators.length) setError("No IPs, domains, URLs or hashes found in that text.");
      setItems(indicators);
      setResults({});
      // Domains that only appear inside a URL are usually redundant, so leave them unticked
      setSelected(new Set(indicators.filter((i) => !i.insideUrl).slice(0, MAX_ITEMS).map((i) => i.value)));
    } catch (err) {
      setError(err.message);
    }
  }

  function toggle(value) {
    const next = new Set(selected);
    next.has(value) ? next.delete(value) : next.size < MAX_ITEMS && next.add(value);
    setSelected(next);
  }

  async function wait(ms) {
    setWaitUntil(Date.now() + ms);
    const end = Date.now() + ms;
    while (Date.now() < end && !stopRef.current) {
      await sleep(250);
      setTick((t) => t + 1); // re-render so the countdown updates
    }
    setWaitUntil(null);
  }

  async function scanAll() {
    stopRef.current = false;
    setRunning(true);
    const queue = items.filter((i) => selected.has(i.value));
    for (let n = 0; n < queue.length && !stopRef.current; n++) {
      const { value } = queue[n];
      setResults((r) => ({ ...r, [value]: { status: "scanning" } }));
      try {
        let data = await api(`/api/lookup?q=${encodeURIComponent(value)}`);
        if (data.virustotal?.rateLimited) {
          await wait(60000);
          data = await api(`/api/lookup?q=${encodeURIComponent(value)}`);
        }
        setResults((r) => ({ ...r, [value]: { status: "done", data } }));
        // Space out live lookups so the free VirusTotal quota isn't exceeded; cached ones are free
        if (!data.cached && n < queue.length - 1) await wait(VT_GAP_MS);
      } catch (err) {
        setResults((r) => ({ ...r, [value]: { status: "error", error: err.message } }));
      }
    }
    setRunning(false);
  }

  function exportCSV() {
    const rows = items.filter((i) => results[i.value]?.data).map((i) => results[i.value].data);
    const csv = toCSV(rows, [
      { label: "Indicator", get: (d) => d.query },
      { label: "Defanged", get: (d) => defang(d.query) },
      { label: "Type", get: (d) => d.type },
      { label: "Verdict", get: (d) => d.risk.level },
      { label: "Risk score", get: (d) => d.risk.score },
      { label: "VT malicious", get: (d) => d.virustotal?.stats?.malicious },
      { label: "Abuse score", get: (d) => d.abuseipdb?.score },
      { label: "Country", get: (d) => d.geo?.country },
      { label: "Summary", get: (d) => d.risk.summary },
      { label: "Checked at", get: (d) => d.checkedAt },
    ]);
    downloadFile(`threatlens-bulk-${new Date().toISOString().slice(0, 10)}.csv`, csv, "text/csv");
  }

  const done = Object.values(results).filter((r) => r.status === "done").length;
  const total = items.filter((i) => selected.has(i.value)).length;
  const secondsLeft = waitUntil ? Math.max(0, Math.ceil((waitUntil - Date.now()) / 1000)) : 0;

  return (
    <div className="bulk">
      <section className="panel">
        <header className="panel-head">
          <h3>IOC extractor</h3>
          <span className="panel-source">Paste a threat report, phishing email or log</span>
        </header>
        <textarea
          className="ioc-input mono"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste any text: indicators are pulled out automatically, including defanged ones like hxxp://evil[.]com"
          rows={8}
          spellCheck="false"
        />
        <div className="bulk-bar">
          <button className="btn" onClick={extract} disabled={!text.trim() || running}>Extract indicators</button>
          <button className="btn-ghost" onClick={() => setText(SAMPLE)} disabled={running}>Load sample phishing email</button>
        </div>
        {error && <Note tone="bad">{error}</Note>}
      </section>

      {items.length > 0 && (
        <section className="panel">
          <header className="panel-head">
            <h3>
              {items.length} indicators found · {selected.size} selected
            </h3>
            <span className="panel-source">max {MAX_ITEMS} per batch</span>
          </header>

          <div className="bulk-bar">
            {!running ? (
              <button className="btn" onClick={scanAll} disabled={!selected.size}>Scan selected</button>
            ) : (
              <button className="btn-ghost" onClick={() => (stopRef.current = true)}>Stop</button>
            )}
            {done > 0 && !running && <button className="btn-ghost" onClick={exportCSV}>Export CSV</button>}
            {(running || done > 0) && (
              <div className="progress">
                <div className="meter-track">
                  <div className="meter-fill" style={{ width: `${(done / Math.max(total, 1)) * 100}%`, background: "#5AA9FF" }} />
                </div>
                <span>
                  {done} / {total}
                  {waitUntil && ` · waiting ${secondsLeft}s for VirusTotal rate limit`}
                </span>
              </div>
            )}
          </div>

          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th></th>
                  <th>Indicator</th>
                  <th>Type</th>
                  <th>Verdict</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {items.map((i) => {
                  const r = results[i.value];
                  return (
                    <tr key={i.value} className={r?.data ? "clickable" : ""} onClick={() => r?.data && onOpen(r.data)}>
                      <td onClick={(e) => e.stopPropagation()}>
                        <input type="checkbox" checked={selected.has(i.value)} onChange={() => toggle(i.value)} disabled={running} aria-label={`Select ${i.value}`} />
                      </td>
                      <td className="mono cell-ioc">{i.value}</td>
                      <td>{TYPE_NAME[i.type]}</td>
                      <td>
                        {!r && <span className="muted">{selected.has(i.value) ? "queued" : "-"}</span>}
                        {r?.status === "scanning" && <span className="muted">scanning…</span>}
                        {r?.status === "error" && <span className="bad">error</span>}
                        {r?.data && <LevelBadge level={r.data.risk.level} score={r.data.risk.score} />}
                      </td>
                      <td className="muted cell-detail">
                        {r?.error}
                        {r?.data && (r.data.virustotal?.error || (r.data.virustotal?.stats ? `${r.data.virustotal.stats.malicious || 0} AV engines` : "")) }
                        {r?.data?.abuseipdb?.score ? ` · ${r.data.abuseipdb.score}% abuse` : ""}
                        {r?.data?.cached ? " · cached" : ""}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {done > 0 && <p className="hint">Click a scanned row to open its full report.</p>}
        </section>
      )}
    </div>
  );
}
