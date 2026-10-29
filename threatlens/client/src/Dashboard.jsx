import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import { C, LEVEL_COLOR, LEVEL_ICON, TYPE_NAME, api, timeAgo } from "./lib.js";
import { Panel, Note, LevelBadge, Spinner } from "./components.jsx";

const LEVELS = ["Malicious", "Suspicious", "Clean", "Unknown"];
const TOOLTIP_STYLE = { background: "#16233A", border: "1px solid #2B3D5C", borderRadius: 8, color: "#E6EDF7" };

function StatTile({ label, value, color }) {
  return (
    <div className="stat-tile">
      <span>{label}</span>
      <strong style={color ? { color } : undefined}>{value}</strong>
    </div>
  );
}

// One horizontal bar split by verdict, with a labelled legend so it never relies on color alone
function VerdictBar({ byLevel, total }) {
  if (!total) return <Note>No scans yet.</Note>;
  return (
    <>
      <div className="verdict-bar" role="img" aria-label={LEVELS.map((l) => `${l}: ${byLevel[l] || 0}`).join(", ")}>
        {LEVELS.filter((l) => byLevel[l]).map((l) => (
          <div key={l} title={`${l}: ${byLevel[l]}`} style={{ flexGrow: byLevel[l], background: LEVEL_COLOR[l] }} />
        ))}
      </div>
      <ul className="legend legend-row">
        {LEVELS.map((l) => (
          <li key={l}>
            <span className="swatch" style={{ background: LEVEL_COLOR[l] }} />
            {l}
            <b>{byLevel[l] || 0}</b>
            <span className="muted">{Math.round(((byLevel[l] || 0) / total) * 100)}%</span>
          </li>
        ))}
      </ul>
    </>
  );
}

export default function Dashboard({ onOpenId, refreshKey }) {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [filter, setFilter] = useState("All");
  const [error, setError] = useState("");

  function load() {
    Promise.all([api("/api/stats"), api("/api/history?limit=200")])
      .then(([s, h]) => {
        setStats(s);
        setHistory(h);
        setError("");
      })
      .catch((err) => setError(err.message));
  }

  useEffect(load, [refreshKey]);

  async function clearHistory() {
    if (!confirm("Delete all scan history and cached reports?")) return;
    await api("/api/history", { method: "DELETE" });
    load();
  }

  if (error) return <Note tone="bad">{error}</Note>;
  if (!stats) return <Spinner>Loading dashboard…</Spinner>;

  const byLevel = stats.byLevel || {};
  const shown = filter === "All" ? history : history.filter((h) => h.level === filter);
  const perDay = stats.perDay.map((d) => ({ ...d, label: new Date(d.date + "T00:00").toLocaleDateString(undefined, { month: "short", day: "numeric" }) }));

  return (
    <div className="dashboard">
      <div className="stat-row">
        <StatTile label="Total scans" value={stats.totalScans} />
        <StatTile label="Unique indicators" value={stats.uniqueIndicators} />
        <StatTile label="Malicious" value={byLevel.Malicious || 0} color={C.malicious} />
        <StatTile label="Suspicious" value={byLevel.Suspicious || 0} color={C.suspicious} />
        <StatTile label="Clean" value={byLevel.Clean || 0} color={C.clean} />
        <StatTile label="Avg analysis time" value={stats.avgDurationMs ? `${(stats.avgDurationMs / 1000).toFixed(1)} s` : "-"} />
      </div>

      <div className="grid">
        <Panel title="Verdicts" source="Unique indicators">
          <VerdictBar byLevel={byLevel} total={stats.uniqueIndicators} />
          <ul className="type-list">
            {Object.entries(TYPE_NAME).map(([k, name]) => (
              <li key={k}>
                {name}
                <b>{stats.byType[k] || 0}</b>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Scans per day" source="Last 14 days">
          <div className="chart">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={perDay} margin={{ top: 8, right: 4, left: -24, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke="#22314B" />
                <XAxis dataKey="label" tick={{ fill: "#8A9BB5", fontSize: 11 }} axisLine={false} tickLine={false} interval={1} />
                <YAxis allowDecimals={false} tick={{ fill: "#8A9BB5", fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} itemStyle={{ color: "#E6EDF7" }} cursor={{ fill: "rgba(90,169,255,0.08)" }} formatter={(v) => [v, "Scans"]} />
                <Bar dataKey="count" fill={C.info} radius={[4, 4, 0, 0]} maxBarSize={22} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Highest-risk indicators" source="Top 8">
          {stats.topThreats.length ? (
            <ol className="top-list">
              {stats.topThreats.map((t) => (
                <li key={t.query}>
                  <span className="mono cell-ioc">{t.query}</span>
                  <LevelBadge level={t.level} score={t.score} />
                </li>
              ))}
            </ol>
          ) : (
            <Note>No scored indicators yet.</Note>
          )}
        </Panel>
      </div>

      <Panel title="Scan history" source={`${shown.length} entries`} wide>
        <div className="bulk-bar">
          <div className="filters" role="group" aria-label="Filter by verdict">
            {["All", ...LEVELS].map((l) => (
              <button key={l} className={`filter ${filter === l ? "active" : ""}`} onClick={() => setFilter(l)}>
                {l !== "All" && <span aria-hidden="true" style={{ color: LEVEL_COLOR[l] }}>{LEVEL_ICON[l]} </span>}
                {l}
              </button>
            ))}
          </div>
          {history.length > 0 && <button className="btn-ghost push-right" onClick={clearHistory}>Clear history</button>}
        </div>
        {shown.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Indicator</th>
                  <th>Type</th>
                  <th>Verdict</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((h) => (
                  <tr key={h.id} className="clickable" onClick={() => onOpenId(h.id)}>
                    <td className="mono cell-ioc">{h.query}</td>
                    <td>{TYPE_NAME[h.type]}</td>
                    <td><LevelBadge level={h.level} score={h.score} /></td>
                    <td className="muted" title={new Date(h.created_at).toLocaleString()}>{timeAgo(h.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Note>Nothing here yet. Investigate an indicator to start building history.</Note>
        )}
      </Panel>
    </div>
  );
}
