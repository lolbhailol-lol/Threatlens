import { C, LEVEL_COLOR, LEVEL_ICON } from "./lib.js";

export function StatusDot({ label, on }) {
  return (
    <span className="status-item" title={on ? `${label} connected` : `${label} not configured`}>
      <span className="status-dot" style={{ background: on ? C.clean : C.malicious }} />
      {label}
    </span>
  );
}

export function LevelBadge({ level, score }) {
  const color = LEVEL_COLOR[level] || C.muted;
  return (
    <span className="level-badge" style={{ color, borderColor: color }}>
      <span aria-hidden="true">{LEVEL_ICON[level]}</span>
      {level}
      {score !== undefined && score !== null && <b>{score}</b>}
    </span>
  );
}

export function RiskGauge({ score, level }) {
  const r = 80;
  const len = Math.PI * r;
  const pct = score ?? 0;
  const color = LEVEL_COLOR[level] || C.muted;
  return (
    <svg className="gauge" viewBox="0 0 200 118" role="img" aria-label={`Risk score ${score ?? "unknown"} of 100`}>
      <path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="#24344F" strokeWidth="14" strokeLinecap="round" />
      <path
        d="M20 100 A80 80 0 0 1 180 100"
        fill="none"
        stroke={color}
        strokeWidth="14"
        strokeLinecap="round"
        strokeDasharray={len}
        strokeDashoffset={len * (1 - pct / 100)}
        className="gauge-arc"
      />
      <text x="100" y="90" textAnchor="middle" className="gauge-score" fill={color}>
        {score ?? "--"}
      </text>
      <text x="100" y="112" textAnchor="middle" className="gauge-sub">
        risk score / 100
      </text>
    </svg>
  );
}

export function Panel({ title, source, children, wide, className = "" }) {
  return (
    <section className={`panel ${wide ? "panel-wide" : ""} ${className}`}>
      <header className="panel-head">
        <h3>{title}</h3>
        {source && <span className="panel-source">{source}</span>}
      </header>
      {children}
    </section>
  );
}

export function Rows({ items }) {
  return (
    <dl className="rows">
      {items
        .filter((i) => i.value !== undefined && i.value !== null && i.value !== "")
        .map((i) => (
          <div className="row" key={i.label}>
            <dt>{i.label}</dt>
            <dd className={i.mono ? "mono" : ""}>{String(i.value)}</dd>
          </div>
        ))}
    </dl>
  );
}

export function Note({ children, tone = "muted" }) {
  return <p className={`note note-${tone}`}>{children}</p>;
}

export function Spinner({ children }) {
  return (
    <div className="loading">
      <span className="spinner" />
      {children}
    </div>
  );
}
