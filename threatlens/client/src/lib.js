// Shared constants and helpers

export const C = {
  clean: "#3DD68C",
  suspicious: "#F5B544",
  malicious: "#F0506E",
  info: "#5AA9FF",
  muted: "#64748B",
};

export const LEVEL_COLOR = {
  Clean: C.clean,
  Suspicious: C.suspicious,
  Malicious: C.malicious,
  Unknown: C.muted,
};

export const LEVEL_ICON = { Clean: "✓", Suspicious: "!", Malicious: "✕", Unknown: "?" };

export const TYPE_NAME = { ip: "IP address", domain: "Domain", url: "URL", hash: "File hash" };

// Undo defanging used in threat reports: hxxp://evil[.]com -> http://evil.com
export function refang(v) {
  return v
    .replace(/\bhxxp(s?)/gi, "http$1")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[:\]/g, ":");
}

// Make an indicator safe to paste into chat/email without it becoming a clickable link
export function defang(v) {
  return v.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}

export function detectType(q) {
  const v = refang(q.trim());
  if (/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(v)) return "ip";
  if (v.includes(":") && /^[0-9a-f:]+$/i.test(v)) return "ip";
  if (/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(v)) return "hash";
  if (/^https?:\/\//i.test(v)) return "url";
  if (/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(v)) return "domain";
  return null;
}

export function scoreColor(s) {
  if (s === null || s === undefined) return C.muted;
  return s >= 60 ? C.malicious : s >= 20 ? C.suspicious : C.clean;
}

export async function api(path, options) {
  let res;
  try {
    res = await fetch(path, options);
  } catch {
    throw new Error("Can't reach the ThreatLens server. Is it running?");
  }
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json.error || `Server returned ${res.status}`);
  return json;
}

export function downloadFile(name, content, type) {
  const blob = new Blob([content], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

export function toCSV(rows, columns) {
  const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  return [columns.map((c) => esc(c.label)).join(","), ...rows.map((r) => columns.map((c) => esc(c.get(r))).join(","))].join("\n");
}

export function timeAgo(iso) {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
