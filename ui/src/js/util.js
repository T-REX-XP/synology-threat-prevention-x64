export function $(id) {
  return document.getElementById(id);
}

export function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c];
  });
}

export function sevNum(s) {
  if (s === 1 || s === "1" || s === "high") return 1;
  if (s === 2 || s === "2" || s === "medium") return 2;
  if (s === 3 || s === "3" || s === "low") return 3;
  const n = parseInt(s, 10);
  return n === 1 || n === 2 || n === 3 ? n : 3;
}

export function sevLabel(s) {
  const n = sevNum(s);
  if (n === 1) return '<span class="bad">High</span>';
  if (n === 2) return '<span class="warn">Medium</span>';
  return '<span class="muted">Low</span>';
}

export function engineRunning(status) {
  return status === "running" || status === "engine_start";
}

export function ifaceNames(sensor) {
  const list = sensor.interface_list || sensor.interfaceList;
  if (Array.isArray(list)) {
    return list
      .filter(function (x) { return x && x.enabled !== false; })
      .map(function (x) { return x.if_id || x.ifname || ""; })
      .filter(Boolean);
  }
  if (typeof list === "string" && list.trim()) {
    return list.replace(/,/g, " ").split(/\s+/).filter(Boolean);
  }
  if (sensor.interface) return [String(sensor.interface)];
  return [];
}

export function bars(points) {
  const pts = points || [];
  const max = Math.max.apply(null, pts.map(function (p) { return p.total || 0; }).concat([1]));
  return pts.map(function (p) {
    const total = p.total || 0;
    return '<span title="' + total + '" style="height:' + Math.round(100 * total / max) + '%"></span>';
  }).join("");
}

export function opt(cur, val) {
  return "<option value='" + val + "'" + (cur === val ? " selected" : "") + ">" + val + "</option>";
}

export function sleep(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}
