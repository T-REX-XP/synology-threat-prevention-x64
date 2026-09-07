import { sleep } from "./util.js";

const state = { apiBase: null };

function unique(list) {
  return list.filter(function (x, i, a) { return a.indexOf(x) === i; });
}

export function apiBases() {
  const host = location.hostname || "127.0.0.1";
  const dir = location.pathname.replace(/\/[^/]*$/, "") || "";
  const sameOriginApi = dir + "/api";
  const portBase = location.port === "19557"
    ? ""
    : (location.protocol === "https:" ? "" : "http://" + host + ":19557");
  return unique([sameOriginApi, "", portBase, "http://" + host + ":19557"].filter(function (x) {
    return x !== undefined && x !== null;
  }));
}

function query(api, method, params) {
  const q = Object.keys(params || {}).map(function (k) {
    const v = params[k];
    if (v === undefined || v === null || v === "") return "";
    return encodeURIComponent(k) + "=" + encodeURIComponent(typeof v === "object" ? JSON.stringify(v) : v);
  }).filter(Boolean).join("&");
  return "?api=" + encodeURIComponent(api) + "&method=" + encodeURIComponent(method) + "&version=1" + (q ? "&" + q : "");
}

export function showBanner(t) {
  const el = document.getElementById("banner");
  if (!el) return;
  el.textContent = t;
  el.classList.remove("hidden");
}

export function hideBanner() {
  const el = document.getElementById("banner");
  if (!el) return;
  el.classList.add("hidden");
}

function unwrap(j) {
  const d = (j && j.data) || {};
  if (d.data && (d.data.events || d.data.total != null) && d.finish) return d.data;
  return d;
}

async function tryOne(base, path) {
  const url = (base || "") + path;
  const r = await fetch(url, { credentials: "include", cache: "no-store" });
  if (!r.ok) throw new Error("http " + r.status);
  return r.json();
}

export async function rawCall(api, method, params) {
  const path = query(api, method, params);
  const bases = state.apiBase != null ? [state.apiBase] : apiBases();
  let last = new Error("API unreachable");
  for (let i = 0; i < bases.length; i++) {
    try {
      const j = await tryOne(bases[i], path);
      state.apiBase = bases[i];
      hideBanner();
      if (!j.success) throw new Error("API error " + ((j.error && j.error.code) || "?"));
      return j;
    } catch (err) {
      last = err;
    }
  }
  showBanner("Cannot reach tpsweb. Start the package, or open http://" + (location.hostname || "NAS") + ":19557/");
  throw last;
}

export async function call(api, method, params) {
  const j = await rawCall(api, method, params || {});
  let data = unwrap(j);
  if (api === "SYNO.TPS.Event" && method === "list" && data.task_id && !(data.events || []).length) {
    data = await pollEventList(data.task_id);
  }
  return data;
}

async function pollEventList(taskId) {
  for (let i = 0; i < 20; i++) {
    const j = await rawCall("SYNO.TPS.Event", "list_status", { task_id: taskId });
    const inner = unwrap(j);
    const finish = (j.data && j.data.finish) || inner.finish;
    if (finish || (inner.events && inner.events.length) || inner.total != null) {
      return inner.events ? inner : (inner.data || inner);
    }
    await sleep(250);
  }
  return { events: [], total: 0 };
}

export async function pollUntil(api, method, params, done, tries) {
  let last = {};
  for (let i = 0; i < (tries || 40); i++) {
    last = await call(api, method, params);
    const nested = last.data || last;
    if (done(nested, last)) return last;
    await sleep(1000);
  }
  return last;
}
