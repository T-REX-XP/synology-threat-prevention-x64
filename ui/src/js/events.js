import { call } from "./api.js";
import { $, esc, sevLabel } from "./util.js";

export const eventsState = { events: [], selected: null, offset: 0, total: 0 };

export function loadEvents() {
  const kw = $("ev-q").value;
  return call("SYNO.TPS.Event", "list", {
    offset: eventsState.offset,
    limit: 50,
    key_words: kw,
    date_range: $("ev-range").value,
  }).then(function (d) {
    eventsState.events = d.events || [];
    eventsState.total = d.total || 0;
    $("ev-meta").textContent = eventsState.total + " events";
    $("ev-body").innerHTML = eventsState.events.map(function (e) {
      const src = e.ip_src_str || e.ip_src || "";
      const dst = e.ip_dst_str || e.ip_dst || "";
      return "<tr data-cid='" + e.cid + "'>" +
        "<td>" + esc(e.timestamp) + "</td>" +
        "<td>" + sevLabel(e.severity) + "</td>" +
        "<td>" + esc(e.sig_name) + "</td>" +
        "<td>" + esc(src) + ":" + (e.port_src || "") + "</td>" +
        "<td>" + esc(dst) + ":" + (e.port_dst || "") + "</td>" +
        "<td>" + esc(e.action) + "</td></tr>";
    }).join("") || '<tr><td colspan="6" class="muted">No events yet. Engine must be capturing.</td></tr>';
  });
}

export function loadEvent(cid) {
  return call("SYNO.TPS.Event", "get", { cid: cid, id: cid }).then(function (e) {
    eventsState.selected = e;
    const src = e.ip_src_str || e.ip_src || "";
    const dst = e.ip_dst_str || e.ip_dst || "";
    const payload = e.payload || e.data_payload || "";
    $("ev-detail").innerHTML =
      "<h2>Event " + esc(e.cid) + "</h2>" +
      "<p><strong>" + esc(e.sig_name) + "</strong> (sid " + esc(e.sig_sid) + " rev " + esc(e.sig_rev) + ")</p>" +
      "<p>Class: " + esc(e.sig_class_name) + " · " + sevLabel(e.severity) + "</p>" +
      "<p>" + esc(src) + ":" + (e.port_src || "") + " → " + esc(dst) + ":" + (e.port_dst || "") + "</p>" +
      (payload ? "<p class='muted'>Payload</p><pre>" + esc(payload) + "</pre>" : "") +
      '<div class="toolbar"><button class="btn" data-act="whitelist">Add to whitelist</button>' +
      '<button class="btn" data-act="drop">Change action: drop</button></div>';
  });
}

export function bindEvents() {
  $("ev-go").addEventListener("click", function () { eventsState.offset = 0; loadEvents(); });
  $("ev-prev").addEventListener("click", function () {
    eventsState.offset = Math.max(0, eventsState.offset - 50);
    loadEvents();
  });
  $("ev-next").addEventListener("click", function () { eventsState.offset += 50; loadEvents(); });
  $("ev-body").addEventListener("click", function (ev) {
    const tr = ev.target.closest("tr");
    if (tr && tr.getAttribute("data-cid")) {
      document.querySelectorAll("#ev-body tr").forEach(function (x) { x.classList.remove("sel"); });
      tr.classList.add("sel");
      loadEvent(tr.getAttribute("data-cid"));
    }
  });
  $("ev-detail").addEventListener("click", function (ev) {
    const act = ev.target.getAttribute("data-act");
    if (!act || !eventsState.selected) return;
    const e = eventsState.selected;
    call("SYNO.TPS.Signature.Policy", "add", {
      type: act === "whitelist" ? "filter" : "signature",
      raw_sid: e.sig_sid,
      sig_class_id: e.sig_class_id,
      sig_name: e.sig_name,
      action: act === "whitelist" ? "pass" : "drop",
      ip_src_str: act === "whitelist" ? (e.ip_src_str || e.ip_src) : "",
      ip_dst_str: act === "whitelist" ? (e.ip_dst_str || e.ip_dst) : "",
    }).then(function () { loadEvents(); });
  });
}
