import { call } from "./api.js";
import { $, esc, opt } from "./util.js";

export function loadPolicy() {
  Promise.all([
    call("SYNO.TPS.Signature", "list"),
    call("SYNO.TPS.Signature.Policy", "list"),
  ]).then(function (res) {
    const classes = res[0].classes || res[0].signatures || [];
    $("pol-classes").innerHTML = classes.map(function (c) {
      const action = c.action || (c.enabled === false ? "disable" : "alert");
      const total = c.totalCount != null ? c.totalCount : (c.total || 0);
      return "<tr><td>" + esc(c.name || c.class_name) + "</td><td>" + esc(c.description) + "</td><td>" + total +
        "</td><td><select data-class='" + (c.sig_class_id || "") + "' data-name='" + esc(c.name || c.class_name) + "'>" +
        opt(action, "alert") + opt(action, "drop") + opt(action, "pass") + opt(action, "disable") +
        "</select></td></tr>";
    }).join("");
    const pol = res[1].policy || res[1].list || [];
    $("pol-extra").innerHTML = pol.filter(function (p) {
      return p.type !== "class" && p.type !== 1;
    }).map(function (p) {
      const typ = p.type === 3 ? "filter" : (p.type === 2 ? "signature" : p.type);
      return "<tr><td>" + esc(typ) + "</td><td>" + (p.raw_sid || p.sid || "") + "</td><td>" + esc(p.sig_name || p.name) +
        "</td><td>" + esc(p.action) + "</td><td>" + esc(p.ip_src_str || p.ip_src || "") +
        "</td><td><button class='btn danger' data-del-type='" + typ + "' data-sid='" + (p.raw_sid || p.sid || "") +
        "' data-id='" + (p.id || "") + "'>Delete</button></td></tr>";
    }).join("") || '<tr><td colspan="6" class="muted">No signature or filter overrides</td></tr>';
  });
  const q = $("rule-q").value;
  const cid = $("rule-class").value;
  return call("SYNO.TPS.Signature.Rule", "list", { key_words: q, sig_class_id: cid, limit: 40 }).then(function (d) {
    $("pol-rules").innerHTML = (d.rules || []).map(function (r) {
      return "<tr><td>" + r.sig_sid + "</td><td>" + esc(r.sig_name) + "</td><td>" + esc(r.class_name) +
        "</td><td><select data-sid='" + r.sig_sid + "' data-class='" + r.sig_class_id + "' data-name='" + esc(r.sig_name) + "'>" +
        opt(r.action, "alert") + opt(r.action, "drop") + opt(r.action, "pass") + opt(r.action, "disable") +
        "</select></td></tr>";
    }).join("");
  });
}

export function bindPolicy() {
  $("pol-classes").addEventListener("change", function (ev) {
    const id = ev.target.getAttribute("data-class");
    const name = ev.target.getAttribute("data-name");
    if (!id && !name) return;
    call("SYNO.TPS.Signature.Policy", "set", {
      type: "class",
      sig_class_id: id,
      class_name: name,
      action: ev.target.value,
    }).then(loadPolicy);
  });
  $("pol-rules").addEventListener("change", function (ev) {
    const sid = ev.target.getAttribute("data-sid");
    if (!sid) return;
    call("SYNO.TPS.Signature.Policy", "set", {
      type: "signature",
      raw_sid: sid,
      sig_class_id: ev.target.getAttribute("data-class"),
      sig_name: ev.target.getAttribute("data-name"),
      action: ev.target.value,
    });
  });
  $("pol-extra").addEventListener("click", function (ev) {
    const t = ev.target.getAttribute("data-del-type");
    if (!t) return;
    call("SYNO.TPS.Signature.Policy", "delete", {
      type: t,
      raw_sid: ev.target.getAttribute("data-sid"),
      id: ev.target.getAttribute("data-id"),
    }).then(loadPolicy);
  });
  $("rule-go").addEventListener("click", loadPolicy);
}
