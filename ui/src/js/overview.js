import { call } from "./api.js";
import { $, bars, engineRunning, esc, ifaceNames, sevLabel } from "./util.js";

export function loadOverview() {
  return Promise.all([
    call("SYNO.TPS.Overview", "get"),
    call("SYNO.TPS.Statistic.Trends", "get"),
    call("SYNO.TPS.Statistic.Device", "list", { limit: 8 }),
  ]).then(function (res) {
    const o = res[0];
    const tr = res[1];
    const dev = res[2];
    const s = o.sensor || {};
    const st = o.stats || o.days7 || {};
    $("ov-engine").innerHTML = engineRunning(s.status)
      ? '<span class="ok">running</span> (pid ' + (s.pid || "?") + ")"
      : '<span class="bad">' + esc(s.status || "stopped") + "</span>";
    $("ov-iface").textContent = ifaceNames(s).join(" ") || "auto";
    $("ov-rules").textContent = o.rules || "";
    $("ov-updated").textContent = o.last_updated || "not yet";
    $("ov-total").textContent = st.total || 0;
    $("ov-high").innerHTML = sevLabel(1) + " " + (st.high || 0);
    $("ov-med").innerHTML = sevLabel(2) + " " + (st.medium || 0);
    $("ov-low").innerHTML = sevLabel(3) + " " + (st.low || 0);
    $("ov-chart").innerHTML = bars(tr.points || tr.trends);
    const devices = dev.devices || dev.device_list || [];
    $("ov-devices").innerHTML = devices.length
      ? "<table><thead><tr><th>Source</th><th>Hits</th></tr></thead><tbody>" +
        devices.map(function (d) {
          return "<tr><td>" + esc(d.ip || d.device_name) + "</td><td>" + (d.count || d.loading || 0) + "</td></tr>";
        }).join("") + "</tbody></table>"
      : '<p class="muted">No devices in need of extra attention</p>';
  }).catch(function () {});
}
