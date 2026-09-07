import { call } from "./api.js";
import { $, bars, esc } from "./util.js";

function bucket(stat) {
  return stat.days7 || stat;
}

export function loadStats() {
  return Promise.all([
    call("SYNO.TPS.Event.Statistic", "get", { date_range: "7days" }),
    call("SYNO.TPS.Statistic.Trends", "get"),
  ]).then(function (res) {
    const s = bucket(res[0]);
    const tr = res[1];
    $("st-sum").innerHTML =
      "<p>Total " + (s.total || 0) + " · High " + (s.high || 0) + " · Medium " + (s.medium || 0) + " · Low " + (s.low || 0) + "</p>";
    $("st-chart").innerHTML = bars(tr.points || tr.trends);
    const classes = s.top_class || s.class_name || [];
    $("st-class").innerHTML = classes.map(function (c) {
      return "<tr><td>" + esc(c.name || c.sig_class_name) + "</td><td>" + c.count + "</td></tr>";
    }).join("") || "<tr><td class='muted'>No data</td></tr>";
    const src = s.top_src || s.ip_src || [];
    $("st-src").innerHTML = src.map(function (c) {
      return "<tr><td>" + esc(c.ip || c.ip_src) + "</td><td>" + c.count + "</td></tr>";
    }).join("");
    const dst = s.top_dst || s.ip_dst || [];
    $("st-dst").innerHTML = dst.map(function (c) {
      return "<tr><td>" + esc(c.ip || c.ip_dst) + "</td><td>" + c.count + "</td></tr>";
    }).join("");
  });
}
