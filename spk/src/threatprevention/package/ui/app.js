(function () {
  var state = { tab: "overview", apiBase: "", events: [], selected: null, offset: 0, total: 0 };
  var $ = function (id) { return document.getElementById(id); };

  function apiBases() {
    var host = location.hostname || "127.0.0.1";
    var portBase = location.protocol === "https:"
      ? "http://" + host + ":19557"
      : (location.port === "19557" ? "" : "http://" + host + ":19557");
    return [portBase, "", location.origin.replace(/:\d+$/, "") + ":19557"].filter(function (x, i, a) {
      return a.indexOf(x) === i;
    });
  }

  function call(api, method, params) {
    params = params || {};
    var q = Object.keys(params).map(function (k) {
      var v = params[k];
      if (v === undefined || v === null || v === "") return "";
      return encodeURIComponent(k) + "=" + encodeURIComponent(typeof v === "object" ? JSON.stringify(v) : v);
    }).filter(Boolean).join("&");
    var path = "?api=" + encodeURIComponent(api) + "&method=" + encodeURIComponent(method) + "&version=1" + (q ? "&" + q : "");
    var bases = state.apiBase !== "" ? [state.apiBase] : apiBases();
    function tryOne(i) {
      if (i >= bases.length) return Promise.reject(new Error("API unreachable"));
      var url = (bases[i] || "") + path;
      if (bases[i] === "" && location.protocol === "https:") {
        url = (location.origin.replace(/:\d+$/, "") + ":19557") + path;
      }
      return fetch(url, { credentials: "include", cache: "no-store" }).then(function (r) {
        if (!r.ok) throw new Error("http " + r.status);
        return r.json();
      }).then(function (j) {
        state.apiBase = bases[i];
        hideBanner();
        if (!j.success) throw new Error("API error " + ((j.error && j.error.code) || "?"));
        return j.data || {};
      }).catch(function (err) {
        if (i + 1 < bases.length) return tryOne(i + 1);
        showBanner("Cannot reach tpsweb on port 19557. Start the package, or open http://" + (location.hostname || "NAS") + ":19557/");
        throw err;
      });
    }
    return tryOne(0);
  }

  function showBanner(t) { $("banner").textContent = t; $("banner").classList.remove("hidden"); }
  function hideBanner() { $("banner").classList.add("hidden"); }

  function sevLabel(s) {
    if (s === 1) return '<span class="bad">High</span>';
    if (s === 2) return '<span class="warn">Medium</span>';
    return '<span class="muted">Low</span>';
  }

  function setTab(name) {
    state.tab = name;
    document.querySelectorAll(".tabs button").forEach(function (b) {
      b.classList.toggle("on", b.getAttribute("data-tab") === name);
    });
    ["overview", "events", "policy", "statistics", "settings"].forEach(function (t) {
      $(t).classList.toggle("hidden", t !== name);
    });
    if (name === "overview") loadOverview();
    if (name === "events") loadEvents();
    if (name === "policy") loadPolicy();
    if (name === "statistics") loadStats();
    if (name === "settings") loadSettings();
  }

  function loadOverview() {
    Promise.all([
      call("SYNO.TPS.Overview", "get"),
      call("SYNO.TPS.Statistic.Trends", "get"),
      call("SYNO.TPS.Statistic.Device", "list", { limit: 8 })
    ]).then(function (res) {
      var o = res[0], tr = res[1], dev = res[2];
      var s = o.sensor || {};
      var st = o.stats || {};
      $("ov-engine").innerHTML = s.status === "running"
        ? '<span class="ok">running</span> (pid ' + (s.pid || "?") + ")"
        : '<span class="bad">' + (s.status || "stopped") + "</span>";
      $("ov-iface").textContent = s.interface_list || "auto";
      $("ov-rules").textContent = o.rules || "";
      $("ov-updated").textContent = o.last_updated || "not yet";
      $("ov-total").textContent = st.total || 0;
      $("ov-high").innerHTML = sevLabel(1) + " " + (st.high || 0);
      $("ov-med").innerHTML = sevLabel(2) + " " + (st.medium || 0);
      $("ov-low").innerHTML = sevLabel(3) + " " + (st.low || 0);
      var pts = (tr.points || []);
      var max = Math.max.apply(null, pts.map(function (p) { return p.total; }).concat([1]));
      $("ov-chart").innerHTML = pts.map(function (p) {
        return '<span title="' + p.total + '" style="height:' + Math.round(100 * p.total / max) + '%"></span>';
      }).join("");
      $("ov-devices").innerHTML = ((dev.devices || []).length
        ? '<table><thead><tr><th>Source</th><th>Hits</th></tr></thead><tbody>' +
          dev.devices.map(function (d) {
            return "<tr><td>" + esc(d.ip || d.device_name) + "</td><td>" + d.count + "</td></tr>";
          }).join("") + "</tbody></table>"
        : '<p class="muted">No devices in need of extra attention</p>');
    }).catch(function () {});
  }

  function loadEvents() {
    var kw = $("ev-q").value;
    call("SYNO.TPS.Event", "list", { offset: state.offset, limit: 50, key_words: kw, date_range: $("ev-range").value }).then(function (d) {
      state.events = d.events || [];
      state.total = d.total || 0;
      $("ev-meta").textContent = state.total + " events";
      $("ev-body").innerHTML = state.events.map(function (e) {
        return "<tr data-cid='" + e.cid + "'>" +
          "<td>" + esc(e.timestamp) + "</td>" +
          "<td>" + sevLabel(e.severity) + "</td>" +
          "<td>" + esc(e.sig_name) + "</td>" +
          "<td>" + esc(e.ip_src_str) + ":" + e.port_src + "</td>" +
          "<td>" + esc(e.ip_dst_str) + ":" + e.port_dst + "</td>" +
          "<td>" + esc(e.action) + "</td></tr>";
      }).join("") || '<tr><td colspan="6" class="muted">No events yet. Engine must be capturing.</td></tr>';
    });
  }

  function loadEvent(cid) {
    call("SYNO.TPS.Event", "get", { cid: cid }).then(function (e) {
      state.selected = e;
      $("ev-detail").innerHTML =
        "<h2>Event " + e.cid + "</h2>" +
        "<p><strong>" + esc(e.sig_name) + "</strong> (sid " + e.sig_sid + " rev " + e.sig_rev + ")</p>" +
        "<p>Class: " + esc(e.sig_class_name) + " · " + sevLabel(e.severity) + "</p>" +
        "<p>" + esc(e.ip_src_str) + ":" + e.port_src + " → " + esc(e.ip_dst_str) + ":" + e.port_dst + "</p>" +
        (e.data_payload ? "<p class='muted'>Payload</p><pre>" + esc(e.data_payload) + "</pre>" : "") +
        '<div class="toolbar"><button class="btn" data-act="whitelist">Add to whitelist</button>' +
        '<button class="btn" data-act="drop">Change action: drop</button></div>';
    });
  }

  function loadPolicy() {
    Promise.all([
      call("SYNO.TPS.Signature", "list"),
      call("SYNO.TPS.Signature.Policy", "list")
    ]).then(function (res) {
      var classes = res[0].classes || [];
      $("pol-classes").innerHTML = classes.map(function (c) {
        return "<tr><td>" + esc(c.name) + "</td><td>" + esc(c.description) + "</td><td>" + c.total +
          "</td><td><select data-class='" + c.sig_class_id + "'>" +
          opt(c.action, "alert") + opt(c.action, "drop") + opt(c.action, "pass") + opt(c.action, "disable") +
          "</select></td></tr>";
      }).join("");
      var pol = res[1].policy || [];
      $("pol-extra").innerHTML = pol.filter(function (p) { return p.type !== "class"; }).map(function (p) {
        return "<tr><td>" + esc(p.type) + "</td><td>" + (p.raw_sid || "") + "</td><td>" + esc(p.sig_name) +
          "</td><td>" + esc(p.action) + "</td><td>" + esc(p.ip_src_str || "") +
          "</td><td><button class='btn danger' data-del-type='" + p.type + "' data-sid='" + p.raw_sid +
          "' data-id='" + (p.id || "") + "'>Delete</button></td></tr>";
      }).join("") || '<tr><td colspan="6" class="muted">No signature or filter overrides</td></tr>';
    });
    var q = $("rule-q").value;
    var cid = $("rule-class").value;
    call("SYNO.TPS.Signature.Rule", "list", { key_words: q, sig_class_id: cid, limit: 40 }).then(function (d) {
      $("pol-rules").innerHTML = (d.rules || []).map(function (r) {
        return "<tr><td>" + r.sig_sid + "</td><td>" + esc(r.sig_name) + "</td><td>" + esc(r.class_name) +
          "</td><td><select data-sid='" + r.sig_sid + "' data-class='" + r.sig_class_id + "' data-name='" + esc(r.sig_name) + "'>" +
          opt(r.action, "alert") + opt(r.action, "drop") + opt(r.action, "pass") + opt(r.action, "disable") +
          "</select></td></tr>";
      }).join("");
    });
  }

  function opt(cur, val) {
    return "<option value='" + val + "'" + (cur === val ? " selected" : "") + ">" + val + "</option>";
  }

  function loadStats() {
    Promise.all([
      call("SYNO.TPS.Event.Statistic", "get", { date_range: "7days" }),
      call("SYNO.TPS.Statistic.Trends", "get")
    ]).then(function (res) {
      var s = res[0], tr = res[1];
      $("st-sum").innerHTML =
        "<p>Total " + s.total + " · High " + s.high + " · Medium " + s.medium + " · Low " + s.low + "</p>";
      var max = Math.max.apply(null, (tr.points || []).map(function (p) { return p.total; }).concat([1]));
      $("st-chart").innerHTML = (tr.points || []).map(function (p) {
        return '<span title="' + p.total + '" style="height:' + Math.round(100 * p.total / max) + '%"></span>';
      }).join("");
      $("st-class").innerHTML = (s.top_class || []).map(function (c) {
        return "<tr><td>" + esc(c.name) + "</td><td>" + c.count + "</td></tr>";
      }).join("") || "<tr><td class='muted'>No data</td></tr>";
      $("st-src").innerHTML = (s.top_src || []).map(function (c) {
        return "<tr><td>" + esc(c.ip) + "</td><td>" + c.count + "</td></tr>";
      }).join("");
      $("st-dst").innerHTML = (s.top_dst || []).map(function (c) {
        return "<tr><td>" + esc(c.ip) + "</td><td>" + c.count + "</td></tr>";
      }).join("");
    });
  }

  function loadSettings() {
    Promise.all([
      call("SYNO.TPS.Sensor", "get"),
      call("SYNO.TPS.Settings.Update", "status"),
      call("SYNO.TPS.Settings.Update.Schedule", "get"),
      call("SYNO.TPS.Settings.Update.Source", "get"),
      call("SYNO.TPS.Settings.Storage", "get"),
      call("SYNO.TPS.Device", "list"),
      call("SYNO.TPS.Notification", "get")
    ]).then(function (res) {
      var sensor = res[0], upd = res[1], sch = res[2], src = res[3], stor = res[4], dev = res[5], ntf = res[6];
      $("set-enable").checked = !!sensor.enable_sensor;
      $("set-prev").checked = !!sensor.enable_prevention;
      $("set-iface").value = sensor.interface_list || "";
      $("set-mode").value = sensor.network_security_mode || "availability";
      $("set-upd").textContent = (upd.status || "") + (upd.last_updated ? " · last " + upd.last_updated : "");
      $("set-auto").checked = !!sch.auto_update;
      $("set-src").value = src.source || "et-open";
      $("set-code").value = src.code || "";
      $("set-limit").value = String(stor.limit || 500);
      $("set-db").textContent = ((stor.db_size || 0) / 1048576).toFixed(2) + " MiB used";
      $("set-mail").checked = !!ntf.enable_mail;
      $("set-push").checked = !!ntf.enable_push;
      $("set-ntf").checked = !!ntf.enable_notification;
      $("set-prefix").value = ntf.subject_prefix || "";
      $("set-dev").innerHTML = (dev.devices || []).map(function (d) {
        return "<tr><td>" + esc(d.device_name) + "</td><td>" + esc(d.mac) + "</td><td>" +
          (d.online ? '<span class="ok">online</span>' : "off") +
          "</td><td><input type='checkbox' data-mac='" + esc(d.mac) + "'" + (d.detect ? " checked" : "") + "></td></tr>";
      }).join("") || '<tr><td colspan="4" class="muted">No ARP/device rows yet</td></tr>';
    });
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c];
    });
  }

  function bind() {
    document.querySelectorAll(".tabs button").forEach(function (b) {
      b.addEventListener("click", function () { setTab(b.getAttribute("data-tab")); });
    });
    $("ev-go").addEventListener("click", function () { state.offset = 0; loadEvents(); });
    $("ev-prev").addEventListener("click", function () { state.offset = Math.max(0, state.offset - 50); loadEvents(); });
    $("ev-next").addEventListener("click", function () { state.offset += 50; loadEvents(); });
    $("ev-body").addEventListener("click", function (ev) {
      var tr = ev.target.closest("tr");
      if (tr && tr.getAttribute("data-cid")) {
        document.querySelectorAll("#ev-body tr").forEach(function (x) { x.classList.remove("sel"); });
        tr.classList.add("sel");
        loadEvent(tr.getAttribute("data-cid"));
      }
    });
    $("ev-detail").addEventListener("click", function (ev) {
      var act = ev.target.getAttribute("data-act");
      if (!act || !state.selected) return;
      var e = state.selected;
      call("SYNO.TPS.Signature.Policy", "add", {
        type: act === "whitelist" ? "filter" : "signature",
        raw_sid: e.sig_sid,
        sig_class_id: e.sig_class_id,
        sig_name: e.sig_name,
        action: act === "whitelist" ? "pass" : "drop",
        ip_src_str: act === "whitelist" ? e.ip_src_str : "",
        ip_dst_str: act === "whitelist" ? e.ip_dst_str : ""
      }).then(function () { loadPolicy(); });
    });
    $("pol-classes").addEventListener("change", function (ev) {
      var id = ev.target.getAttribute("data-class");
      if (!id) return;
      call("SYNO.TPS.Signature.Policy", "set", { type: "class", sig_class_id: id, action: ev.target.value }).then(loadPolicy);
    });
    $("pol-rules").addEventListener("change", function (ev) {
      var sid = ev.target.getAttribute("data-sid");
      if (!sid) return;
      call("SYNO.TPS.Signature.Policy", "set", {
        type: "signature", raw_sid: sid, sig_class_id: ev.target.getAttribute("data-class"),
        sig_name: ev.target.getAttribute("data-name"), action: ev.target.value
      });
    });
    $("pol-extra").addEventListener("click", function (ev) {
      var t = ev.target.getAttribute("data-del-type");
      if (!t) return;
      call("SYNO.TPS.Signature.Policy", "delete", {
        type: t, raw_sid: ev.target.getAttribute("data-sid"), id: ev.target.getAttribute("data-id")
      }).then(loadPolicy);
    });
    $("rule-go").addEventListener("click", loadPolicy);
    $("set-save-sensor").addEventListener("click", function () {
      call("SYNO.TPS.Sensor", "set", {
        enable_sensor: $("set-enable").checked,
        enable_prevention: $("set-prev").checked,
        interface_list: $("set-iface").value,
        network_security_mode: $("set-mode").value
      }).then(function () { alert("Saved. Restart the package from Package Center if the interface changed."); });
    });
    $("set-update").addEventListener("click", function () {
      call("SYNO.TPS.Settings.Update", "start_update").then(function () {
        $("set-upd").textContent = "updating…";
        setTimeout(loadSettings, 4000);
      });
    });
    $("set-save-upd").addEventListener("click", function () {
      Promise.all([
        call("SYNO.TPS.Settings.Update.Schedule", "set", { auto_update: $("set-auto").checked }),
        call("SYNO.TPS.Settings.Update.Source", "set", { source: $("set-src").value, code: $("set-code").value })
      ]).then(function () { alert("Saved"); });
    });
    $("set-save-stor").addEventListener("click", function () {
      call("SYNO.TPS.Settings.Storage", "set", { limit: $("set-limit").value }).then(function () { alert("Saved"); });
    });
    $("set-clear").addEventListener("click", function () {
      if (!confirm("Clear all logged events?")) return;
      call("SYNO.TPS.Settings.Storage", "clear_log").then(loadSettings);
    });
    $("set-save-ntf").addEventListener("click", function () {
      call("SYNO.TPS.Notification", "set", {
        enable_notification: $("set-ntf").checked,
        enable_mail: $("set-mail").checked,
        enable_push: $("set-push").checked,
        subject_prefix: $("set-prefix").value
      }).then(function () { alert("Saved (DSM Control Panel still sends mail/push)."); });
    });
    $("set-dev").addEventListener("change", function (ev) {
      var mac = ev.target.getAttribute("data-mac");
      if (!mac) return;
      call("SYNO.TPS.Device", "set", { mac: mac, detect: ev.target.checked });
    });
    $("set-backup").addEventListener("click", function () {
      call("SYNO.TPS.Backup", "backup").then(function (d) {
        var blob = new Blob([d.json || ""], { type: "application/json" });
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "threatprevention-backup.json";
        a.click();
      });
    });
    $("set-restore").addEventListener("change", function (ev) {
      var f = ev.target.files[0];
      if (!f) return;
      var r = new FileReader();
      r.onload = function () {
        call("SYNO.TPS.Backup", "restore", { json: r.result }).then(function () { alert("Restored"); loadSettings(); });
      };
      r.readAsText(f);
    });
  }

  bind();
  setTab("overview");
})();
