import { call, pollUntil } from "./api.js";
import { $, esc } from "./util.js";

function storageLimit(stor) {
  const raw = stor.limit || stor.db_size;
  if (raw === "db_size_500mb") return "500";
  if (raw === "db_size_1gb") return "1024";
  if (raw === "db_size_2gb") return "2048";
  const n = parseInt(raw, 10);
  if (n === 500 || n === 1024 || n === 2048) return String(n);
  return "500";
}

function sourceValue(src) {
  if (src.use_code === "etPro" || src.source === "et-pro") return "et-pro";
  return src.source || "et-open";
}

function renderIfaces(sensor) {
  const list = Array.isArray(sensor.interface_list) ? sensor.interface_list : [];
  if (!list.length) {
    const fallback = typeof sensor.interface_list === "string" ? sensor.interface_list : (sensor.interface || "ovs_eth0");
    $("set-ifaces").innerHTML =
      '<label class="row">Interface <input id="set-iface" placeholder="ovs_eth0" value="' + esc(fallback) + '"></label>';
    return;
  }
  $("set-ifaces").innerHTML = '<div class="iface-list">' + list.map(function (iface) {
    const name = iface.if_id || iface.ifname;
    const on = iface.enabled !== false;
    return '<label><input type="checkbox" data-if="' + esc(name) + '"' + (on ? " checked" : "") + "> " + esc(name) + "</label>";
  }).join("") + "</div>";
}

function collectIfaces() {
  const boxes = document.querySelectorAll("#set-ifaces input[data-if]");
  if (!boxes.length) {
    const input = document.getElementById("set-iface");
    return input && input.value ? input.value : "";
  }
  const out = [];
  boxes.forEach(function (box) {
    out.push({ if_id: box.getAttribute("data-if"), enabled: box.checked });
  });
  return out;
}

function scheduleHour(sch) {
  const minute = sch.minute;
  if (minute === "hourly" || minute == null) return 2;
  const n = parseInt(minute, 10);
  if (isNaN(n)) return 2;
  return Math.floor(n / 60) % 24;
}

export function loadSettings() {
  return Promise.all([
    call("SYNO.TPS.Sensor", "get"),
    call("SYNO.TPS.Settings.Update", "status"),
    call("SYNO.TPS.Settings.Update.Schedule", "get"),
    call("SYNO.TPS.Settings.Update.Source", "get"),
    call("SYNO.TPS.Settings.Storage", "get"),
    call("SYNO.TPS.Device", "list"),
    call("SYNO.TPS.Notification", "get"),
    call("SYNO.TPS.Event.ExportFolder", "get"),
  ]).then(function (res) {
    const sensor = res[0];
    const upd = res[1].data || res[1];
    const sch = res[2];
    const src = res[3];
    const stor = res[4];
    const dev = res[5];
    const ntf = res[6];
    const exp = res[7];
    $("set-enable").checked = !!sensor.enable_sensor;
    $("set-prev").checked = !!sensor.enable_prevention;
    $("set-mode").value = sensor.network_security_mode || "availability";
    renderIfaces(sensor);
    $("set-upd").textContent = (upd.status || "") + (upd.last_updated ? " · last " + upd.last_updated : "");
    $("set-auto").checked = !!sch.auto_update;
    $("set-weekday").value = String(sch.weekday != null ? sch.weekday : "daily");
    $("set-hour").value = String(scheduleHour(sch));
    $("set-src").value = sourceValue(src);
    $("set-code").value = src.code || "";
    $("set-limit").value = storageLimit(stor);
    const used = stor.db_size_bytes != null ? stor.db_size_bytes : (typeof stor.db_size === "number" ? stor.db_size : 0);
    $("set-db").textContent = (used / 1048576).toFixed(2) + " MiB used";
    $("set-mail").checked = !!ntf.enable_mail;
    $("set-push").checked = !!ntf.enable_push;
    $("set-ntf").checked = !!ntf.enable_notification;
    $("set-prefix").value = ntf.subject_prefix || "";
    $("set-export").textContent = exp.export_folder
      ? "File Station export folder: " + exp.export_folder
      : "";
    const devices = dev.devices || dev.device_list || [];
    $("set-dev").innerHTML = devices.map(function (d) {
      return "<tr><td>" + esc(d.device_name) + "</td><td>" + esc(d.mac) + "</td><td>" +
        (d.online ? '<span class="ok">online</span>' : "off") +
        "</td><td>" + (d.loading_score || d.loading || 0) +
        "</td><td><input type='checkbox' data-mac='" + esc(d.mac) + "'" + (d.detect ? " checked" : "") + "></td></tr>";
    }).join("") || '<tr><td colspan="5" class="muted">No ARP/device rows yet</td></tr>';
  });
}

export function bindSettings() {
  $("set-save-sensor").addEventListener("click", function () {
    call("SYNO.TPS.Sensor", "set", {
      enable_sensor: $("set-enable").checked,
      enable_prevention: $("set-prev").checked,
      interface_list: collectIfaces(),
      network_security_mode: $("set-mode").value,
    }).then(function () { alert("Saved. Restart the package from Package Center if the interface changed."); });
  });
  $("set-update").addEventListener("click", function () {
    call("SYNO.TPS.Settings.Update", "start_update").then(function (d) {
      $("set-upd").textContent = "updating…";
      const tid = d.task_id;
      return pollUntil("SYNO.TPS.Settings.Update", "status", tid ? { task_id: tid } : {}, function (st) {
        const status = (st.data && st.data.status) || st.status;
        return status && status !== "updating" && status !== "checking";
      }, 90);
    }).then(loadSettings);
  });
  $("set-save-upd").addEventListener("click", function () {
    const hour = parseInt($("set-hour").value, 10) || 2;
    Promise.all([
      call("SYNO.TPS.Settings.Update.Schedule", "set", {
        auto_update: $("set-auto").checked,
        weekday: $("set-weekday").value,
        minute: hour * 60,
      }),
      call("SYNO.TPS.Settings.Update.Source", "set", {
        source: $("set-src").value,
        use_code: $("set-src").value === "et-pro" ? "etPro" : "etOpen",
        code: $("set-code").value,
      }),
    ]).then(function () { alert("Saved"); });
  });
  $("set-save-stor").addEventListener("click", function () {
    call("SYNO.TPS.Settings.Storage", "set", { limit: $("set-limit").value, db_size: $("set-limit").value }).then(function () {
      alert("Saved");
    });
  });
  $("set-clear").addEventListener("click", function () {
    if (!confirm("Clear all logged events?")) return;
    call("SYNO.TPS.Settings.Storage", "start_clear_log").then(function (d) {
      const tid = d.task_id;
      return pollUntil("SYNO.TPS.Settings.Storage", "status_clear_log", tid ? { task_id: tid } : {}, function (st) {
        const status = (st.data && st.data.status) || st.status;
        return status === "cleared" || status === "idle";
      }, 30);
    }).then(loadSettings);
  });
  $("set-save-ntf").addEventListener("click", function () {
    call("SYNO.TPS.Notification", "set", {
      enable_notification: $("set-ntf").checked,
      enable_mail: $("set-mail").checked,
      enable_push: $("set-push").checked,
      subject_prefix: $("set-prefix").value,
    }).then(function () { alert("Saved (DSM Control Panel still sends mail/push)."); });
  });
  $("set-dev").addEventListener("change", function (ev) {
    const mac = ev.target.getAttribute("data-mac");
    if (!mac) return;
    call("SYNO.TPS.Device", "set", { mac: mac, detect: ev.target.checked });
  });
  $("set-backup").addEventListener("click", function () {
    call("SYNO.TPS.Backup", "backup").then(function (d) {
      const blob = new Blob([d.json || ""], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "threatprevention-backup.json";
      a.click();
    });
  });
  $("set-restore").addEventListener("change", function (ev) {
    const f = ev.target.files[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = function () {
      call("SYNO.TPS.Backup", "restore", { json: r.result }).then(function () {
        alert("Restored");
        loadSettings();
      });
    };
    r.readAsText(f);
  });
}
