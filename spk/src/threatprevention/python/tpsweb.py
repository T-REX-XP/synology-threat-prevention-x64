#!/usr/bin/env python3
"""SYNO.TPS.* JSON API + static UI on TCP :19557 and a unix socket."""
import base64
import json
import os
import re
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from compat import (
    coerce_params,
    flatten_keywords,
    now_str,
    official_devices,
    official_event,
    official_event_statistic,
    official_map,
    official_policy_list,
    official_policy_write,
    official_sensor,
    official_signature_classes,
    official_source,
    official_storage,
    usb_max_label,
    official_trends,
    official_update_status,
    official_variables,
    classify_update,
    parse_event_id,
    severity_name,
    severity_num,
    to_epoch,
)
from compiler import compile_rules, import_rules, parse_header, parse_refs, reload_suricata
from corehost import iface_ipv4, list_neighbors, nsm_device_list, systemdb_get, usb_list
from feeds import add_feed, delete_feed, list_feeds, update_feed, write_feeds_json
from notify import (
    list_filters,
    read_telegram_conf,
    send_telegram,
    upsert_filters,
    write_telegram_conf,
)
from paths import (
    EXPORT_DIR,
    GMAPS_KEY,
    IFACE_FILE,
    PKGDEST,
    PKGETC,
    PKGVAR,
    SENSOR_CONF,
    SOCK_PATH,
    SURICATA_BIN,
    SURICATA_PID,
    TPSWEB_PID,
    TPSWEB_PORT,
    UPDATE_SCRIPT,
    YAML_PATH,
)
from store import (
    backup_json,
    clear_events,
    connect,
    init_db,
    ip_to_int,
    kv_get,
    kv_set,
    restore_json,
)

STOP = False
EVENT_TASKS = {}
EVENT_TASK_SEQ = 0
JOBS = {}
JOB_SEQ = 0


def _stop(signum, frame):
    global STOP
    STOP = True


def ok(data=None):
    return {"success": True, "data": data if data is not None else {}}


def err(code, extra=None):
    body = {"success": False, "error": {"code": int(code)}}
    if extra:
        body["error"].update(extra)
    return body


def _pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _find_suricata_pid():
    proc = "/proc"
    try:
        names = os.listdir(proc)
    except OSError:
        return 0
    for name in names:
        if not name.isdigit():
            continue
        try:
            raw = open(os.path.join(proc, name, "cmdline"), "rb").read()
        except OSError:
            continue
        argv0 = raw.split(b"\x00", 1)[0]
        if argv0.endswith(b"/suricata") or argv0 == b"suricata":
            return int(name)
    return 0


def engine_status():
    if os.path.isfile(SURICATA_PID):
        try:
            pid = int(open(SURICATA_PID).read().strip() or "0")
            if _pid_alive(pid):
                return "running", pid
            try:
                os.remove(SURICATA_PID)
            except OSError:
                pass
        except (ValueError, OSError):
            pass
    pid = _find_suricata_pid()
    if pid:
        try:
            with open(SURICATA_PID, "w") as fh:
                fh.write("%s\n" % pid)
        except OSError:
            pass
        return "running", pid
    return "stopped", 0


_AUTOSTART_TRY = 0.0
_AUTOSTART_FAIL = 0.0


def maybe_autostart(enable):
    """If capture is enabled but Suricata is dead, try to start it (needs setcap)."""
    global _AUTOSTART_TRY, _AUTOSTART_FAIL
    if not enable:
        return
    st, _pid = engine_status()
    if st == "running":
        return
    now = time.time()
    if now - _AUTOSTART_TRY < 45:
        return
    if _AUTOSTART_FAIL and now - _AUTOSTART_FAIL < 120:
        return
    _AUTOSTART_TRY = now

    def _run():
        global _AUTOSTART_FAIL
        try:
            conn = connect()
            try:
                kv_set(conn, "engine_ui_status", "engine_init")
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass
        if start_engine():
            _AUTOSTART_FAIL = 0.0
        else:
            _AUTOSTART_FAIL = time.time()
            try:
                conn = connect()
                try:
                    kv_set(conn, "engine_ui_status", "")
                    conn.commit()
                finally:
                    conn.close()
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True).start()


def _capture_iface():
    if os.path.isfile(IFACE_FILE):
        try:
            text = open(IFACE_FILE, encoding="utf-8", errors="replace").read().strip()
            if text:
                return text.split()[0]
        except OSError:
            pass
    return "ovs_eth0"


def start_engine():
    st, _pid = engine_status()
    if st == "running":
        return True
    if os.path.isfile(SURICATA_PID):
        try:
            os.remove(SURICATA_PID)
        except OSError:
            pass
    if not os.path.isfile(SURICATA_BIN):
        return False
    iface = _capture_iface()
    logdir = os.path.join(PKGVAR, "log")
    try:
        os.makedirs(logdir, exist_ok=True)
    except OSError:
        pass
    cmd = [
        SURICATA_BIN, "-c", YAML_PATH, "--pidfile", SURICATA_PID,
        "-D", "-i", iface, "-l", logdir, "--set", "af-packet.0.interface=" + iface,
    ]
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        return False
    for _ in range(20):
        time.sleep(0.5)
        if engine_status()[0] == "running":
            return True
    return engine_status()[0] == "running"


def stop_engine():
    st, pid = engine_status()
    if st == "running" and pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    if os.path.isfile(SURICATA_PID):
        try:
            os.remove(SURICATA_PID)
        except OSError:
            pass


def read_sensor():
    cfg = {
        "enable_sensor": True,
        "enable_prevention": False,
        "interface_list": "",
        "network_security_mode": "availability",
        "default_detect": True,
    }
    if os.path.isfile(SENSOR_CONF):
        with open(SENSOR_CONF, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "=" not in line or line.strip().startswith("#"):
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    if os.path.isfile(IFACE_FILE):
        cfg["interface_list"] = open(IFACE_FILE).read().strip()
    cfg["enable_sensor"] = _truth(cfg.get("enable_sensor", True))
    cfg["enable_prevention"] = _truth(cfg.get("enable_prevention", False))
    cfg["default_detect"] = _truth(cfg.get("default_detect", True))
    cfg["enable_auto_export_events_during_postupgrade"] = _truth(
        cfg.get("enable_auto_export_events_during_postupgrade", False)
    )
    maybe_autostart(cfg["enable_sensor"])
    ui = kv_peek("engine_ui_status")
    st, pid = engine_status()
    if st == "running":
        if ui:
            try:
                conn = connect()
                try:
                    kv_set(conn, "engine_ui_status", "")
                    conn.commit()
                finally:
                    conn.close()
            except Exception:
                pass
    elif ui:
        st = ui
    data = official_sensor(cfg, st, pid, cfg.get("interface_list") or "", list_ifaces())
    for item in data.get("interface_list") or []:
        item["ip_addr"] = iface_ipv4(item.get("if_id") or item.get("ifname") or "") or ""
    return data


def write_sensor(data):
    os.makedirs(PKGETC, exist_ok=True)
    raw_iface = data.get("interface_list") or data.get("interfaceList") or ""
    if isinstance(raw_iface, list):
        names = []
        for item in raw_iface:
            if isinstance(item, dict):
                if _truth(item.get("enabled", True)):
                    names.append(item.get("if_id") or item.get("ifname") or "")
            else:
                names.append(str(item))
        iface = " ".join(n for n in names if n)
    else:
        iface = str(raw_iface).strip()
    if iface:
        with open(IFACE_FILE, "w") as fh:
            fh.write(iface.split()[0] + "\n")
        try:
            os.chmod(IFACE_FILE, 0o644)
        except OSError:
            pass
    lines = [
        "enable_sensor=%s" % ("yes" if _truth(data.get("enable_sensor", True)) else "no"),
        "enable_prevention=%s" % ("yes" if _truth(data.get("enable_prevention", False)) else "no"),
        "default_detect=%s" % ("yes" if _truth(data.get("default_detect", True)) else "no"),
        "enable_auto_export_events_during_postupgrade=%s" % (
            "yes" if _truth(data.get("enable_auto_export_events_during_postupgrade", False)) else "no"
        ),
        "network_security_mode=%s" % (data.get("network_security_mode") or "availability"),
        "interface_list=%s" % iface,
    ]
    with open(SENSOR_CONF, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    # persist the checkbox; capture stays AF_PACKET IDS (no NFQUEUE).


def _truth(v):
    if isinstance(v, bool):
        return v
    return str(v).lower() in ("1", "true", "yes", "on")


def kv_peek(key, default=""):
    try:
        conn = connect()
        try:
            return kv_get(conn, key, default)
        finally:
            conn.close()
    except Exception:
        return default


def list_ifaces():
    names = []
    sysnet = "/sys/class/net"
    if os.path.isdir(sysnet):
        for name in sorted(os.listdir(sysnet)):
            if name in ("lo", "sit0", "ovs-system", "syno_ovs_bonds", "dummy0") or name.startswith(("veth", "docker", "br-", "tun", "tap", "gre", "sit")):
                continue
            names.append(name)
        return names
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show"], stderr=subprocess.DEVNULL, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return names
    for line in out.decode("utf-8", "replace").splitlines():
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip().split("@", 1)[0]
        if name in ("lo", "sit0", "ovs-system", "syno_ovs_bonds") or name.startswith(("veth", "docker", "br-")):
            continue
        names.append(name)
    return names


def write_update_source(source, code=""):
    """Sidecar files update-rules.sh reads (no sqlite in the shell script)."""
    os.makedirs(PKGETC, exist_ok=True)
    src = "et-pro" if str(source).lower() in ("et-pro", "etpro", "et_pro") else "et-open"
    with open(os.path.join(PKGETC, "update-source"), "w") as fh:
        fh.write(src + "\n")
    path = os.path.join(PKGETC, "etpro.code")
    if src == "et-pro" and code:
        with open(path, "w") as fh:
            fh.write(str(code).strip() + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    elif os.path.isfile(path) and src != "et-pro":
        try:
            os.remove(path)
        except OSError:
            pass


def probe_rule_update(last_updated="", source="et-open", code=""):
    """HEAD ET Open or ET Pro tarball. Returns (reachable, remote_newer)."""
    if str(source).lower() in ("et-pro", "etpro") and code:
        urls = (
            "https://rules.emergingthreatspro.com/%s/suricata-8.0/etpro.rules.tar.gz" % code,
            "https://rules.emergingthreatspro.com/%s/suricata/etpro.rules.tar.gz" % code,
        )
    else:
        urls = (
            "https://rules.emergingthreats.net/open/suricata-8.0.6/emerging.rules.tar.gz",
            "https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz",
            "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz",
        )
    try:
        from urllib.request import Request, urlopen
    except ImportError:
        return False, False
    local = 0
    if last_updated:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%a, %d %b %Y %H:%M:%S %Z"):
            try:
                local = int(time.mktime(time.strptime(last_updated, fmt)))
                break
            except ValueError:
                continue
    catalog = os.path.join(PKGVAR, "rules", "catalog.rules")
    if not local and os.path.isfile(catalog):
        try:
            local = int(os.path.getmtime(catalog))
        except OSError:
            pass
    for url in urls:
        try:
            req = Request(url, method="HEAD")
            req.add_header("User-Agent", "ThreatPrevention-PoC")
            with urlopen(req, timeout=20) as resp:
                lm = resp.headers.get("Last-Modified") or ""
            remote = 0
            if lm:
                try:
                    remote = int(time.mktime(time.strptime(lm, "%a, %d %b %Y %H:%M:%S %Z")))
                except ValueError:
                    remote = 0
            return True, bool(remote and local and remote > local + 60)
        except Exception:
            continue
    return False, False


def start_job(initial=None):
    global JOB_SEQ
    JOB_SEQ += 1
    tid = str(JOB_SEQ)
    JOBS[tid] = dict(initial or {"status": "running"})
    while len(JOBS) > 32:
        JOBS.pop(next(iter(JOBS)))
    return tid


def job_get(tid):
    return JOBS.get(str(tid or ""))


def ensure_export_dir():
    try:
        os.makedirs(EXPORT_DIR, exist_ok=True)
    except OSError:
        pass
    real = os.path.realpath(EXPORT_DIR)
    for root in ("/volume1/homes", "/var/services/homes"):
        if not os.path.isdir(root):
            continue
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            if name.startswith(".") or name.startswith("@"):
                continue
            dest = os.path.join(root, name, "ThreatPrevention")
            try:
                os.makedirs(dest, exist_ok=True)
            except OSError:
                continue
            if os.access(dest, os.W_OK):
                return os.path.realpath(dest)
    return real


def event_row(r, conn=None):
    name = r["sig_name"]
    class_name = ""
    severity = 3
    if conn is not None:
        cr = conn.execute("SELECT sig_class_name, sig_priority FROM sig_class WHERE sig_class_id=?", (r["sig_class_id"],)).fetchone()
        if cr:
            class_name = cr["sig_class_name"]
            severity = 1 if cr["sig_priority"] <= 1 else (2 if cr["sig_priority"] == 2 else 3)
    if r["impact_flag"] and int(r["impact_flag"]) > 0:
        severity = int(r["impact_flag"]) if int(r["impact_flag"]) <= 3 else severity
    return {
        "sid": r["sid"],
        "cid": r["cid"],
        "timestamp": r["timestamp"],
        "ts_epoch": r["ts_epoch"],
        "sig_sid": r["sig_sid"],
        "sig_rev": r["sig_rev"],
        "sig_name": name,
        "sig_class_id": r["sig_class_id"],
        "sig_class_name": class_name,
        "severity": severity,
        "action": r["action"],
        "ip_src": r["ip_src"],
        "ip_dst": r["ip_dst"],
        "ip_src_str": r["ip_src_str"],
        "ip_dst_str": r["ip_dst_str"],
        "port_src": r["port_src"],
        "port_dst": r["port_dst"],
        "ip_proto": r["ip_proto"],
        "mac_src": r["mac_src"],
        "mac_dst": r["mac_dst"],
        "device_src": r["mac_src"],
        "device_dst": r["mac_dst"],
    }


def handle(api, method, params, conn):
    params = coerce_params(params)
    if api == "SYNO.TPS.Event" and method == "list":
        return event_list(conn, params)
    if api == "SYNO.TPS.Event" and method == "get":
        return event_get(conn, params)
    if api == "SYNO.TPS.Event" and method == "list_status":
        return event_list_status(params)
    if api == "SYNO.TPS.Event.Offset" and method == "get":
        return event_offset(conn, params)
    if api == "SYNO.TPS.Event.Statistic" and method == "get":
        return event_stat(conn, params)
    if api == "SYNO.TPS.Event.Map" and method == "list":
        return ok(official_map(conn, params.get("date_range")))
    if api == "SYNO.TPS.Event.ExportFolder" and method == "get":
        return ok({"export_folder": ensure_export_dir()})
    if api == "SYNO.TPS.Sensor" and method == "get":
        return ok(read_sensor())
    if api == "SYNO.TPS.Sensor" and method == "set":
        write_sensor(params)
        kv_set(conn, "default_detect", "1" if _truth(params.get("default_detect", True)) else "0")
        if _truth(params.get("enable_sensor", True)):
            kv_set(conn, "engine_ui_status", "engine_init")
            conn.commit()
            if not start_engine():
                kv_set(conn, "engine_ui_status", "")
                conn.commit()
        else:
            stop_engine()
            kv_set(conn, "engine_ui_status", "")
            conn.commit()
        return ok(read_sensor())
    if api == "SYNO.TPS.Sensor.Variables" and method == "get":
        return ok(sensor_vars())
    if api == "SYNO.TPS.Signature" and method == "list":
        return signature_classes(conn)
    if api == "SYNO.TPS.Signature.Classification" and method == "list":
        return signature_classes(conn)
    if api == "SYNO.TPS.Signature.Rule" and method == "list":
        return signature_rules(conn, params)
    if api == "SYNO.TPS.Signature.Policy":
        return signature_policy(conn, method, params)
    if api.startswith("SYNO.TPS.Settings.Update"):
        return settings_update(conn, api, method, params)
    if api == "SYNO.TPS.Settings.Storage":
        return settings_storage(conn, method, params)
    if api == "SYNO.TPS.Device":
        return devices(conn, method, params)
    if api == "SYNO.TPS.Statistic.Device":
        return stat_device(conn, method, params)
    if api == "SYNO.TPS.Statistic.Trends" and method == "get":
        return trends(conn, params)
    if api == "SYNO.TPS.Notification":
        return notification(conn, method, params)
    if api == "SYNO.TPS.Notification.Filter":
        return notification_filter(conn, method, params)
    if api == "SYNO.TPS.Backup":
        return backup_api(conn, method, params)
    if api == "SYNO.TPS.Overview" and method == "get":
        return overview(conn)
    if api == "SYNO.TPS.Settings.Map" and method == "get":
        return ok({"key": read_gmaps_key()})
    if api == "SYNO.TPS.Settings.Telegram":
        return settings_telegram(conn, method, params)
    if api == "SYNO.TPS.Settings.Feed":
        return settings_feed(conn, method, params)
    if api == "SYNO.Core.Network.NSM.Device" and method == "get":
        return ok(nsm_device_list())
    if api == "SYNO.Core.SystemDB" and method == "get":
        return ok(systemdb_get())
    if api == "SYNO.Core.ExternalDevice.Storage.USB" and method == "list":
        return ok(usb_list())
    return err(101)


def read_gmaps_key():
    path = GMAPS_KEY
    if not os.path.isfile(path):
        return ""
    try:
        raw = open(path, encoding="utf-8", errors="replace").read().strip()
    except OSError:
        return ""
    if not raw or raw.startswith("#") or " " in raw or len(raw) < 8:
        return ""
    return raw.splitlines()[0].strip()


def fetch_osm_tile(z, x, y):
    """Same-origin OSM tile for DSM CSP (img-src 'self'). Cache under var/osm-cache."""
    try:
        z, x, y = int(z), int(x), int(y)
    except (TypeError, ValueError):
        return None
    if z < 0 or z > 18:
        return None
    n = 1 << z
    if y < 0 or y >= n:
        return None
    x = x % n
    cache = os.path.join(PKGVAR, "osm-cache", str(z), str(x), "%s.png" % y)
    if os.path.isfile(cache) and os.path.getsize(cache) > 64:
        try:
            return open(cache, "rb").read()
        except OSError:
            pass
    url = "https://tile.openstreetmap.org/%s/%s/%s.png" % (z, x, y)
    try:
        from urllib.request import Request, urlopen
        req = Request(url)
        req.add_header("User-Agent", "ThreatPrevention-PoC/8.0.6 (Synology DSM tile proxy)")
        with urlopen(req, timeout=12) as resp:
            data = resp.read()
            ctype = (resp.headers.get("Content-Type") or "").lower()
    except Exception:
        return None
    if not data or len(data) < 64:
        return None
    if ctype and "png" not in ctype and "octet-stream" not in ctype:
        return None
    try:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        tmp = cache + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, cache)
    except OSError:
        pass
    return data


def event_list(conn, p):
    offset = int(p.get("offset", 0) or 0)
    limit = min(int(p.get("limit", 50) or 50), 200)
    where = ["1=1"]
    args = []
    keywords = flatten_keywords(p.get("key_words"))
    if keywords:
        where.append("(sig_name LIKE ? OR ip_src_str LIKE ? OR ip_dst_str LIKE ?)")
        q = "%" + keywords + "%"
        args.extend([q, q, q])
    if p.get("sig_sid"):
        where.append("sig_sid=?")
        args.append(int(p["sig_sid"]))
    sev = severity_num(p.get("severity"))
    if sev is not None:
        where.append("impact_flag=?")
        args.append(sev)
    if p.get("ip_src"):
        where.append("(ip_src_str=? OR ip_src=?)")
        args.extend([p["ip_src"], ip_to_int(p["ip_src"])])
    if p.get("ip_dst"):
        where.append("(ip_dst_str=? OR ip_dst=?)")
        args.extend([p["ip_dst"], ip_to_int(p["ip_dst"])])
    begin = to_epoch(p.get("begin"))
    finish = to_epoch(p.get("finish") or p.get("end"))
    if begin is not None:
        where.append("ts_epoch>=?")
        args.append(begin)
    elif p.get("date_range") == "7days":
        where.append("ts_epoch>=?")
        args.append(int(time.time()) - 7 * 86400)
    elif p.get("date_range") == "30days":
        where.append("ts_epoch>=?")
        args.append(int(time.time()) - 30 * 86400)
    if finish is not None:
        where.append("ts_epoch<=?")
        args.append(finish)
    sql = "FROM event WHERE " + " AND ".join(where)
    total = conn.execute("SELECT COUNT(*) n " + sql, args).fetchone()["n"]
    rows = conn.execute(
        "SELECT * " + sql + " ORDER BY ts_epoch DESC, cid DESC LIMIT ? OFFSET ?",
        args + [limit, offset],
    )
    events = [official_event(r, conn, detail=False) for r in rows]
    kv_set(conn, "event_offset", str(offset))
    conn.commit()
    payload = {"events": events, "offset": offset, "total": total, "now": now_str()}
    global EVENT_TASK_SEQ
    EVENT_TASK_SEQ += 1
    tid = str(EVENT_TASK_SEQ)
    EVENT_TASKS[tid] = payload
    while len(EVENT_TASKS) > 32:
        EVENT_TASKS.pop(next(iter(EVENT_TASKS)))
    # Official JS only reads task_id here, then polls list_status.
    return ok({"task_id": tid})


def event_list_status(p):
    tid = str(p.get("task_id") or "")
    data = EVENT_TASKS.get(tid)
    if data is None:
        return ok({"finish": True, "status": "ready", "total": 0, "data": {"events": [], "total": 0, "now": now_str()}})
    return ok({"finish": True, "status": "ready", "total": data.get("total", 0), "data": data})


def event_offset(conn, p):
    cid = parse_event_id(p)
    if cid:
        row = conn.execute(
            """SELECT COUNT(*) n FROM event
               WHERE ts_epoch > (SELECT ts_epoch FROM event WHERE cid=?)
                  OR (ts_epoch = (SELECT ts_epoch FROM event WHERE cid=?) AND cid > ?)""",
            (cid, cid, cid),
        ).fetchone()
        return ok({"offset": int(row["n"] if row else 0)})
    return ok({"offset": int(kv_get(conn, "event_offset", "0") or 0)})


def event_get(conn, p):
    cid = parse_event_id(p)
    row = conn.execute("SELECT * FROM event WHERE cid=?", (cid,)).fetchone()
    if not row:
        return err(100)
    return ok(official_event(row, conn, detail=True))


def event_stat(conn, p):
    since = 0
    if p.get("date_range") == "7days":
        since = int(time.time()) - 7 * 86400
    elif p.get("date_range") == "30days":
        since = int(time.time()) - 30 * 86400
    args = []
    where = "1=1"
    if since:
        where = "ts_epoch>=?"
        args = [since]
    total = conn.execute("SELECT COUNT(*) n FROM event WHERE " + where, args).fetchone()["n"]
    high = conn.execute("SELECT COUNT(*) n FROM event WHERE %s AND impact_flag=1" % where, args).fetchone()["n"]
    medium = conn.execute("SELECT COUNT(*) n FROM event WHERE %s AND impact_flag=2" % where, args).fetchone()["n"]
    low = conn.execute("SELECT COUNT(*) n FROM event WHERE %s AND (impact_flag>=3 OR impact_flag<1)" % where, args).fetchone()["n"]
    top_class = [
        {"name": r["sig_class_name"], "count": r["n"]}
        for r in conn.execute(
            """SELECT c.sig_class_name, COUNT(*) n FROM event e
               JOIN sig_class c ON c.sig_class_id=e.sig_class_id
               WHERE """ + where.replace("ts_epoch", "e.ts_epoch") + """
               GROUP BY c.sig_class_id ORDER BY n DESC LIMIT 5""",
            args,
        )
    ]
    top_src = [{"ip": r["ip_src_str"], "count": r["n"]} for r in conn.execute(
        "SELECT ip_src_str, COUNT(*) n FROM event WHERE " + where + " GROUP BY ip_src_str ORDER BY n DESC LIMIT 5", args)]
    top_dst = [{"ip": r["ip_dst_str"], "count": r["n"]} for r in conn.execute(
        "SELECT ip_dst_str, COUNT(*) n FROM event WHERE " + where + " GROUP BY ip_dst_str ORDER BY n DESC LIMIT 5", args)]
    official = official_event_statistic(conn)
    official.update({"total": total, "high": high, "medium": medium, "low": low, "top_class": top_class, "top_src": top_src, "top_dst": top_dst})
    return ok(official)


def sensor_vars():
    out = {
        "HOME_NET": "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]",
        "EXTERNAL_NET": "!$HOME_NET",
        "HTTP_PORTS": "80",
        "SSH_PORTS": "22",
    }
    if os.path.isfile(YAML_PATH):
        section = None
        with open(YAML_PATH, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "address-groups:" in line:
                    section = "addr"
                elif "port-groups:" in line:
                    section = "port"
                elif line.strip() and not line.startswith(" ") and not line.startswith("\t"):
                    if section and not line.strip().startswith("#"):
                        section = None
                if ":" in line and section:
                    k, v = line.split(":", 1)
                    k, v = k.strip(), v.strip().strip('"')
                    if k and v and not k.startswith("#"):
                        out[k] = v
    return official_variables(out)


def signature_classes(conn):
    if conn.execute("SELECT COUNT(*) n FROM signature").fetchone()["n"] == 0:
        import_rules(conn)
    rows = []
    for r in conn.execute(
        """SELECT c.*, COALESCE(p.action,'alert') AS action
           FROM sig_class c LEFT JOIN policy_class p ON p.sig_class_id=c.sig_class_id
           ORDER BY c.sig_priority, c.sig_class_name"""
    ):
        rows.append({
            "sig_class_id": r["sig_class_id"],
            "name": r["sig_class_name"],
            "class_name": r["sig_class_name"],
            "description": r["sig_class_description"],
            "severity": r["sig_priority"],
            "total": r["sig_total_count"],
            "enabled": r["sig_enabled_count"],
            "action": r["action"],
        })
    return ok(official_signature_classes(rows))


def signature_rules(conn, p):
    if conn.execute("SELECT COUNT(*) n FROM signature").fetchone()["n"] == 0:
        import_rules(conn)
    offset = int(p.get("offset", 0) or 0)
    limit = min(int(p.get("limit", 50) or 50), 200)
    where = ["1=1"]
    args = []
    if p.get("sig_class_id"):
        where.append("s.sig_class_id=?")
        args.append(int(p["sig_class_id"]))
    if p.get("name") and not p.get("sig_class_id"):
        where.append("c.sig_class_name=?")
        args.append(p["name"])
    if p.get("key_words"):
        where.append("(s.sig_name LIKE ? OR CAST(s.sig_sid AS TEXT) LIKE ?)")
        q = "%" + p["key_words"] + "%"
        args.extend([q, q])
    sql = (
        "FROM signature s JOIN sig_class c ON c.sig_class_id=s.sig_class_id "
        "LEFT JOIN policy_signature ps ON ps.raw_sid=s.sig_sid WHERE " + " AND ".join(where)
    )
    total = conn.execute("SELECT COUNT(*) n " + sql, args).fetchone()["n"]
    rules = []
    for r in conn.execute(
        "SELECT s.*, c.sig_class_name, COALESCE(ps.action, s.sig_action) AS eff "
        + sql + " ORDER BY s.sig_sid LIMIT ? OFFSET ?",
        args + [limit, offset],
    ):
        raw = r["sig_raw_rule"] or ""
        ip_src, port_src, ip_dst, port_dst = parse_header(raw)
        if (r["sig_ip_src"] or "") not in ("", "any"):
            ip_src = r["sig_ip_src"]
        if (r["sig_ip_dst"] or "") not in ("", "any"):
            ip_dst = r["sig_ip_dst"]
        if (r["sig_port_src"] or "") not in ("", "any"):
            port_src = r["sig_port_src"]
        if (r["sig_port_dst"] or "") not in ("", "any"):
            port_dst = r["sig_port_dst"]
        refs = parse_refs(raw)
        if not refs and r["sig_ref"]:
            for part in str(r["sig_ref"]).split(";"):
                if "," not in part:
                    continue
                system, tag = part.split(",", 1)
                refs.append({"ref_system_name": system.strip().lower(), "ref_tag": tag.strip()})
        msg = r["sig_name"] or ""
        rules.append({
            "sig_sid": r["sig_sid"],
            "sid": r["sig_sid"],
            "sig_rev": r["sig_rev"],
            "sig_name": msg,
            "name": msg,
            "msg": base64.b64encode(msg.encode("utf-8")).decode("ascii"),
            "encode": True,
            "action": r["eff"],
            "sig_class_id": r["sig_class_id"],
            "class_name": r["sig_class_name"],
            "sig_protocol": r["sig_protocol"],
            "ip_proto": r["sig_protocol"] or "ip",
            "ip_src": ip_src or "any",
            "ip_dst": ip_dst or "any",
            "port_src": port_src or "any",
            "port_dst": port_dst or "any",
            "references": refs,
        })
    return ok({"rules": rules, "total": total})


def signature_policy(conn, method, p):
    if method == "list":
        items = []
        for r in conn.execute(
            """SELECT p.sig_class_id, p.action, p.comment, c.sig_class_name
               FROM policy_class p JOIN sig_class c ON c.sig_class_id=p.sig_class_id"""
        ):
            items.append({
                "type": "class", "raw_sid": 0, "sig_class_id": r["sig_class_id"],
                "sig_name": r["sig_class_name"], "action": r["action"],
                "ip_src": 0, "ip_dst": 0, "comment": r["comment"],
            })
        for r in conn.execute("SELECT * FROM policy_signature"):
            items.append({
                "type": "signature", "raw_sid": r["raw_sid"], "sig_class_id": r["sig_class_id"],
                "sig_name": r["sig_name"], "action": r["action"],
                "ip_src": 0, "ip_dst": 0, "comment": r["comment"],
            })
        for r in conn.execute("SELECT * FROM policy_filter"):
            items.append({
                "type": "filter", "raw_sid": r["raw_sid"], "sig_class_id": r["sig_class_id"],
                "sig_name": r["sig_name"], "action": r["action"],
                "ip_src": r["ip_src"], "ip_dst": r["ip_dst"],
                "ip_src_str": r["ip_src_str"], "ip_dst_str": r["ip_dst_str"],
                "comment": r["comment"], "id": r["id"],
            })
        for rec in items:
            if rec["type"] == "class":
                rec["severity"] = severity_name(0, 2)
            else:
                rec["severity"] = "medium"
        return ok(official_policy_list(items))
    if method == "get":
        return signature_policy(conn, "list", p)
    if method in ("add", "set", "update"):
        if p.get("policy"):
            _apply_policy_batch(conn, p["policy"])
            conn.commit()
            compile_rules(conn)
            reload_suricata()
            return ok(official_policy_write(False))
        need_force, applied = _policy_add_or_update(conn, method, p)
        if not applied:
            return ok(official_policy_write(True))
        conn.commit()
        compile_rules(conn)
        reload_suricata()
        return ok(official_policy_write(need_force))
    if method == "delete":
        if p.get("classes") or p.get("signatures"):
            for cls in p.get("classes") or []:
                name = cls.get("class_name") if isinstance(cls, dict) else str(cls)
                row = conn.execute("SELECT sig_class_id FROM sig_class WHERE sig_class_name=?", (name,)).fetchone()
                if row:
                    conn.execute("DELETE FROM policy_class WHERE sig_class_id=?", (row["sig_class_id"],))
            for sig in p.get("signatures") or []:
                sid = int(sig.get("sid") or sig.get("raw_sid") or 0) if isinstance(sig, dict) else int(sig or 0)
                ip_src = (sig.get("ip_src") or "") if isinstance(sig, dict) else ""
                ip_dst = (sig.get("ip_dst") or "") if isinstance(sig, dict) else ""
                if ip_src or ip_dst:
                    conn.execute(
                        "DELETE FROM policy_filter WHERE raw_sid=? AND ip_src_str=? AND ip_dst_str=?",
                        (sid, ip_src, ip_dst),
                    )
                else:
                    conn.execute("DELETE FROM policy_signature WHERE raw_sid=?", (sid,))
                    conn.execute("DELETE FROM policy_filter WHERE raw_sid=?", (sid,))
        else:
            typ = p.get("type") or "signature"
            if typ == "class" or typ == 1 or typ == "1":
                conn.execute("DELETE FROM policy_class WHERE sig_class_id=?", (int(p.get("sig_class_id") or 0),))
            elif typ == "filter" or typ == 3 or typ == "3":
                conn.execute("DELETE FROM policy_filter WHERE id=?", (int(p.get("id") or 0),))
            else:
                conn.execute("DELETE FROM policy_signature WHERE raw_sid=?", (int(p.get("raw_sid") or p.get("sig_sid") or p.get("sid") or 0),))
        conn.commit()
        compile_rules(conn)
        reload_suricata()
        return ok({})
    return err(102)


def _class_id_by_name(conn, name):
    row = conn.execute("SELECT sig_class_id FROM sig_class WHERE sig_class_name=?", (name,)).fetchone()
    return row["sig_class_id"] if row else 0


def _map_policy_action(action):
    a = (action or "alert").lower()
    if a in ("enabled", "enable", "alert"):
        return "alert"
    if a in ("disabled", "disable", "do_nothing"):
        return "disable"
    if a in ("drop", "pass"):
        return a
    return a or "alert"


def _norm_ip(value):
    text = str(value or "").strip()
    if text.lower() in ("", "any", "0", "0.0.0.0"):
        return ""
    return text


def _has_ip_filter(p):
    return bool(_norm_ip(p.get("ip_src") or p.get("ip_src_str")) or _norm_ip(p.get("ip_dst") or p.get("ip_dst_str")))


def _sig_meta(conn, sid):
    row = conn.execute(
        "SELECT sig_class_id, sig_name FROM signature WHERE sig_sid=?",
        (int(sid or 0),),
    ).fetchone()
    if not row:
        return 0, ""
    return row["sig_class_id"], row["sig_name"] or ""


def _policy_row_exists(conn, sid, ip_src, ip_dst):
    if ip_src or ip_dst:
        return bool(conn.execute(
            "SELECT id FROM policy_filter WHERE raw_sid=? AND ip_src_str=? AND ip_dst_str=?",
            (sid, ip_src, ip_dst),
        ).fetchone())
    if conn.execute("SELECT raw_sid FROM policy_signature WHERE raw_sid=?", (sid,)).fetchone():
        return True
    return bool(conn.execute("SELECT id FROM policy_filter WHERE raw_sid=?", (sid,)).fetchone())


def _delete_policy_row(conn, sid, ip_src, ip_dst):
    if ip_src or ip_dst:
        conn.execute(
            "DELETE FROM policy_filter WHERE raw_sid=? AND ip_src_str=? AND ip_dst_str=?",
            (sid, ip_src, ip_dst),
        )
        return
    conn.execute("DELETE FROM policy_signature WHERE raw_sid=?", (sid,))
    conn.execute("DELETE FROM policy_filter WHERE raw_sid=?", (sid,))


def _policy_add_or_update(conn, method, p):
    sid = int(p.get("sid") or p.get("raw_sid") or p.get("sig_sid") or 0)
    ip_src = _norm_ip(p.get("ip_src") or p.get("ip_src_str"))
    ip_dst = _norm_ip(p.get("ip_dst") or p.get("ip_dst_str"))
    force = _truth(p.get("force"))
    old_sid = int(p.get("old_sid") or 0) if method == "update" else 0
    old_ip_src = _norm_ip(p.get("old_ip_src")) if method == "update" else ""
    old_ip_dst = _norm_ip(p.get("old_ip_dst")) if method == "update" else ""
    same_as_old = method == "update" and sid == old_sid and ip_src == old_ip_src and ip_dst == old_ip_dst
    conflict = _policy_row_exists(conn, sid, ip_src, ip_dst) and not same_as_old
    if conflict and not force:
        return True, False
    if method == "update" and old_sid:
        _delete_policy_row(conn, old_sid, old_ip_src, old_ip_dst)
    if force:
        _delete_policy_row(conn, sid, ip_src, ip_dst)
    _apply_policy_item(conn, p)
    return False, True


def _apply_policy_item(conn, p):
    action = _map_policy_action(p.get("action") or "alert")
    comment = p.get("comment") or ""
    sid = int(p.get("raw_sid") or p.get("sig_sid") or p.get("sid") or 0)
    typ = p.get("type")
    if typ in (None, "", 0):
        if _has_ip_filter(p):
            typ = "filter"
        elif sid:
            typ = "signature"
        else:
            typ = "class"
    if typ in ("class", 1, "1") or (p.get("class_name") and not sid and typ != "filter"):
        cid = int(p.get("sig_class_id") or 0) or _class_id_by_name(conn, p.get("class_name") or p.get("name") or "")
        if cid:
            conn.execute("INSERT OR REPLACE INTO policy_class(sig_class_id, action, comment) VALUES (?,?,?)", (cid, action, comment))
        return
    cid, name = _sig_meta(conn, sid)
    cid = int(p.get("sig_class_id") or 0) or cid
    name = p.get("sig_name") or p.get("name") or name
    if typ in ("filter", 3, "3") or _has_ip_filter(p):
        ip_src = _norm_ip(p.get("ip_src_str") or p.get("ip_src"))
        ip_dst = _norm_ip(p.get("ip_dst_str") or p.get("ip_dst"))
        conn.execute(
            """INSERT INTO policy_filter(raw_sid, filter_sid, filter_rev, sig_class_id, sig_name, action, ip_src, ip_dst, ip_src_str, ip_dst_str, comment)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                sid, 0, 0, cid, name, action,
                ip_to_int(ip_src), ip_to_int(ip_dst), ip_src, ip_dst, comment,
            ),
        )
        return
    conn.execute(
        "INSERT OR REPLACE INTO policy_signature(raw_sid, sig_class_id, sig_name, action, comment) VALUES (?,?,?,?,?)",
        (sid, cid, name, action, comment),
    )


def _apply_policy_batch(conn, policy):
    """Official Policy.set: [{class_name, action: enabled|disabled, signatures: [...]}]."""
    for item in policy or []:
        if not isinstance(item, dict):
            continue
        action = _map_policy_action(item.get("action") or "")
        name = item.get("class_name") or item.get("name") or ""
        if name and item.get("action") not in ("", None):
            _apply_policy_item(conn, {"type": "class", "class_name": name, "action": action, "comment": item.get("comment") or ""})
        for sig in item.get("signatures") or []:
            if not isinstance(sig, dict):
                continue
            _apply_policy_item(conn, {
                "type": "signature",
                "sid": sig.get("sid") or sig.get("raw_sid") or sig.get("sig_sid"),
                "sig_class_id": sig.get("sig_class_id") or 0,
                "sig_name": sig.get("sig_name") or sig.get("name") or "",
                "action": sig.get("action") or action or "alert",
                "comment": sig.get("comment") or "",
            })


def settings_update(conn, api, method, p):
    if api == "SYNO.TPS.Settings.Update.Schedule":
        if method == "get":
            stored = kv_get(conn, "update_minute", "120")
            hour = kv_get(conn, "update_hour", "")
            minute = kv_get(conn, "update_min_of_hour", "")
            if hour == "" or minute == "":
                try:
                    combined = int(stored or 120)
                except ValueError:
                    combined = 120
                hour, minute = combined // 60, combined % 60
            return ok({
                "auto_update": kv_get(conn, "auto_update") == "1",
                "weekday": kv_get(conn, "update_weekday", "daily"),
                "hour": int(hour or 2),
                "minute": int(minute or 0),
                "schedule_minute": int(stored or 120) if str(stored).isdigit() else stored,
            })
        if method == "set":
            kv_set(conn, "auto_update", "1" if _truth(p.get("auto_update")) else "0")
            if "weekday" in p:
                kv_set(conn, "update_weekday", p["weekday"])
            if "hour" in p or "minute" in p:
                try:
                    hour = int(p.get("hour") if p.get("hour") not in (None, "") else kv_get(conn, "update_hour", "2") or 2)
                except ValueError:
                    hour = 2
                try:
                    minute = int(p.get("minute") if p.get("minute") not in (None, "") else kv_get(conn, "update_min_of_hour", "0") or 0)
                except ValueError:
                    minute = 0
                kv_set(conn, "update_hour", str(hour))
                kv_set(conn, "update_min_of_hour", str(minute))
                kv_set(conn, "update_minute", str(hour * 60 + minute))
            conn.commit()
            return ok({})
    if api == "SYNO.TPS.Settings.Update.Source":
        if method == "get":
            return ok(official_source(kv_get(conn, "update_source", "et-open"), kv_get(conn, "etpro_code", "")))
        if method == "set":
            use = str(p.get("use_code") or p.get("source") or "et-open")
            if use in ("etPro", "et-pro", "etpro"):
                kv_set(conn, "update_source", "et-pro")
            else:
                kv_set(conn, "update_source", "et-open")
            if "code" in p:
                kv_set(conn, "etpro_code", p.get("code") or "")
            conn.commit()
            write_update_source(
                kv_get(conn, "update_source", "et-open"),
                kv_get(conn, "etpro_code", ""),
            )
            return ok({})
    if api == "SYNO.TPS.Settings.Update":
        if method == "status":
            job = job_get(p.get("task_id"))
            status = (job or {}).get("status") or kv_get(conn, "update_status", "up_to_date")
            return ok(official_update_status(
                status,
                kv_get(conn, "last_updated", ""),
                kv_get(conn, "remote_version", ""),
                str(p.get("task_id") or ""),
            ))
        if method == "start_check":
            tid = start_job({"status": "checking"})
            kv_set(conn, "update_status", "checking")
            conn.commit()

            def _check():
                c = connect()
                try:
                    src = kv_get(c, "update_source", "et-open")
                    code = kv_get(c, "etpro_code", "")
                    if src == "et-pro" and not code:
                        kv_set(c, "update_status", "etpro_error")
                        JOBS[tid]["status"] = "etpro_error"
                        c.commit()
                        return
                    marker = os.path.join(PKGVAR, "rules", ".from-suricata-update")
                    last = kv_get(c, "last_updated", "")
                    ever = os.path.isfile(marker) or bool(last)
                    reachable, newer = probe_rule_update(last, src, code)
                    status = classify_update(ever, reachable, newer)
                    kv_set(c, "update_status", status)
                    c.commit()
                    JOBS[tid]["status"] = status
                except Exception:
                    kv_set(c, "update_status", "connect_error")
                    JOBS[tid]["status"] = "connect_error"
                    c.commit()
                finally:
                    c.close()

            threading.Thread(target=_check, daemon=True).start()
            return ok({"task_id": tid, "status": "checking"})
        if method == "start_update":
            tid = start_job({"status": "updating"})
            kv_set(conn, "update_status", "updating")
            kv_set(conn, "engine_ui_status", "updating_signature")
            conn.commit()

            def _run():
                c = connect()
                try:
                    src = kv_get(c, "update_source", "et-open")
                    code = kv_get(c, "etpro_code", "")
                    write_update_source(src, code)
                    if src == "et-pro" and not code:
                        kv_set(c, "update_status", "etpro_error")
                        kv_set(c, "engine_ui_status", "")
                        JOBS[tid]["status"] = "etpro_error"
                        c.commit()
                        return
                    kv_set(c, "engine_ui_status", "updating_signature")
                    c.commit()
                    rc = subprocess.call(["/bin/sh", UPDATE_SCRIPT], timeout=600)
                    if rc == 0:
                        kv_set(c, "engine_ui_status", "build_signature_database")
                        c.commit()
                        import_rules(c)
                        compile_rules(c)
                        reload_suricata()
                        kv_set(c, "update_status", "up_to_date")
                        kv_set(c, "last_updated", time.strftime("%Y-%m-%d %H:%M:%S"))
                        JOBS[tid]["status"] = "up_to_date"
                    elif rc == 2:
                        kv_set(c, "update_status", "etpro_error")
                        JOBS[tid]["status"] = "etpro_error"
                    else:
                        kv_set(c, "update_status", "connect_error")
                        JOBS[tid]["status"] = "connect_error"
                    kv_set(c, "engine_ui_status", "")
                    c.commit()
                except Exception:
                    kv_set(c, "update_status", "connect_error")
                    kv_set(c, "engine_ui_status", "")
                    JOBS[tid]["status"] = "connect_error"
                    c.commit()
                finally:
                    c.close()

            threading.Thread(target=_run, daemon=True).start()
            return ok({"task_id": tid, "status": "updating"})
    return err(102)


def _storage_limit(p):
    raw = p.get("db_size") if p.get("db_size") not in (None, "") else p.get("limit")
    if raw in (None, ""):
        raw = 500
    if isinstance(raw, str):
        raw = raw.strip().strip('"')
    if raw in ("db_size_500mb", "500"):
        return 500
    if raw in ("db_size_1gb", "1024"):
        return 1024
    if raw in ("db_size_2gb", "2048"):
        return 2048
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return 500
    return n if n in (500, 1024, 2048) else 500


def _storage_limit_mb(raw):
    return _storage_limit({"db_size": raw})


def settings_storage(conn, method, p):
    db = os.path.join(PKGVAR, "tps.db")
    size = os.path.getsize(db) if os.path.isfile(db) else 0
    limit = _storage_limit_mb(kv_get(conn, "storage_limit_mb", "500"))
    if method == "get":
        return ok(official_storage(size, limit, kv_get(conn, "clear_status", "idle"), usb_max=usb_max_label()))
    if method == "set":
        limit = _storage_limit(p)
        kv_set(conn, "storage_limit_mb", str(limit))
        conn.commit()
        return ok(official_storage(size, limit, kv_get(conn, "clear_status", "idle"), usb_max=usb_max_label()))
    if method in ("clear_log", "start_clear_log"):
        tid = start_job({"status": "clearing", "clear_percentage": 0})
        kv_set(conn, "clear_status", "clearing")
        conn.commit()

        def _clear():
            c = connect()
            try:
                JOBS[tid]["clear_percentage"] = 10
                clear_events(c)
                JOBS[tid]["status"] = "cleared"
                JOBS[tid]["clear_percentage"] = 100
            except Exception:
                JOBS[tid]["status"] = "idle"
            finally:
                c.close()

        threading.Thread(target=_clear, daemon=True).start()
        return ok({"task_id": tid, "status": "clearing", "data": {"status": "clearing", "clear_percentage": 0}})
    if method == "status_clear_log":
        job = job_get(p.get("task_id")) or {}
        status = job.get("status") or kv_get(conn, "clear_status", "idle")
        percent = job.get("clear_percentage", 100 if status == "cleared" else 0)
        return ok({"status": status, "clear_percentage": percent, "data": {"status": status, "clear_percentage": percent}})
    return err(102)


def devices(conn, method, p):
    online = set()
    default_detect = 1 if kv_get(conn, "default_detect", "1") == "1" else 0
    for rec in list_neighbors():
        mac = rec.get("mac") or ""
        if not mac:
            continue
        if rec.get("is_online"):
            online.add(mac)
        name = rec.get("hostname") or rec.get("ip") or mac
        conn.execute(
            "INSERT OR IGNORE INTO device(mac, device_name, detect, loading_score) VALUES (?,?,?,0)",
            (mac, name, default_detect),
        )
        row = conn.execute("SELECT device_name FROM device WHERE mac=?", (mac,)).fetchone()
        if row and row["device_name"] in (mac, rec.get("ip") or "") and rec.get("hostname"):
            conn.execute("UPDATE device SET device_name=? WHERE mac=?", (rec["hostname"], mac))
    conn.commit()
    if method == "list":
        conn.execute(
            """UPDATE device SET loading_score = COALESCE((
                 SELECT COUNT(*) FROM event e WHERE lower(e.mac_src)=lower(device.mac)
               ), 0)"""
        )
        conn.commit()
        out = []
        for r in conn.execute("SELECT * FROM device ORDER BY device_name"):
            out.append({
                "mac": r["mac"],
                "device_name": r["device_name"],
                "detect": bool(r["detect"]),
                "loading_score": r["loading_score"],
                "loading": r["loading_score"],
                "online": r["mac"].lower() in online,
            })
        return ok(official_devices(out, kv_get(conn, "default_detect", "1") == "1"))
    if method == "set":
        if "default_detect" in p:
            kv_set(conn, "default_detect", "1" if _truth(p.get("default_detect")) else "0")
        for item in p.get("device_list") or []:
            if not isinstance(item, dict):
                continue
            mac = (item.get("mac") or "").lower()
            if not mac:
                continue
            detect = 1 if _truth(item.get("detect", True)) else 0
            name = item.get("device_name") or mac
            conn.execute(
                "INSERT OR REPLACE INTO device(mac, device_name, detect, loading_score) VALUES (?,?,?,0)",
                (mac, name, detect),
            )
        mac = (p.get("mac") or "").lower()
        if mac:
            detect = 1 if _truth(p.get("detect", True)) else 0
            name = p.get("device_name")
            if name:
                conn.execute("INSERT OR REPLACE INTO device(mac, device_name, detect, loading_score) VALUES (?,?,?,0)", (mac, name, detect))
            else:
                conn.execute("UPDATE device SET detect=? WHERE mac=?", (detect, mac))
        conn.commit()
        return ok({})
    return err(102)


def stat_device(conn, method, p):
    if method == "list":
        rows = [
            {"ip": r["ip_src_str"], "count": r["n"], "mac": r["mac_src"], "device_name": r["mac_src"] or r["ip_src_str"]}
            for r in conn.execute(
                """SELECT ip_src_str, mac_src, COUNT(*) n FROM event
                   WHERE ts_epoch>=? GROUP BY ip_src_str ORDER BY n DESC LIMIT ?"""
                ,
                (int(time.time()) - 7 * 86400, int(p.get("limit") or 20)),
            )
        ]
        return ok({"devices": [
            dict(r, name=r["device_name"], loading=r.get("count") or 0) for r in rows
        ]})
    if method == "get":
        ip = p.get("ip") or ""
        n = conn.execute("SELECT COUNT(*) n FROM event WHERE ip_src_str=?", (ip,)).fetchone()["n"]
        return ok({"ip": ip, "count": n})
    return err(102)


def trends(conn, p):
    now = int(time.time())
    start = now - 7 * 86400
    bucket = 8 * 3600
    points = []
    t = start - (start % bucket)
    while t < now:
        rows = conn.execute(
            """SELECT
                 SUM(CASE WHEN impact_flag=1 THEN 1 ELSE 0 END) AS high,
                 SUM(CASE WHEN impact_flag=2 THEN 1 ELSE 0 END) AS medium,
                 SUM(CASE WHEN impact_flag>=3 OR impact_flag<1 THEN 1 ELSE 0 END) AS low,
                 COUNT(*) AS total
               FROM event WHERE ts_epoch>=? AND ts_epoch<?""",
            (t, t + bucket),
        ).fetchone()
        points.append({
            "ts": t,
            "high": rows["high"] or 0,
            "medium": rows["medium"] or 0,
            "low": rows["low"] or 0,
            "total": rows["total"] or 0,
        })
        t += bucket
    return ok(official_trends(conn))


def notification(conn, method, p):
    keys = (
        "enable_notification", "enable_mail", "enable_push", "enable_sms",
        "min_interval_mail", "min_interval_push", "min_interval_sms", "subject_prefix",
    )
    if method == "get":
        data = {k: kv_get(conn, k) for k in keys}
        for k in keys:
            if k.startswith("enable_"):
                data[k] = data[k] == "1"
            elif k.startswith("min_"):
                data[k] = int(data[k] or 5)
        return ok(data)
    if method == "set":
        for k in keys:
            if k not in p:
                continue
            v = p[k]
            if k.startswith("enable_"):
                v = "1" if _truth(v) else "0"
            kv_set(conn, k, v)
        conn.commit()
        return ok({})
    return err(102)


def notification_filter(conn, method, p):
    if method == "list":
        return ok({"notification_filters": list_filters(conn)})
    if method == "set":
        upsert_filters(conn, p.get("notification_filters") or [])
        conn.commit()
        return ok({})
    return err(102)


def settings_telegram(conn, method, p):
    if method == "get":
        cfg = read_telegram_conf()
        return ok({
            "enable_telegram": kv_get(conn, "enable_telegram", "0") == "1",
            "follow_mail": kv_get(conn, "telegram_follow_mail", "1") == "1",
            "min_interval_telegram": int(kv_get(conn, "min_interval_telegram", "300") or 300),
            "has_token": bool(cfg.get("token")),
            "chat_id": cfg.get("chat") or "",
            "token": "",
        })
    if method == "set":
        if "enable_telegram" in p:
            kv_set(conn, "enable_telegram", "1" if _truth(p.get("enable_telegram")) else "0")
        if "follow_mail" in p or "telegram_follow_mail" in p:
            kv_set(conn, "telegram_follow_mail", "1" if _truth(p.get("follow_mail", p.get("telegram_follow_mail"))) else "0")
        if "min_interval_telegram" in p:
            try:
                kv_set(conn, "min_interval_telegram", str(max(0, int(p.get("min_interval_telegram") or 300))))
            except (TypeError, ValueError):
                kv_set(conn, "min_interval_telegram", "300")
        token = p.get("token") or p.get("bot_token")
        chat = p.get("chat_id") if "chat_id" in p else p.get("chat")
        if token or chat is not None:
            write_telegram_conf(token if token else None, chat)
        conn.commit()
        return ok({})
    if method == "test":
        cfg = read_telegram_conf()
        token = (p.get("token") or "").strip() or cfg.get("token")
        chat = (p.get("chat_id") or p.get("chat") or "").strip() or cfg.get("chat")
        if not token or not chat:
            return err(100)
        prefix = kv_get(conn, "subject_prefix", "Threat Prevention") or "Threat Prevention"
        if send_telegram(token, chat, "%s\nThreat Prevention Telegram test" % prefix):
            return ok({"sent": True})
        return err(104)
    return err(102)


def settings_feed(conn, method, p):
    if method == "list":
        return ok({"feeds": list_feeds(conn)})
    if method == "add":
        fid = add_feed(conn, p.get("name"), p.get("url"), _truth(p.get("enabled", True)))
        if not fid:
            return err(100)
        conn.commit()
        write_feeds_json(conn)
        return ok({"id": fid})
    if method == "update":
        try:
            fid = int(p.get("id") or 0)
        except (TypeError, ValueError):
            return err(100)
        enabled = None
        if "enabled" in p:
            enabled = _truth(p.get("enabled"))
        if not update_feed(conn, fid, p.get("name"), p.get("url"), enabled):
            return err(100)
        conn.commit()
        write_feeds_json(conn)
        return ok({})
    if method == "delete":
        try:
            fid = int(p.get("id") or 0)
        except (TypeError, ValueError):
            return err(100)
        delete_feed(conn, fid)
        conn.commit()
        write_feeds_json(conn)
        return ok({})
    return err(102)


def backup_api(conn, method, p):
    if method == "backup":
        return ok({"json": backup_json(conn), "format": "json"})
    if method == "restore":
        raw = p.get("json") or p.get("data") or p.get("dss_file") or ""
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError:
                return err(100)
        raw = (raw or "").strip()
        if not raw or raw[0] not in "{[":
            return err(100)
        restore_json(conn, raw)
        compile_rules(conn)
        reload_suricata()
        return ok({})
    return err(102)


def _parse_multipart(body, ctype):
    import re
    fields, files = {}, {}
    match = re.search(r"boundary=([^;]+)", ctype or "", re.I)
    if not match:
        return fields, files
    boundary = match.group(1).strip().strip('"')
    sep = b"--" + boundary.encode("ascii", "replace")
    for part in body.split(sep):
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        head, _, data = part.partition(b"\r\n\r\n")
        if data.endswith(b"--"):
            data = data[:-2]
        data = data.rstrip(b"\r\n")
        header = head.decode("utf-8", "replace")
        name_m = re.search(r'name="([^"]+)"', header)
        if not name_m:
            continue
        name = name_m.group(1)
        if "filename=" in header:
            files[name] = data
        else:
            fields[name] = data.decode("utf-8", "replace")
    return fields, files


def overview(conn):
    sensor = read_sensor()
    st = event_stat(conn, {"date_range": "7days"})["data"]
    rules = "suricata-update" if os.path.isfile(os.path.join(PKGVAR, "rules", ".from-suricata-update")) else "bundled"
    return ok({
        "sensor": sensor,
        "stats": st,
        "rules": rules,
        "last_updated": kv_get(conn, "last_updated", ""),
        "update_status": kv_get(conn, "update_status", "up_to_date"),
    })


def _schedule_due(conn, now):
    if kv_get(conn, "auto_update") != "1":
        return False
    weekday = kv_get(conn, "update_weekday", "daily")
    minute = kv_get(conn, "update_minute", "120")
    last = kv_get(conn, "last_auto_update_slot", "")
    lt = time.localtime(now)
    if str(weekday) not in ("daily", "", "None"):
        try:
            want = int(weekday)
        except ValueError:
            want = None
        # Official UI uses Sunday=0; Python tm_wday is Monday=0.
        sun0 = (lt.tm_wday + 1) % 7
        if want is not None and want not in (sun0, lt.tm_wday):
            return False
    if str(minute) == "hourly":
        slot = time.strftime("%Y%m%d%H", lt)
    else:
        try:
            target = int(minute)
        except ValueError:
            target = 120
        now_min = lt.tm_hour * 60 + lt.tm_min
        if now_min < target or now_min >= target + 2:
            return False
        slot = time.strftime("%Y%m%d", lt) + ":" + str(target)
    if last == slot:
        return False
    kv_set(conn, "last_auto_update_slot", slot)
    conn.commit()
    return True


def scheduler_loop():
    while not STOP:
        time.sleep(30)
        if STOP:
            return
        conn = None
        try:
            conn = connect()
            if _schedule_due(conn, time.time()):
                kv_set(conn, "update_status", "updating")
                conn.commit()
                rc = subprocess.call(["/bin/sh", UPDATE_SCRIPT], timeout=600)
                if rc == 0:
                    import_rules(conn)
                    compile_rules(conn)
                    reload_suricata()
                    kv_set(conn, "update_status", "up_to_date")
                    kv_set(conn, "last_updated", time.strftime("%Y-%m-%d %H:%M:%S"))
                else:
                    kv_set(conn, "update_status", "connect_error")
                conn.commit()
        except Exception:
            pass
        finally:
            if conn is not None:
                conn.close()


def authorized(handler):
    # 3rdparty UI is admin-gated. Require a DSM session cookie or local peer.
    addr = getattr(handler, "client_address", None)
    if not addr or isinstance(addr, str):
        return True
    peer = addr[0] if isinstance(addr, (list, tuple)) else str(addr)
    if peer in ("127.0.0.1", "::1", ""):
        return True
    cookie = handler.headers.get("Cookie") or ""
    if "id=" in cookie or "smid=" in cookie or "_sid=" in cookie:
        return True
    if handler.headers.get("X-SYNO-TOKEN") or "SynoToken=" in (handler.path or ""):
        return True
    # LAN open for the DSM-hosted SPA (port differs; cookie may be SameSite-blocked)
    if peer.startswith("192.168.") or peer.startswith("10.") or peer.startswith("172."):
        return True
    return False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.address_string(), fmt % args))

    def _cors(self):
        origin = self.headers.get("Origin") or "*"
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-SYNO-TOKEN, X-Requested-With")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def _dispatch(self):
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        pre_qs = parse_qs(parsed.query)
        # POST / is the nginx proxy_pass target. Only GET / is the old SPA.
        if self.command == "GET" and path in ("/", "/index.html") and not pre_qs.get("api"):
            return self._static("index.html", "text/html; charset=utf-8")
        if path == "/app.js":
            return self._static("app.js", "application/javascript; charset=utf-8")
        if path == "/app.css":
            return self._static("app.css", "text/css; charset=utf-8")
        if path.startswith("/images/"):
            return self._static(path.lstrip("/"), "image/png")
        osm = re.match(r"^/osm/(\d+)/(\d+)/(\d+)\.png$", path)
        if self.command == "GET" and osm:
            if not authorized(self):
                return self._json(err(403), 403)
            return self._png(fetch_osm_tile(osm.group(1), osm.group(2), osm.group(3)))
        qs = parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if body:
            ctype = self.headers.get("Content-Type") or ""
            if "multipart/form-data" in ctype:
                fields, files = _parse_multipart(body, ctype)
                for k, v in fields.items():
                    qs[k] = [v]
                for k, v in files.items():
                    qs[k] = [v]
            elif "json" in ctype:
                try:
                    extra = json.loads(body.decode("utf-8") or "{}")
                    for k, v in extra.items():
                        qs.setdefault(k, [v if not isinstance(v, (dict, list)) else json.dumps(v)])
                except ValueError:
                    pass
            else:
                for k, v in parse_qs(body.decode("utf-8", "replace")).items():
                    qs[k] = v
        params = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}
        api = params.get("api") or ""
        method = params.get("method") or ""
        api_paths = (
            "/", "/api", "/webapi",
            "/webman/tps-api",
            "/webman/3rdparty/ThreatPrevention/api",
        )
        if path.rstrip("/") in api_paths or api:
            if not authorized(self):
                return self._json(err(403), 403)
            if not api:
                return self._json(err(100))
            if api == "SYNO.TPS.Settings.Map" and method == "tile":
                return self._png(fetch_osm_tile(params.get("z"), params.get("x"), params.get("y")))
            conn = init_db()
            try:
                result = handle(api, method, params, conn)
            except Exception as exc:
                result = err(500, {"message": str(exc)})
            finally:
                conn.close()
            if api == "SYNO.TPS.Backup" and method == "backup" and result.get("success"):
                body = (result.get("data") or {}).get("json") or "{}"
                raw = body.encode("utf-8") if isinstance(body, str) else body
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", "attachment; filename=\"threatprevention-backup.json\"")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            return self._json(result)
        self.send_response(404)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, obj, status=200):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _png(self, data):
        if not data:
            self.send_response(404)
            self._cors()
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "image/png")
        self.send_header("Cache-Control", "public, max-age=86400")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _static(self, name, ctype):
        root = os.path.join(PKGDEST, "ui")
        full = os.path.normpath(os.path.join(root, name))
        if not full.startswith(os.path.normpath(root)):
            self.send_response(403)
            self.end_headers()
            return
        if not os.path.isfile(full):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = open(full, "rb").read()
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def server_bind(self):
        if os.path.exists(self.server_address):
            os.remove(self.server_address)
        socketserver.UnixStreamServer.server_bind(self)


def run():
    os.makedirs(PKGVAR, exist_ok=True)
    with open(TPSWEB_PID, "w") as fh:
        fh.write(str(os.getpid()))
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    init_db()
    ensure_export_dir()
    threading.Thread(target=scheduler_loop, daemon=True).start()
    tcp = ThreadingHTTPServer(("0.0.0.0", TPSWEB_PORT), Handler)
    threads = [threading.Thread(target=tcp.serve_forever, daemon=True)]
    try:
        if os.path.exists(SOCK_PATH):
            os.remove(SOCK_PATH)
        unix = UnixHTTPServer(SOCK_PATH, Handler)
        os.chmod(SOCK_PATH, 0o660)
        threads.append(threading.Thread(target=unix.serve_forever, daemon=True))
    except OSError:
        unix = None
    for t in threads:
        t.start()
    sys.stderr.write("tpsweb on :%s and %s\n" % (TPSWEB_PORT, SOCK_PATH))
    try:
        while not STOP:
            time.sleep(0.5)
    finally:
        tcp.shutdown()
        if unix:
            unix.shutdown()
        try:
            os.remove(TPSWEB_PID)
        except OSError:
            pass
        try:
            os.remove(SOCK_PATH)
        except OSError:
            pass


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    run()
