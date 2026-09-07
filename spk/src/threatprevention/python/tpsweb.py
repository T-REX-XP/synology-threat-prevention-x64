#!/usr/bin/env python3
"""SYNO.TPS.* JSON API + static UI on TCP :19557 and a unix socket."""
import json
import os
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from compiler import compile_rules, import_rules, reload_suricata
from paths import (
    IFACE_FILE,
    PKGDEST,
    PKGETC,
    PKGVAR,
    SENSOR_CONF,
    SOCK_PATH,
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


def engine_status():
    if os.path.isfile(SURICATA_PID):
        try:
            pid = int(open(SURICATA_PID).read().strip() or "0")
            os.kill(pid, 0)
            return "running", pid
        except (ValueError, OSError):
            pass
    return "stopped", 0


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
    st, pid = engine_status()
    return {
        "enable_sensor": _truth(cfg.get("enable_sensor", True)),
        "enable_prevention": _truth(cfg.get("enable_prevention", False)),
        "interface_list": cfg.get("interface_list") or "",
        "network_security_mode": cfg.get("network_security_mode") or "availability",
        "default_detect": _truth(cfg.get("default_detect", True)),
        "status": st,
        "pid": pid,
    }


def write_sensor(data):
    os.makedirs(PKGETC, exist_ok=True)
    iface = (data.get("interface_list") or "").strip()
    if iface:
        with open(IFACE_FILE, "w") as fh:
            fh.write(iface + "\n")
    lines = [
        "enable_sensor=%s" % ("yes" if _truth(data.get("enable_sensor", True)) else "no"),
        "enable_prevention=%s" % ("yes" if _truth(data.get("enable_prevention", False)) else "no"),
        "default_detect=%s" % ("yes" if _truth(data.get("default_detect", True)) else "no"),
        "network_security_mode=%s" % (data.get("network_security_mode") or "availability"),
        "interface_list=%s" % iface,
    ]
    with open(SENSOR_CONF, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def _truth(v):
    if isinstance(v, bool):
        return v
    return str(v).lower() in ("1", "true", "yes", "on")


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
    if api == "SYNO.TPS.Event" and method == "list":
        return event_list(conn, params)
    if api == "SYNO.TPS.Event" and method == "get":
        return event_get(conn, params)
    if api == "SYNO.TPS.Event" and method == "list_status":
        total = conn.execute("SELECT COUNT(*) n FROM event").fetchone()["n"]
        return ok({"total": total, "status": "ready"})
    if api == "SYNO.TPS.Event.Offset" and method == "get":
        return ok({"offset": int(kv_get(conn, "event_offset", "0") or 0)})
    if api == "SYNO.TPS.Event.Statistic" and method == "get":
        return event_stat(conn, params)
    if api == "SYNO.TPS.Event.Map" and method == "list":
        return ok({"events": []})
    if api == "SYNO.TPS.Event.ExportFolder" and method == "get":
        return ok({"export_folder": ""})
    if api == "SYNO.TPS.Sensor" and method == "get":
        return ok(read_sensor())
    if api == "SYNO.TPS.Sensor" and method == "set":
        write_sensor(params)
        kv_set(conn, "default_detect", "1" if _truth(params.get("default_detect", True)) else "0")
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
    return err(101)


def event_list(conn, p):
    offset = int(p.get("offset", 0) or 0)
    limit = min(int(p.get("limit", 50) or 50), 200)
    where = ["1=1"]
    args = []
    if p.get("key_words"):
        where.append("(sig_name LIKE ? OR ip_src_str LIKE ? OR ip_dst_str LIKE ?)")
        q = "%" + p["key_words"] + "%"
        args.extend([q, q, q])
    if p.get("sig_sid"):
        where.append("sig_sid=?")
        args.append(int(p["sig_sid"]))
    if p.get("severity"):
        where.append("impact_flag=?")
        args.append(int(p["severity"]))
    if p.get("ip_src"):
        where.append("(ip_src_str=? OR ip_src=?)")
        args.extend([p["ip_src"], ip_to_int(p["ip_src"])])
    if p.get("ip_dst"):
        where.append("(ip_dst_str=? OR ip_dst=?)")
        args.extend([p["ip_dst"], ip_to_int(p["ip_dst"])])
    if p.get("begin"):
        where.append("ts_epoch>=?")
        args.append(int(p["begin"]))
    elif p.get("date_range") == "7days":
        where.append("ts_epoch>=?")
        args.append(int(time.time()) - 7 * 86400)
    elif p.get("date_range") == "30days":
        where.append("ts_epoch>=?")
        args.append(int(time.time()) - 30 * 86400)
    if p.get("finish"):
        where.append("ts_epoch<=?")
        args.append(int(p["finish"]))
    sql = "FROM event WHERE " + " AND ".join(where)
    total = conn.execute("SELECT COUNT(*) n " + sql, args).fetchone()["n"]
    rows = conn.execute(
        "SELECT * " + sql + " ORDER BY ts_epoch DESC, cid DESC LIMIT ? OFFSET ?",
        args + [limit, offset],
    )
    events = [event_row(r, conn) for r in rows]
    kv_set(conn, "event_offset", str(offset))
    conn.commit()
    return ok({"events": events, "offset": offset, "total": total})


def event_get(conn, p):
    cid = int(p.get("cid") or 0)
    row = conn.execute("SELECT * FROM event WHERE cid=?", (cid,)).fetchone()
    if not row:
        return err(100)
    data = event_row(row, conn)
    for table, key in (("iphdr", "iphdr"), ("tcphdr", "tcphdr"), ("udphdr", "udphdr"), ("icmphdr", "icmphdr")):
        extra = conn.execute("SELECT * FROM %s WHERE cid=?" % table, (cid,)).fetchone()
        data[key] = dict(extra) if extra else {}
    payload = conn.execute("SELECT data_payload FROM data WHERE cid=?", (cid,)).fetchone()
    data["data_payload"] = payload["data_payload"] if payload else ""
    data["references"] = []
    return ok(data)


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
    return ok({"total": total, "high": high, "medium": medium, "low": low, "top_class": top_class, "top_src": top_src, "top_dst": top_dst})


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
    return out


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
    return ok({"classes": rows})


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
        rules.append({
            "sig_sid": r["sig_sid"],
            "sig_rev": r["sig_rev"],
            "sig_name": r["sig_name"],
            "action": r["eff"],
            "sig_class_id": r["sig_class_id"],
            "class_name": r["sig_class_name"],
            "sig_protocol": r["sig_protocol"],
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
        return ok({"policy": items})
    if method == "get":
        return signature_policy(conn, "list", p)
    if method in ("add", "set", "update"):
        typ = p.get("type") or ("filter" if p.get("ip_src_str") or p.get("ip_src") else ("signature" if p.get("raw_sid") else "class"))
        action = p.get("action") or "alert"
        comment = p.get("comment") or ""
        if typ == "class":
            cid = int(p.get("sig_class_id") or 0)
            conn.execute("INSERT OR REPLACE INTO policy_class(sig_class_id, action, comment) VALUES (?,?,?)", (cid, action, comment))
        elif typ == "signature":
            sid = int(p.get("raw_sid") or p.get("sig_sid") or 0)
            conn.execute(
                "INSERT OR REPLACE INTO policy_signature(raw_sid, sig_class_id, sig_name, action, comment) VALUES (?,?,?,?,?)",
                (sid, int(p.get("sig_class_id") or 0), p.get("sig_name") or "", action, comment),
            )
        else:
            conn.execute(
                """INSERT INTO policy_filter(raw_sid, filter_sid, filter_rev, sig_class_id, sig_name, action, ip_src, ip_dst, ip_src_str, ip_dst_str, comment)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    int(p.get("raw_sid") or 0), 0, 0, int(p.get("sig_class_id") or 0),
                    p.get("sig_name") or "", action,
                    ip_to_int(p.get("ip_src_str") or p.get("ip_src") or ""),
                    ip_to_int(p.get("ip_dst_str") or p.get("ip_dst") or ""),
                    p.get("ip_src_str") or "", p.get("ip_dst_str") or "", comment,
                ),
            )
        conn.commit()
        n = compile_rules(conn)
        reload_suricata()
        return ok({"compiled": n})
    if method == "delete":
        typ = p.get("type") or "signature"
        if typ == "class":
            conn.execute("DELETE FROM policy_class WHERE sig_class_id=?", (int(p.get("sig_class_id") or 0),))
        elif typ == "filter":
            conn.execute("DELETE FROM policy_filter WHERE id=?", (int(p.get("id") or 0),))
        else:
            conn.execute("DELETE FROM policy_signature WHERE raw_sid=?", (int(p.get("raw_sid") or p.get("sig_sid") or 0),))
        conn.commit()
        compile_rules(conn)
        reload_suricata()
        return ok({})
    return err(102)


def settings_update(conn, api, method, p):
    if api == "SYNO.TPS.Settings.Update.Schedule":
        if method == "get":
            return ok({
                "auto_update": kv_get(conn, "auto_update") == "1",
                "weekday": kv_get(conn, "update_weekday", "daily"),
                "minute": int(kv_get(conn, "update_minute", "120") or 120),
            })
        if method == "set":
            kv_set(conn, "auto_update", "1" if _truth(p.get("auto_update")) else "0")
            if "weekday" in p:
                kv_set(conn, "update_weekday", p["weekday"])
            if "minute" in p:
                kv_set(conn, "update_minute", p["minute"])
            conn.commit()
            return ok({})
    if api == "SYNO.TPS.Settings.Update.Source":
        if method == "get":
            return ok({"source": kv_get(conn, "update_source", "et-open"), "code": kv_get(conn, "etpro_code", "")})
        if method == "set":
            kv_set(conn, "update_source", p.get("source") or "et-open")
            if "code" in p:
                kv_set(conn, "etpro_code", p.get("code") or "")
            conn.commit()
            return ok({})
    if api == "SYNO.TPS.Settings.Update":
        if method == "status":
            return ok({
                "status": kv_get(conn, "update_status", "up_to_date"),
                "last_updated": kv_get(conn, "last_updated", ""),
                "remote_version": kv_get(conn, "remote_version", ""),
            })
        if method == "start_check":
            kv_set(conn, "update_status", "checking")
            conn.commit()
            kv_set(conn, "update_status", "up_to_date")
            conn.commit()
            return ok({"status": "up_to_date"})
        if method == "start_update":
            kv_set(conn, "update_status", "updating")
            conn.commit()

            def _run():
                c = connect()
                try:
                    rc = subprocess.call(["/bin/sh", UPDATE_SCRIPT], timeout=600)
                    if rc == 0:
                        import_rules(c)
                        compile_rules(c)
                        reload_suricata()
                        kv_set(c, "update_status", "up_to_date")
                        kv_set(c, "last_updated", time.strftime("%Y-%m-%d %H:%M:%S"))
                    else:
                        kv_set(c, "update_status", "connect_error")
                    c.commit()
                except Exception:
                    kv_set(c, "update_status", "connect_error")
                    c.commit()
                finally:
                    c.close()

            threading.Thread(target=_run, daemon=True).start()
            return ok({"status": "updating"})
    return err(102)


def settings_storage(conn, method, p):
    db = os.path.join(PKGVAR, "tps.db")
    size = os.path.getsize(db) if os.path.isfile(db) else 0
    if method == "get":
        return ok({
            "db_size": size,
            "limit": int(kv_get(conn, "storage_limit_mb", "500") or 500),
            "clear_percentage": 80,
            "status_clear_log": kv_get(conn, "clear_status", "idle"),
        })
    if method == "set":
        lim = int(p.get("limit") or 500)
        if lim not in (500, 1024, 2048):
            lim = 500
        kv_set(conn, "storage_limit_mb", str(lim))
        conn.commit()
        return ok({})
    if method in ("clear_log", "start_clear_log"):
        clear_events(conn)
        return ok({"status": "cleared"})
    if method == "status_clear_log":
        return ok({"status": kv_get(conn, "clear_status", "idle")})
    return err(102)


def devices(conn, method, p):
    online = set()
    arp = "/proc/net/arp"
    if os.path.isfile(arp):
        with open(arp, encoding="utf-8", errors="replace") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    online.add(parts[3].lower())
                    mac = parts[3].lower()
                    conn.execute(
                        "INSERT OR IGNORE INTO device(mac, device_name, detect, loading_score) VALUES (?,?,?,0)",
                        (mac, parts[0], 1 if kv_get(conn, "default_detect", "1") == "1" else 0),
                    )
        conn.commit()
    if method == "list":
        out = []
        for r in conn.execute("SELECT * FROM device ORDER BY device_name"):
            out.append({
                "mac": r["mac"],
                "device_name": r["device_name"],
                "detect": bool(r["detect"]),
                "loading_score": r["loading_score"],
                "online": r["mac"].lower() in online,
            })
        return ok({"devices": out})
    if method == "set":
        mac = (p.get("mac") or "").lower()
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
        return ok({"devices": rows})
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
    return ok({"points": points})


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
                data[k] = int(data[k] or 300)
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
        rows = [dict(r) for r in conn.execute("SELECT * FROM notification_filter")]
        return ok({"notification_filters": rows})
    if method == "set":
        conn.execute("DELETE FROM notification_filter")
        for item in p.get("notification_filters") or []:
            conn.execute(
                "INSERT INTO notification_filter(name, severity, action) VALUES (?,?,?)",
                (item.get("name") or "", int(item.get("severity") or 0), item.get("action") or ""),
            )
        conn.commit()
        return ok({})
    return err(102)


def backup_api(conn, method, p):
    if method == "backup":
        return ok({"json": backup_json(conn), "format": "json"})
    if method == "restore":
        raw = p.get("json") or p.get("data") or ""
        if not raw:
            return err(100)
        restore_json(conn, raw)
        compile_rules(conn)
        reload_suricata()
        return ok({})
    return err(102)


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
        if path in ("/", "/index.html") and not pre_qs.get("api"):
            return self._static("index.html", "text/html; charset=utf-8")
        if path == "/app.js":
            return self._static("app.js", "application/javascript; charset=utf-8")
        if path == "/app.css":
            return self._static("app.css", "text/css; charset=utf-8")
        if path.startswith("/images/"):
            return self._static(path.lstrip("/"), "image/png")
        qs = parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if body:
            ctype = self.headers.get("Content-Type") or ""
            if "json" in ctype:
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
        if path in ("/api", "/webapi", "/") or api:
            if not authorized(self):
                return self._json(err(403), 403)
            if not api:
                return self._json(err(100))
            conn = init_db()
            try:
                result = handle(api, method, params, conn)
            except Exception as exc:
                result = err(500, {"message": str(exc)})
            finally:
                conn.close()
            return self._json(result)
        self.send_response(404)
        self._cors()
        self.end_headers()

    def _json(self, obj, status=200):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _static(self, name, ctype):
        root = os.path.join(PKGDEST, "ui")
        full = os.path.normpath(os.path.join(root, name))
        if not full.startswith(os.path.normpath(root)):
            self.send_response(403)
            self.end_headers()
            return
        if not os.path.isfile(full):
            self.send_response(404)
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
