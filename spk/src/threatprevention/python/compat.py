"""Official ExtJS response shapes for SYNO.TPS.* (research compatibility layer).

The community contract in docs/api/SYNO.TPS.contract.md is the simplified
rebuild. Official synoips.js reads different keys, types, and (for Event.list)
an async task_id / list_status handshake. This module maps the SQLite +
Suricata 8 store onto those official envelopes so vanilla Suricata can drive
the Synology app.
"""
import json
import os
import time

from paths import IFACE_FILE, SENSOR_CONF


POLICY_TYPE_CLASS = 1
POLICY_TYPE_SIGNATURE = 2
POLICY_TYPE_FILTER = 3

SEVERITY_NAME = {1: "high", 2: "medium", 3: "low"}


def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def coerce_params(params):
    """JSON-decode official array/object query params (policy, key_words, …)."""
    out = dict(params)
    for key, val in list(out.items()):
        if not isinstance(val, str):
            continue
        text = val.strip()
        if not text or text[0] not in "[{":
            continue
        try:
            out[key] = json.loads(text)
        except ValueError:
            pass
    if "key_words" in out:
        out["key_words"] = flatten_keywords(out["key_words"])
    if "end" in out and "finish" not in out:
        out["finish"] = out["end"]
    return out


def flatten_keywords(value):
    if value is None:
        return ""
    if isinstance(value, list):
        parts = [str(x).strip() for x in value if str(x).strip()]
        return " ".join(parts)
    return str(value)


def severity_name(flag, class_priority=3):
    n = int(flag or 0)
    if n in (1, 2, 3):
        return SEVERITY_NAME[n]
    p = int(class_priority or 3)
    if p <= 1:
        return "high"
    if p == 2:
        return "medium"
    return "low"


def parse_event_id(params):
    raw = params.get("id") or params.get("cid") or 0
    if isinstance(raw, str) and "-" in raw:
        parts = raw.rsplit("-", 1)
        try:
            return int(parts[-1])
        except ValueError:
            return 0
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def official_event(row, conn, detail=False):
    class_name = ""
    class_prio = 3
    cr = conn.execute(
        "SELECT sig_class_name, sig_priority FROM sig_class WHERE sig_class_id=?",
        (row["sig_class_id"],),
    ).fetchone()
    if cr:
        class_name = cr["sig_class_name"] or ""
        class_prio = cr["sig_priority"]
    sev = severity_name(row["impact_flag"], class_prio)
    ip_src = row["ip_src_str"] or ""
    ip_dst = row["ip_dst_str"] or ""
    action = (row["action"] or "alert").lower()
    data = {
        "sid": row["sid"],
        "cid": row["cid"],
        "timestamp": row["timestamp"],
        "ts_epoch": row["ts_epoch"],
        "sig_sid": row["sig_sid"],
        "sig_rev": row["sig_rev"],
        "sig_name": row["sig_name"],
        "sig_class_id": row["sig_class_id"],
        "sig_class_name": class_name,
        "severity": sev,
        "action": action,
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "ip_src_str": ip_src,
        "ip_dst_str": ip_dst,
        "port_src": row["port_src"],
        "port_dst": row["port_dst"],
        "ip_proto": str(row["ip_proto"] or 0),
        "mac_src": row["mac_src"] or "",
        "mac_dst": row["mac_dst"] or "",
        "device_src": row["mac_src"] or "",
        "device_dst": row["mac_dst"] or "",
        "payload": "",
        "references": [],
    }
    if not detail:
        return data
    cid = row["cid"]
    iph = conn.execute("SELECT * FROM iphdr WHERE cid=?", (cid,)).fetchone()
    if iph:
        data.update({
            "ip_ver": iph["ip_ver"],
            "ip_hlen": iph["ip_hlen"],
            "ip_tos": iph["ip_tos"],
            "ip_len": iph["ip_len"],
            "ip_id": iph["ip_id"],
            "ip_flags": iph["ip_flags"],
            "ip_off": iph["ip_off"],
            "ip_ttl": iph["ip_ttl"],
            "ip_csum": iph["ip_csum"],
            "iphdr": dict(iph),
        })
        if iph["ip_proto"]:
            data["ip_proto"] = str(iph["ip_proto"])
    else:
        data["iphdr"] = {}
    tcp = conn.execute("SELECT * FROM tcphdr WHERE cid=?", (cid,)).fetchone()
    data["tcphdr"] = dict(tcp) if tcp else {}
    if tcp:
        data.update({
            "tcp_seq": tcp["tcp_seq"],
            "tcp_ack": tcp["tcp_ack"],
            "tcp_off": tcp["tcp_off"],
            "tcp_res": tcp["tcp_res"],
            "tcp_flags": tcp["tcp_flags"],
            "tcp_win": tcp["tcp_win"],
            "tcp_csum": tcp["tcp_csum"],
            "tcp_urp": tcp["tcp_urp"],
        })
    udp = conn.execute("SELECT * FROM udphdr WHERE cid=?", (cid,)).fetchone()
    data["udphdr"] = dict(udp) if udp else {}
    if udp:
        data["udp_len"] = udp["udp_len"]
        data["udp_csum"] = udp["udp_csum"]
    icmp = conn.execute("SELECT * FROM icmphdr WHERE cid=?", (cid,)).fetchone()
    data["icmphdr"] = dict(icmp) if icmp else {}
    if icmp:
        data.update({
            "icmp_type": icmp["icmp_type"],
            "icmp_code": icmp["icmp_code"],
            "icmp_csum": icmp["icmp_csum"],
            "icmp_id": icmp["icmp_id"],
            "icmp_seq": icmp["icmp_seq"],
        })
    payload = conn.execute("SELECT data_payload FROM data WHERE cid=?", (cid,)).fetchone()
    raw = (payload["data_payload"] if payload else "") or ""
    data["data_payload"] = raw
    data["payload"] = raw if _looks_hex(raw) else raw.encode("utf-8", "replace").hex()
    return data


def _looks_hex(text):
    if not text or len(text) % 2:
        return False
    try:
        int(text, 16)
        return True
    except ValueError:
        return False


def official_sensor(cfg, status, pid, iface):
    ifaces = []
    raw = cfg.get("interface_list") or iface or ""
    if isinstance(raw, list):
        ifaces = raw
    else:
        for part in str(raw).replace(",", " ").split():
            ifaces.append({"if_id": part, "ifname": part, "enabled": True})
    if status == "running":
        eng = "engine_start"
    elif status in ("starting", "engine_init"):
        eng = "engine_init"
    elif status == "failed":
        eng = "failed"
    else:
        eng = status if status and status not in ("stopped",) else ""
    exist = os.path.isfile(SENSOR_CONF) or os.path.isfile(IFACE_FILE)
    return {
        "enable_sensor": cfg.get("enable_sensor", True),
        "enable_prevention": cfg.get("enable_prevention", False),
        "enable_auto_export_events_during_postupgrade": cfg.get(
            "enable_auto_export_events_during_postupgrade", False
        ),
        "network_security_mode": cfg.get("network_security_mode") or "availability",
        "default_detect": cfg.get("default_detect", True),
        "interface_list": ifaces,
        "interfaceList": ifaces,
        "config_exist": exist,
        "sensor_config_exist": exist,
        "status": eng,
        "pid": pid,
    }


def official_variables(raw):
    """Official JS reads lowercase Suricata vars (home_net, http_ports, …)."""
    out = dict(raw)
    for key, val in list(raw.items()):
        out[key.lower()] = val
    out.setdefault("home_net", raw.get("HOME_NET", "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"))
    out.setdefault("external_net", raw.get("EXTERNAL_NET", "!$HOME_NET"))
    out.setdefault("http_ports", raw.get("HTTP_PORTS", "80"))
    out.setdefault("ssh_ports", raw.get("SSH_PORTS", "22"))
    out.setdefault("sql_servers", raw.get("SQL_SERVERS", "$HOME_NET"))
    out.setdefault("smtp_servers", raw.get("SMTP_SERVERS", "$HOME_NET"))
    out.setdefault("http_servers", raw.get("HTTP_SERVERS", "$HOME_NET"))
    out.setdefault("dns_servers", raw.get("DNS_SERVERS", "$HOME_NET"))
    out.setdefault("aim_servers", raw.get("AIM_SERVERS", "$EXTERNAL_NET"))
    out.setdefault("telnet_servers", raw.get("TELNET_SERVERS", "$HOME_NET"))
    out.setdefault("dnp3_server", raw.get("DNP3_SERVER", "$HOME_NET"))
    out.setdefault("dnp3_client", raw.get("DNP3_CLIENT", "$HOME_NET"))
    out.setdefault("enip_server", raw.get("ENIP_SERVER", "$HOME_NET"))
    out.setdefault("enip_client", raw.get("ENIP_CLIENT", "$HOME_NET"))
    out.setdefault("modbus_server", raw.get("MODBUS_SERVER", "$HOME_NET"))
    return out


def official_signature_classes(rows):
    """SYNO.TPS.Signature.list and Classification.list: {signatures: […]}."""
    items = []
    for r in rows:
        enabled_n = r.get("enabled", 0) or 0
        total = r.get("total", 0) or 0
        action = (r.get("action") or "alert").lower()
        items.append({
            "name": r.get("name") or r.get("class_name") or "",
            "class_name": r.get("class_name") or r.get("name") or "",
            "sig_class_id": r.get("sig_class_id"),
            "description": r.get("description") or "",
            "severity": severity_name(0, r.get("severity") or 3),
            "enabled": action not in ("disable", "disabled", "pass"),
            "enabledCount": enabled_n,
            "totalCount": total,
            "total": total,
            "action": action,
        })
    return {"signatures": items, "classes": items}


def official_policy_list(items):
    out = []
    for i, rec in enumerate(items):
        typ = rec.get("type")
        if typ == "class":
            typ_n = POLICY_TYPE_CLASS
        elif typ == "filter":
            typ_n = POLICY_TYPE_FILTER
        else:
            typ_n = POLICY_TYPE_SIGNATURE
        name = rec.get("sig_name") or rec.get("name") or ""
        out.append({
            "type": typ_n,
            "sid": rec.get("raw_sid") or rec.get("sid") or 0,
            "raw_sid": rec.get("raw_sid") or rec.get("sid") or 0,
            "name": name,
            "class_name": name if typ_n == POLICY_TYPE_CLASS else rec.get("class_name") or "",
            "sig_class_id": rec.get("sig_class_id") or 0,
            "severity": rec.get("severity") or "medium",
            "action": (rec.get("action") or "alert").lower(),
            "ip_src": rec.get("ip_src_str") or rec.get("ip_src") or "",
            "ip_dst": rec.get("ip_dst_str") or rec.get("ip_dst") or "",
            "comment": rec.get("comment") or "",
            "order": rec.get("order", i),
            "id": rec.get("id"),
        })
    return {"list": out, "policy": out}


def official_stat_bucket(conn, since, until=None):
    args = []
    where = "1=1"
    if since:
        where += " AND ts_epoch>=?"
        args.append(since)
    if until:
        where += " AND ts_epoch<=?"
        args.append(until)
    begin = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(since or 0)) if since else "1970-01-01 00:00:00"
    end = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(until or int(time.time())))
    class_name = [
        {"sig_class_name": r["sig_class_name"], "name": r["sig_class_name"], "count": r["n"]}
        for r in conn.execute(
            """SELECT c.sig_class_name, COUNT(*) n FROM event e
               JOIN sig_class c ON c.sig_class_id=e.sig_class_id
               WHERE """ + where.replace("ts_epoch", "e.ts_epoch") + """
               GROUP BY c.sig_class_id ORDER BY n DESC LIMIT 10""",
            args,
        )
    ]
    ip_src = [
        {"ip_src": r["ip_src_str"], "ip": r["ip_src_str"], "count": r["n"]}
        for r in conn.execute(
            "SELECT ip_src_str, COUNT(*) n FROM event WHERE " + where + " GROUP BY ip_src_str ORDER BY n DESC LIMIT 10",
            args,
        )
    ]
    ip_dst = [
        {"ip_dst": r["ip_dst_str"], "ip": r["ip_dst_str"], "count": r["n"]}
        for r in conn.execute(
            "SELECT ip_dst_str, COUNT(*) n FROM event WHERE " + where + " GROUP BY ip_dst_str ORDER BY n DESC LIMIT 10",
            args,
        )
    ]
    return {
        "begin": begin,
        "end": end,
        "class_name": class_name,
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "botnet_ip_src": [],
        "botnet_ip_dst": [],
        "country_src": [],
        "total": sum(x["count"] for x in class_name) if class_name else 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "top_class": [{"name": x["sig_class_name"], "count": x["count"]} for x in class_name[:5]],
        "top_src": [{"ip": x["ip_src"], "count": x["count"]} for x in ip_src[:5]],
        "top_dst": [{"ip": x["ip_dst"], "count": x["count"]} for x in ip_dst[:5]],
    }


def official_event_statistic(conn):
    now = int(time.time())
    days7 = official_stat_bucket(conn, now - 7 * 86400)
    days30 = official_stat_bucket(conn, now - 30 * 86400)
    all_logs = official_stat_bucket(conn, 0)
    for bucket in (days7, days30, all_logs):
        counts = conn.execute(
            """SELECT
                 SUM(CASE WHEN impact_flag=1 THEN 1 ELSE 0 END) AS high,
                 SUM(CASE WHEN impact_flag=2 THEN 1 ELSE 0 END) AS medium,
                 SUM(CASE WHEN impact_flag>=3 OR impact_flag<1 THEN 1 ELSE 0 END) AS low,
                 COUNT(*) AS total
               FROM event WHERE ts_epoch>=?""",
            (int(time.mktime(time.strptime(bucket["begin"], "%Y-%m-%d %H:%M:%S"))) if bucket["begin"] != "1970-01-01 00:00:00" else 0,),
        ).fetchone()
        bucket["high"] = counts["high"] or 0
        bucket["medium"] = counts["medium"] or 0
        bucket["low"] = counts["low"] or 0
        bucket["total"] = counts["total"] or 0
    return {
        "days7": days7,
        "days30": days30,
        "all_logs": all_logs,
        "total": all_logs["total"],
        "high": all_logs["high"],
        "medium": all_logs["medium"],
        "low": all_logs["low"],
        "top_class": all_logs["top_class"],
        "top_src": all_logs["top_src"],
        "top_dst": all_logs["top_dst"],
    }


def official_trends(conn, days=7):
    now = int(time.time())
    start = now - days * 86400
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
        begin = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
        end = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t + bucket))
        points.append({
            "ts": t,
            "begin": begin,
            "end": end,
            "high": rows["high"] or 0,
            "medium": rows["medium"] or 0,
            "low": rows["low"] or 0,
            "total": rows["total"] or 0,
        })
        t += bucket
    return {
        "begin": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start)),
        "end": now_str(),
        "trends": points,
        "points": points,
    }


def official_devices(rows):
    items = []
    for r in rows:
        items.append({
            "mac": r.get("mac") or "",
            "device_name": r.get("device_name") or r.get("mac") or "",
            "detect": bool(r.get("detect", True)),
            "loading": r.get("loading_score") if r.get("loading_score") is not None else r.get("loading") or 0,
            "loading_score": r.get("loading_score") or 0,
            "online": bool(r.get("online")),
        })
    return {"device_list": items, "devices": items}
