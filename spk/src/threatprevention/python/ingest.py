#!/usr/bin/env python3
"""Tail eve.json and insert alerts into SQLite."""
import base64
import json
import os
import signal
import sys
import time

from paths import EVE_PATH, INGEST_PID, PKGVAR
from store import connect, init_db, ip_to_int, kv_get, rotate_if_needed

STOP = False


def _handle_stop(signum, frame):
    global STOP
    STOP = True


def fingerprint(obj):
    alert = obj.get("alert") or {}
    return "%s|%s|%s|%s|%s|%s" % (
        obj.get("timestamp", ""),
        alert.get("signature_id", ""),
        obj.get("src_ip", ""),
        obj.get("dest_ip", ""),
        obj.get("src_port", ""),
        obj.get("dest_port", ""),
    )


def proto_num(name):
    return {"TCP": 6, "UDP": 17, "ICMP": 1, "IPV6-ICMP": 58}.get((name or "").upper(), 0)


def payload_hex(obj):
    raw = obj.get("payload")
    if raw:
        try:
            return base64.b64decode(raw).hex()
        except (ValueError, TypeError):
            text = str(raw)
            if text and len(text) % 2 == 0:
                try:
                    int(text, 16)
                    return text
                except ValueError:
                    pass
            return text.encode("utf-8", "replace").hex()
    printable = obj.get("payload_printable") or ""
    return printable.encode("utf-8", "replace").hex() if printable else ""


def _int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def class_id(conn, classtype):
    if not classtype:
        classtype = "unknown"
    row = conn.execute("SELECT sig_class_id FROM sig_class WHERE sig_class_name=?", (classtype,)).fetchone()
    if row:
        return row["sig_class_id"], row["sig_class_id"]
    conn.execute(
        "INSERT INTO sig_class(sig_class_name, sig_class_description, sig_priority) VALUES (?,?,3)",
        (classtype, classtype),
    )
    cid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    return cid, cid


def insert_alert(conn, obj):
    if obj.get("event_type") != "alert":
        return False
    alert = obj.get("alert") or {}
    fp = fingerprint(obj)
    if conn.execute("SELECT cid FROM event WHERE eve_fingerprint=?", (fp,)).fetchone():
        return False
    classtype = alert.get("category") or alert.get("classtype") or "unknown"
    # eve uses "category" as description sometimes; prefer signature classtype if present
    sc_id, _ = class_id(conn, (alert.get("metadata") or {}).get("classtype", [classtype])[0] if isinstance((alert.get("metadata") or {}).get("classtype"), list) else classtype)
    prio = alert.get("severity") or 3
    src = obj.get("src_ip") or ""
    dst = obj.get("dest_ip") or ""
    ether = obj.get("ether") or {}
    ts = obj.get("timestamp") or ""
    try:
        epoch = int(time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")))
    except (ValueError, OverflowError):
        epoch = int(time.time())
    proto = proto_num(obj.get("proto"))
    cur = conn.execute(
        """INSERT INTO event(sid, mac_src, mac_dst, sig_sid, sig_rev, sig_class_id, sig_name, timestamp, ts_epoch,
           impact_flag, action, ip_src, ip_dst, ip_src_str, ip_dst_str, port_src, port_dst, ip_proto, eve_fingerprint)
           VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ether.get("src_mac") or obj.get("src_mac") or "",
            ether.get("dest_mac") or obj.get("dest_mac") or "",
            int(alert.get("signature_id") or 0),
            int(alert.get("rev") or 0),
            sc_id,
            alert.get("signature") or "",
            ts.replace("T", " ")[:19],
            epoch,
            int(prio),
            alert.get("action") or "allowed",
            ip_to_int(src),
            ip_to_int(dst),
            src,
            dst,
            int(obj.get("src_port") or 0),
            int(obj.get("dest_port") or 0),
            proto,
            fp,
        ),
    )
    cid = cur.lastrowid
    ipo = obj.get("ip") or {}
    conn.execute(
        """INSERT OR REPLACE INTO iphdr(sid, cid, ip_src, ip_dst, ip_ver, ip_hlen, ip_tos, ip_len, ip_id, ip_ttl, ip_proto)
           VALUES (1,?,?,?,?,?,?,?,?,?,?)""",
        (
            cid, ip_to_int(src), ip_to_int(dst), 6 if ":" in src else 4,
            _int(ipo.get("ihl") or ipo.get("hdr_len")), _int(ipo.get("tos")),
            _int(ipo.get("ip_len") or obj.get("pkt_len") or ipo.get("len")),
            _int(ipo.get("id")), _int(ipo.get("ttl")), proto,
        ),
    )
    if proto == 6:
        tcp = obj.get("tcp") or {}
        flags = tcp.get("tcp_flags") or tcp.get("flags") or 0
        if isinstance(flags, str):
            flags = _int(flags, 0)
        conn.execute(
            """INSERT OR REPLACE INTO tcphdr(sid, cid, tcp_sport, tcp_dport, tcp_seq, tcp_ack, tcp_off, tcp_flags, tcp_win)
               VALUES (1,?,?,?,?,?,?,?,?)""",
            (
                cid, int(obj.get("src_port") or 0), int(obj.get("dest_port") or 0),
                _int(tcp.get("seq") or tcp.get("tcp_seq")),
                _int(tcp.get("ack") or tcp.get("tcp_ack")),
                _int(tcp.get("data_off") or tcp.get("tcp_off")),
                flags,
                _int(tcp.get("window") or tcp.get("tcp_win")),
            ),
        )
    elif proto == 17:
        udp = obj.get("udp") or {}
        conn.execute(
            "INSERT OR REPLACE INTO udphdr(sid, cid, udp_sport, udp_dport, udp_len) VALUES (1,?,?,?,?)",
            (cid, int(obj.get("src_port") or 0), int(obj.get("dest_port") or 0), _int(udp.get("len") or udp.get("udp_len"))),
        )
    elif proto in (1, 58):
        icmp = obj.get("icmp") or {}
        conn.execute(
            "INSERT OR REPLACE INTO icmphdr(sid, cid, icmp_type, icmp_code, icmp_id, icmp_seq) VALUES (1,?,?,?,?,?)",
            (
                cid, int(icmp.get("type") or 0), int(icmp.get("code") or 0),
                _int(icmp.get("id") or icmp.get("icmp_id")), _int(icmp.get("seq") or icmp.get("icmp_seq")),
            ),
        )
    payload = payload_hex(obj)
    if payload:
        conn.execute("INSERT OR REPLACE INTO data(sid, cid, data_payload) VALUES (1,?,?)", (cid, payload[:8192]))
    mac = ether.get("src_mac") or obj.get("src_mac") or ""
    if mac:
        name = src or mac
        detect = 1 if kv_get(conn, "default_detect", "1") == "1" else 0
        conn.execute(
            "INSERT OR IGNORE INTO device(mac, device_name, detect, loading_score) VALUES (?,?,?,0)",
            (mac, name, detect),
        )
        conn.execute("UPDATE device SET loading_score = loading_score + 1 WHERE lower(mac)=lower(?)", (mac,))
    return True


def follow(path):
    offset_file = os.path.join(PKGVAR, "ingest.offset")
    pos = 0
    if os.path.isfile(offset_file):
        try:
            pos = int(open(offset_file).read().strip() or "0")
        except ValueError:
            pos = 0
    while not STOP:
        if not os.path.isfile(path):
            time.sleep(1)
            continue
        size = os.path.getsize(path)
        if pos > size:
            pos = 0
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(pos)
            while not STOP:
                line = fh.readline()
                if not line:
                    pos = fh.tell()
                    break
                yield line
                pos = fh.tell()
        try:
            with open(offset_file, "w") as of:
                of.write(str(pos))
        except OSError:
            pass
        time.sleep(0.5)


def run():
    os.makedirs(PKGVAR, exist_ok=True)
    with open(INGEST_PID, "w") as fh:
        fh.write(str(os.getpid()))
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    conn = init_db()
    last_rotate = 0
    try:
        for line in follow(EVE_PATH):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            try:
                if insert_alert(conn, obj):
                    conn.commit()
            except Exception:
                conn.rollback()
            now = time.time()
            if now - last_rotate > 300:
                rotate_if_needed(conn)
                last_rotate = now
    finally:
        conn.close()
        try:
            os.remove(INGEST_PID)
        except OSError:
            pass


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    run()
