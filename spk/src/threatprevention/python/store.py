"""SQLite store (Barnyard2-derived schema, SQLite types)."""
import ipaddress
import json
import os
import sqlite3
import time

from paths import CLASSIFICATION, DB_PATH, PKGVAR, SIGNATURE_CONF


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_info (
    vseq INTEGER PRIMARY KEY,
    ctime TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sig_class (
    sig_class_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sig_class_name TEXT NOT NULL UNIQUE,
    sig_class_description TEXT NOT NULL DEFAULT '',
    sig_total_count INTEGER NOT NULL DEFAULT 0,
    sig_enabled_count INTEGER NOT NULL DEFAULT 0,
    sig_priority INTEGER NOT NULL DEFAULT 3
);
CREATE TABLE IF NOT EXISTS signature (
    sig_sid INTEGER NOT NULL,
    sig_rev INTEGER NOT NULL,
    sig_name TEXT NOT NULL,
    sig_class_id INTEGER NOT NULL,
    sig_default_action TEXT NOT NULL DEFAULT 'alert',
    sig_action TEXT NOT NULL DEFAULT 'alert',
    sig_protocol TEXT NOT NULL DEFAULT 'ip',
    sig_ip_src TEXT NOT NULL DEFAULT 'any',
    sig_ip_dst TEXT NOT NULL DEFAULT 'any',
    sig_port_src TEXT NOT NULL DEFAULT 'any',
    sig_port_dst TEXT NOT NULL DEFAULT 'any',
    sig_noalert INTEGER NOT NULL DEFAULT 0,
    sig_ref TEXT NOT NULL DEFAULT '',
    sig_raw_rule TEXT NOT NULL DEFAULT '',
    sig_using INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (sig_sid, sig_rev)
);
CREATE TABLE IF NOT EXISTS event (
    sid INTEGER NOT NULL DEFAULT 1,
    cid INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_src TEXT NOT NULL DEFAULT '',
    mac_dst TEXT NOT NULL DEFAULT '',
    sig_sid INTEGER NOT NULL DEFAULT 0,
    sig_rev INTEGER NOT NULL DEFAULT 0,
    sig_class_id INTEGER NOT NULL DEFAULT 0,
    sig_name TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    ts_epoch INTEGER,
    impact_flag INTEGER NOT NULL DEFAULT -1,
    action TEXT NOT NULL DEFAULT 'alert',
    ip_src INTEGER NOT NULL DEFAULT 0,
    ip_dst INTEGER NOT NULL DEFAULT 0,
    ip_src_str TEXT NOT NULL DEFAULT '',
    ip_dst_str TEXT NOT NULL DEFAULT '',
    port_src INTEGER NOT NULL DEFAULT 0,
    port_dst INTEGER NOT NULL DEFAULT 0,
    ip_proto INTEGER NOT NULL DEFAULT 0,
    eve_fingerprint TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS event_fp ON event(eve_fingerprint);
CREATE INDEX IF NOT EXISTS event_ts ON event(ts_epoch);
CREATE INDEX IF NOT EXISTS event_sig ON event(sig_sid);
CREATE TABLE IF NOT EXISTS iphdr (
    sid INTEGER NOT NULL,
    cid INTEGER NOT NULL,
    ip_src INTEGER NOT NULL DEFAULT 0,
    ip_dst INTEGER NOT NULL DEFAULT 0,
    ip_ver INTEGER,
    ip_hlen INTEGER,
    ip_tos INTEGER,
    ip_len INTEGER,
    ip_id INTEGER,
    ip_flags INTEGER,
    ip_off INTEGER,
    ip_ttl INTEGER,
    ip_proto INTEGER NOT NULL DEFAULT 0,
    ip_csum INTEGER,
    PRIMARY KEY (sid, cid)
);
CREATE TABLE IF NOT EXISTS tcphdr (
    sid INTEGER NOT NULL,
    cid INTEGER NOT NULL,
    tcp_sport INTEGER NOT NULL DEFAULT 0,
    tcp_dport INTEGER NOT NULL DEFAULT 0,
    tcp_seq INTEGER,
    tcp_ack INTEGER,
    tcp_off INTEGER,
    tcp_res INTEGER,
    tcp_flags INTEGER NOT NULL DEFAULT 0,
    tcp_win INTEGER,
    tcp_csum INTEGER,
    tcp_urp INTEGER,
    PRIMARY KEY (sid, cid)
);
CREATE TABLE IF NOT EXISTS udphdr (
    sid INTEGER NOT NULL,
    cid INTEGER NOT NULL,
    udp_sport INTEGER NOT NULL DEFAULT 0,
    udp_dport INTEGER NOT NULL DEFAULT 0,
    udp_len INTEGER,
    udp_csum INTEGER,
    PRIMARY KEY (sid, cid)
);
CREATE TABLE IF NOT EXISTS icmphdr (
    sid INTEGER NOT NULL,
    cid INTEGER NOT NULL,
    icmp_type INTEGER NOT NULL DEFAULT 0,
    icmp_code INTEGER NOT NULL DEFAULT 0,
    icmp_csum INTEGER,
    icmp_id INTEGER,
    icmp_seq INTEGER,
    PRIMARY KEY (sid, cid)
);
CREATE TABLE IF NOT EXISTS data (
    sid INTEGER NOT NULL,
    cid INTEGER NOT NULL,
    data_payload TEXT,
    PRIMARY KEY (sid, cid)
);
CREATE TABLE IF NOT EXISTS device (
    mac TEXT PRIMARY KEY,
    device_name TEXT NOT NULL DEFAULT '',
    detect INTEGER NOT NULL DEFAULT 1,
    loading_score INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS policy_class (
    sig_class_id INTEGER PRIMARY KEY,
    action TEXT NOT NULL,
    comment TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS policy_signature (
    raw_sid INTEGER PRIMARY KEY,
    sig_class_id INTEGER NOT NULL DEFAULT 0,
    sig_name TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    comment TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS policy_filter (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_sid INTEGER NOT NULL,
    filter_sid INTEGER NOT NULL DEFAULT 0,
    filter_rev INTEGER NOT NULL DEFAULT 0,
    sig_class_id INTEGER NOT NULL DEFAULT 0,
    sig_name TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    ip_src INTEGER NOT NULL DEFAULT 0,
    ip_dst INTEGER NOT NULL DEFAULT 0,
    ip_src_str TEXT NOT NULL DEFAULT '',
    ip_dst_str TEXT NOT NULL DEFAULT '',
    comment TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS notification_filter (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    severity INTEGER NOT NULL DEFAULT 0,
    action TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS rule_feed (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created INTEGER NOT NULL DEFAULT 0
);
"""

DEFAULTS = {
    "storage_limit_mb": "500",
    "enable_notification": "0",
    "enable_mail": "0",
    "enable_push": "0",
    "enable_sms": "0",
    "enable_telegram": "0",
    "telegram_follow_mail": "1",
    "min_interval_mail": "300",
    "min_interval_push": "300",
    "min_interval_sms": "300",
    "min_interval_telegram": "300",
    "subject_prefix": "Threat Prevention",
    "auto_update": "0",
    "update_weekday": "daily",
    "update_minute": "120",
    "update_source": "et-open",
    "etpro_code": "",
    "update_status": "up_to_date",
    "last_updated": "",
    "remote_version": "",
    "clear_status": "idle",
    "event_offset": "0",
    "default_detect": "1",
    "engine_ui_status": "",
    "last_auto_update_slot": "",
}


def connect(path=None):
    os.makedirs(os.path.dirname(path or DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(path or DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(path=None):
    os.makedirs(PKGVAR, exist_ok=True)
    conn = connect(path)
    conn.executescript(SCHEMA_SQL)
    if conn.execute("SELECT COUNT(*) FROM schema_info").fetchone()[0] == 0:
        conn.execute("INSERT INTO schema_info(vseq, ctime) VALUES (107, datetime('now'))")
    for k, v in DEFAULTS.items():
        conn.execute("INSERT OR IGNORE INTO kv(k, v) VALUES (?, ?)", (k, v))
    conn.commit()
    seed_classes(conn)
    from notify import migrate_filters
    from feeds import migrate_feeds
    migrate_filters(conn)
    migrate_feeds(conn)
    conn.commit()
    return conn


def seed_classes(conn):
    if conn.execute("SELECT COUNT(*) FROM sig_class").fetchone()[0] > 0:
        return
    path = CLASSIFICATION if os.path.isfile(CLASSIFICATION) else ""
    if path:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("config classification:"):
                    continue
                body = line.split(":", 1)[1].strip()
                parts = [p.strip() for p in body.split(",")]
                if len(parts) < 3:
                    continue
                name, desc, prio = parts[0], parts[1], int(parts[2])
                conn.execute(
                    "INSERT OR IGNORE INTO sig_class(sig_class_name, sig_class_description, sig_priority) VALUES (?,?,?)",
                    (name, desc, prio),
                )
    for name in ("others",):
        conn.execute(
            "INSERT OR IGNORE INTO sig_class(sig_class_name, sig_class_description, sig_priority) VALUES (?,?,?)",
            (name, name, 3),
        )
    seed_class_policies(conn)


def seed_class_policies(conn):
    defaults = parse_signature_conf(SIGNATURE_CONF if os.path.isfile(SIGNATURE_CONF) else "")
    for name, cfg in defaults.items():
        row = conn.execute("SELECT sig_class_id FROM sig_class WHERE sig_class_name=?", (name,)).fetchone()
        if not row:
            conn.execute(
                "INSERT OR IGNORE INTO sig_class(sig_class_name, sig_class_description, sig_priority) VALUES (?,?,3)",
                (name, name),
            )
            row = conn.execute("SELECT sig_class_id FROM sig_class WHERE sig_class_name=?", (name,)).fetchone()
        if not row:
            continue
        action = "disable" if cfg.get("enabled") == "no" else cfg.get("default_action", "alert")
        conn.execute(
            "INSERT OR IGNORE INTO policy_class(sig_class_id, action, comment) VALUES (?,?,?)",
            (row["sig_class_id"], action, "from signature.conf"),
        )


def parse_signature_conf(path):
    out = {}
    if not path or not os.path.isfile(path):
        return out
    current = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1]
                out.setdefault(current, {})
            elif current and "=" in line:
                k, v = line.split("=", 1)
                out[current][k.strip()] = v.strip()
    return out


def kv_get(conn, key, default=""):
    row = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    return row["v"] if row else default


def kv_set(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO kv(k, v) VALUES (?, ?)", (key, str(value)))


def ip_to_int(addr):
    if not addr:
        return 0
    try:
        ip = ipaddress.ip_address(addr.split("/")[0])
        if isinstance(ip, ipaddress.IPv4Address):
            return int(ip)
    except ValueError:
        return 0
    return 0


def severity_from_priority(prio):
    try:
        p = int(prio)
    except (TypeError, ValueError):
        return 3
    if p <= 1:
        return 1
    if p == 2:
        return 2
    return 3


def rotate_if_needed(conn, path=None):
    db = path or DB_PATH
    try:
        size = os.path.getsize(db)
    except OSError:
        return 0
    limit_mb = int(kv_get(conn, "storage_limit_mb", "500") or "500")
    limit = limit_mb * 1024 * 1024
    if size <= limit:
        return 0
    deleted = 0
    while size > int(limit * 0.8):
        cur = conn.execute("SELECT cid FROM event ORDER BY ts_epoch ASC LIMIT 500")
        ids = [r["cid"] for r in cur]
        if not ids:
            break
        conn.executemany("DELETE FROM event WHERE cid=?", [(i,) for i in ids])
        conn.executemany("DELETE FROM iphdr WHERE cid=?", [(i,) for i in ids])
        conn.executemany("DELETE FROM tcphdr WHERE cid=?", [(i,) for i in ids])
        conn.executemany("DELETE FROM udphdr WHERE cid=?", [(i,) for i in ids])
        conn.executemany("DELETE FROM icmphdr WHERE cid=?", [(i,) for i in ids])
        conn.executemany("DELETE FROM data WHERE cid=?", [(i,) for i in ids])
        deleted += len(ids)
        conn.commit()
        try:
            size = os.path.getsize(db)
        except OSError:
            break
    conn.execute("VACUUM")
    return deleted


def clear_events(conn):
    kv_set(conn, "clear_status", "clearing")
    conn.commit()
    for table in ("data", "icmphdr", "udphdr", "tcphdr", "iphdr", "event"):
        conn.execute("DELETE FROM %s" % table)
    kv_set(conn, "clear_status", "cleared")
    conn.commit()


def backup_json(conn):
    payload = {"kv": {}, "policy_class": [], "policy_signature": [], "policy_filter": [], "device": [], "rule_feed": []}
    skip = ("telegram_token", "bot_token", "etpro_code")
    for row in conn.execute("SELECT k, v FROM kv"):
        if row["k"] in skip:
            continue
        payload["kv"][row["k"]] = row["v"]
    for table in ("policy_class", "policy_signature", "policy_filter", "device"):
        payload[table] = [dict(r) for r in conn.execute("SELECT * FROM %s" % table)]
    try:
        payload["rule_feed"] = [dict(r) for r in conn.execute("SELECT name, url, enabled FROM rule_feed")]
    except sqlite3.Error:
        payload["rule_feed"] = []
    return json.dumps(payload, indent=2)


def restore_json(conn, text):
    payload = json.loads(text)
    for k, v in (payload.get("kv") or {}).items():
        kv_set(conn, k, v)
    conn.execute("DELETE FROM policy_class")
    conn.execute("DELETE FROM policy_signature")
    conn.execute("DELETE FROM policy_filter")
    for row in payload.get("policy_class") or []:
        conn.execute(
            "INSERT OR REPLACE INTO policy_class(sig_class_id, action, comment) VALUES (?,?,?)",
            (row["sig_class_id"], row["action"], row.get("comment", "")),
        )
    for row in payload.get("policy_signature") or []:
        conn.execute(
            "INSERT OR REPLACE INTO policy_signature(raw_sid, sig_class_id, sig_name, action, comment) VALUES (?,?,?,?,?)",
            (row["raw_sid"], row.get("sig_class_id", 0), row.get("sig_name", ""), row["action"], row.get("comment", "")),
        )
    for row in payload.get("policy_filter") or []:
        conn.execute(
            """INSERT INTO policy_filter(raw_sid, filter_sid, filter_rev, sig_class_id, sig_name, action, ip_src, ip_dst, ip_src_str, ip_dst_str, comment)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["raw_sid"], row.get("filter_sid", 0), row.get("filter_rev", 0),
                row.get("sig_class_id", 0), row.get("sig_name", ""), row["action"],
                row.get("ip_src", 0), row.get("ip_dst", 0),
                row.get("ip_src_str", ""), row.get("ip_dst_str", ""), row.get("comment", ""),
            ),
        )
    if "rule_feed" in payload:
        try:
            conn.execute("DELETE FROM rule_feed")
            for row in payload.get("rule_feed") or []:
                name = (row.get("name") or "").strip()
                url = (row.get("url") or "").strip()
                if not name or not url:
                    continue
                conn.execute(
                    "INSERT OR REPLACE INTO rule_feed(name, url, enabled, created) VALUES (?,?,?,?)",
                    (name, url, 1 if row.get("enabled", 1) else 0, int(time.time())),
                )
        except sqlite3.Error:
            pass
    conn.commit()


def now_ts():
    return int(time.time())
