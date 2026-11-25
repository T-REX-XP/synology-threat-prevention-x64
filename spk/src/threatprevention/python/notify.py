"""Notification filters + optional DSM desktop notify + Telegram."""
import json
import os
import subprocess
import time
from html import escape
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from corehost import server_name
from host_info import alert_macs, lookup_host
from paths import PKGETC, PKGVAR, TELEGRAM_CONF
from store import kv_get, kv_set


def migrate_filters(conn):
    cols = {r[1] for r in conn.execute("PRAGMA table_info(notification_filter)")}
    for name, spec in (
        ("description", "TEXT NOT NULL DEFAULT ''"),
        ("enable_mail", "INTEGER NOT NULL DEFAULT 0"),
        ("enable_sms", "INTEGER NOT NULL DEFAULT 0"),
        ("enable_push", "INTEGER NOT NULL DEFAULT 0"),
        ("enable_telegram", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if name not in cols:
            conn.execute("ALTER TABLE notification_filter ADD COLUMN %s %s" % (name, spec))
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS notification_filter_name ON notification_filter(name)"
    )


def _flag(value):
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("1", "true", "yes", "on")


def list_filters(conn):
    migrate_filters(conn)
    saved = {}
    for r in conn.execute("SELECT * FROM notification_filter"):
        saved[r["name"]] = dict(r)
    out = []
    seen = set()
    for r in conn.execute(
        "SELECT sig_class_name, sig_class_description, sig_priority "
        "FROM sig_class ORDER BY sig_priority, sig_class_name"
    ):
        name = r["sig_class_name"]
        seen.add(name)
        s = saved.get(name) or {}
        out.append({
            "name": name,
            "description": (s.get("description") or r["sig_class_description"] or name),
            "severity": int(r["sig_priority"] or 3),
            "enable_mail": _flag(s.get("enable_mail")),
            "enable_sms": _flag(s.get("enable_sms")),
            "enable_push": _flag(s.get("enable_push")),
            "enable_telegram": _flag(s.get("enable_telegram")),
            "action": s.get("action") or "",
        })
    for name, s in saved.items():
        if name in seen:
            continue
        out.append({
            "name": name,
            "description": s.get("description") or name,
            "severity": int(s.get("severity") or 3),
            "enable_mail": _flag(s.get("enable_mail")),
            "enable_sms": _flag(s.get("enable_sms")),
            "enable_push": _flag(s.get("enable_push")),
            "enable_telegram": _flag(s.get("enable_telegram")),
            "action": s.get("action") or "",
        })
    return out


def upsert_filters(conn, items):
    migrate_filters(conn)
    for item in items or []:
        name = (item.get("name") or "").strip()
        if not name:
            continue
        conn.execute(
            """INSERT INTO notification_filter
               (name, description, severity, enable_mail, enable_sms, enable_push, enable_telegram, action)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(name) DO UPDATE SET
                 description=excluded.description,
                 severity=excluded.severity,
                 enable_mail=excluded.enable_mail,
                 enable_sms=excluded.enable_sms,
                 enable_push=excluded.enable_push,
                 enable_telegram=excluded.enable_telegram,
                 action=excluded.action""",
            (
                name,
                item.get("description") or name,
                int(item.get("severity") or 0),
                1 if _flag(item.get("enable_mail")) else 0,
                1 if _flag(item.get("enable_sms")) else 0,
                1 if _flag(item.get("enable_push")) else 0,
                1 if _flag(item.get("enable_telegram")) else 0,
                item.get("action") or "",
            ),
        )


def maybe_notify(conn, classtype, sig_name, severity=3, ip_src="", *, event=None):
    """Best-effort DSM notify + Telegram. Mail/SMS/push stay Control Panel."""
    title = kv_get(conn, "subject_prefix", "Threat Prevention") or "Threat Prevention"
    msg = "%s: %s" % (classtype or "alert", sig_name or "")
    if ip_src:
        msg = "%s (%s)" % (msg, ip_src)
    dsm = _maybe_dsm(conn, classtype, title, msg)
    tg = _maybe_telegram(conn, classtype, title, msg, sig_name, severity, ip_src, event or {})
    return dsm or tg


def _maybe_dsm(conn, classtype, title, msg):
    if kv_get(conn, "enable_notification", "0") != "1":
        return False
    migrate_filters(conn)
    row = conn.execute(
        "SELECT * FROM notification_filter WHERE name=?", (classtype or "",)
    ).fetchone()
    has_filters = conn.execute("SELECT COUNT(*) n FROM notification_filter").fetchone()["n"]
    if has_filters and not row:
        return False
    want_mail = kv_get(conn, "enable_mail", "0") == "1" and (not row or _flag(row["enable_mail"]))
    want_sms = kv_get(conn, "enable_sms", "0") == "1" and (not row or _flag(row["enable_sms"]))
    want_push = kv_get(conn, "enable_push", "0") == "1" and (not row or _flag(row["enable_push"]))
    if not (want_mail or want_sms or want_push):
        return False
    intervals = []
    if want_mail:
        intervals.append(int(kv_get(conn, "min_interval_mail", "300") or 300))
    if want_sms:
        intervals.append(int(kv_get(conn, "min_interval_sms", "300") or 300))
    if want_push:
        intervals.append(int(kv_get(conn, "min_interval_push", "300") or 300))
    gap = min(intervals) if intervals else 300
    last = int(kv_get(conn, "last_notify_ts", "0") or 0)
    now = int(time.time())
    if last and now - last < gap:
        return False
    sent = _dsm_notify(title, msg)
    kv_set(conn, "last_notify_ts", str(now))
    kv_set(conn, "last_notify_msg", msg[:200])
    return sent


def _telegram_class_ok(conn, classtype):
    migrate_filters(conn)
    row = conn.execute(
        "SELECT * FROM notification_filter WHERE name=?", (classtype or "",)
    ).fetchone()
    has_filters = conn.execute("SELECT COUNT(*) n FROM notification_filter").fetchone()["n"]
    follow = kv_get(conn, "telegram_follow_mail", "1") == "1"
    if not has_filters:
        return True
    if not row:
        return False
    if follow:
        return _flag(row["enable_mail"])
    return _flag(row["enable_telegram"] if "enable_telegram" in row.keys() else 0)


def _field(value, limit=160):
    return escape(" ".join(str(value).split())[:limit], quote=False)


def _endpoint(label, ip, port, captured_mac):
    if not ip:
        return "%s <i>Unknown</i>" % label
    address = str(ip)
    if port:
        address = "%s:%s" % ("[%s]" % address if ":" in address else address, port)
    host = lookup_host(ip, captured_mac)
    details = []
    for key, name in (("hostname", "Host"), ("netbios", "NetBIOS"), ("mac", "MAC"),
                      ("link_mac", "Captured link MAC")):
        if host.get(key):
            details.append("%s <code>%s</code>" % (name, _field(host[key])))
    line = "%s <code>%s</code>" % (label, _field(address))
    return line + (" · " + " · ".join(details) if details else "")


def format_telegram_alert(title, classtype, signature, severity, ip_src, event):
    alert = event.get("alert") or {}
    src_mac, dst_mac = alert_macs(event)
    level = {1: "High", 2: "Medium"}.get(severity, "Low")
    details = ["Priority %s (%s)" % (_field(severity, 10), level)]
    for value in (event.get("proto"), event.get("app_proto"), alert.get("action")):
        if value and str(value).lower() != "failed":
            details.append(_field(value, 48))
    if alert.get("signature_id"):
        rule_id = str(alert["signature_id"])
        if alert.get("rev"):
            rule_id += " rev " + str(alert["rev"])
        details.append("SID <code>%s</code>" % _field(rule_id, 48))
    lines = [
        "🚨 <b>%s</b>" % _field(title),
        "<b>%s</b>" % _field(signature or "Suricata alert", 900),
        _field(classtype or "Alert") + " · " + " · ".join(details),
        "",
        _endpoint("📤 <b>Source</b>", ip_src, event.get("src_port"), src_mac),
        _endpoint("🎯 <b>Target</b>", event.get("dest_ip"), event.get("dest_port"), dst_mac),
    ]
    if event.get("timestamp"):
        lines.append("🕒 <code>%s</code>" % _field(event["timestamp"], 64))
    return "\n".join(lines)


def _maybe_telegram(conn, classtype, title, msg, sig_name, severity, ip_src, event):
    if kv_get(conn, "enable_telegram", "0") != "1":
        return False
    if not _telegram_class_ok(conn, classtype):
        return False
    gap = int(kv_get(conn, "min_interval_telegram", "300") or 300)
    last = int(kv_get(conn, "last_telegram_ts", "0") or 0)
    now = int(time.time())
    if last and now - last < gap:
        return False
    cfg = read_telegram_conf()
    if not cfg.get("token") or not cfg.get("chat"):
        _notify_log("telegram skipped: missing token/chat")
        return False
    text = format_telegram_alert(title, classtype, sig_name, severity, ip_src, event)
    sent = send_telegram(cfg["token"], cfg["chat"], text, html=True)
    kv_set(conn, "last_telegram_ts", str(now))
    kv_set(conn, "last_telegram_msg", msg[:200])
    return sent


def notify_operation(conn, key, message, interval=1800):
    """Operational Telegram alerts use their own cooldown and ignore threat classes."""
    if kv_get(conn, "enable_telegram", "0") != "1":
        return False
    cfg = read_telegram_conf()
    if not cfg["token"] or not cfg["chat"]:
        return False
    if interval:
        now = int(time.time())
        stamp = "last_operation_notice_" + key
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            last = int(kv_get(conn, stamp, "0") or 0)
            if last and now - last < interval:
                return False
            kv_set(conn, stamp, str(now))
    return send_telegram(cfg["token"], cfg["chat"], "Threat Prevention on %s\n%s" % (server_name(), message))


def read_telegram_conf():
    out = {"token": "", "chat": ""}
    if not os.path.isfile(TELEGRAM_CONF):
        return out
    try:
        with open(TELEGRAM_CONF, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                key = k.strip().upper()
                val = v.strip()
                if key in ("TOKEN", "BOT_TOKEN"):
                    out["token"] = val
                elif key in ("CHAT", "CHAT_ID"):
                    out["chat"] = val
    except OSError:
        return out
    return out


def write_telegram_conf(token=None, chat=None):
    cur = read_telegram_conf()
    token_s = "" if token is None else str(token).strip()
    chat_s = "" if chat is None else str(chat).strip()
    # Empty values mean "leave unchanged". A second Apply with a blank
    # password field must not truncate TOKEN=/CHAT=.
    if token_s:
        cur["token"] = token_s
    if chat_s:
        cur["chat"] = chat_s
    os.makedirs(PKGETC, exist_ok=True)
    payload = "TOKEN=%s\nCHAT=%s\n" % (cur.get("token") or "", cur.get("chat") or "")
    tmp = TELEGRAM_CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(payload)
    os.replace(tmp, TELEGRAM_CONF)
    try:
        os.chmod(TELEGRAM_CONF, 0o600)
    except OSError:
        pass
    return cur


def send_telegram(token, chat, text, timeout=10, *, html=False):
    if not token or not chat or not text:
        return False
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    fields = {"chat_id": chat, "text": text if html else text[:3500], "disable_web_page_preview": "1"}
    if html:
        fields["parse_mode"] = "HTML"
    body = urlencode(fields).encode("utf-8")
    req = Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
        data = json.loads(raw)
        if data.get("ok"):
            return True
        _notify_log("Telegram returned a failed response")
        return False
    except Exception as exc:
        status = getattr(exc, "code", None)
        reason = "HTTP %d" % status if isinstance(status, int) else type(exc).__name__
        _notify_log("Telegram send failed: %s" % reason)
        return False


def _notify_log(line):
    try:
        os.makedirs(os.path.join(PKGVAR, "log"), exist_ok=True)
        with open(os.path.join(PKGVAR, "log", "notify.log"), "a", encoding="utf-8") as fh:
            fh.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), line))
    except OSError:
        pass


def _dsm_notify(title, msg):
    candidates = (
        ["/usr/syno/bin/synodsmnotify", "-c", "SYNO.SDS.TPS.Application", "@administrators", title, msg],
        ["/usr/syno/bin/synodsmnotify", "@administrators", title, msg],
        ["/usr/syno/bin/synonotify", "TPSNotify", '{"%%TITLE%%":"%s","%%MSG%%":"%s"}' % (
            title.replace('"', ""), msg.replace('"', ""),
        )],
    )
    for cmd in candidates:
        if not os.path.isfile(cmd[0]):
            continue
        try:
            rc = subprocess.call(cmd, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if rc == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            continue
    try:
        os.makedirs(os.path.join(PKGVAR, "log"), exist_ok=True)
        with open(os.path.join(PKGVAR, "log", "notify.log"), "a", encoding="utf-8") as fh:
            fh.write("%s %s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), title, msg))
    except OSError:
        return False
    return True
