"""Notification filters + optional DSM desktop notify + Telegram."""
import json
import os
import subprocess
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

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


def maybe_notify(conn, classtype, sig_name, severity=3, ip_src=""):
    """Best-effort DSM notify + Telegram. Mail/SMS/push stay Control Panel."""
    title = kv_get(conn, "subject_prefix", "Threat Prevention") or "Threat Prevention"
    msg = "%s: %s" % (classtype or "alert", sig_name or "")
    if ip_src:
        msg = "%s (%s)" % (msg, ip_src)
    dsm = _maybe_dsm(conn, classtype, title, msg)
    tg = _maybe_telegram(conn, classtype, title, msg)
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


def _maybe_telegram(conn, classtype, title, msg):
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
    sent = send_telegram(cfg["token"], cfg["chat"], "%s\n%s" % (title, msg))
    kv_set(conn, "last_telegram_ts", str(now))
    kv_set(conn, "last_telegram_msg", msg[:200])
    return sent


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


def send_telegram(token, chat, text, timeout=10):
    if not token or not chat or not text:
        return False
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    body = urlencode({"chat_id": chat, "text": text[:3500], "disable_web_page_preview": "1"}).encode("utf-8")
    req = Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
        data = json.loads(raw)
        return bool(data.get("ok"))
    except Exception as exc:
        _notify_log("telegram send failed: %s" % exc)
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
