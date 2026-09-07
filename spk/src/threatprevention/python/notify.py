"""Notification filters + optional DSM desktop notify (no mail transport)."""
import os
import subprocess
import time

from paths import PKGVAR
from store import kv_get, kv_set


def migrate_filters(conn):
    cols = {r[1] for r in conn.execute("PRAGMA table_info(notification_filter)")}
    for name, spec in (
        ("description", "TEXT NOT NULL DEFAULT ''"),
        ("enable_mail", "INTEGER NOT NULL DEFAULT 0"),
        ("enable_sms", "INTEGER NOT NULL DEFAULT 0"),
        ("enable_push", "INTEGER NOT NULL DEFAULT 0"),
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
               (name, description, severity, enable_mail, enable_sms, enable_push, action)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(name) DO UPDATE SET
                 description=excluded.description,
                 severity=excluded.severity,
                 enable_mail=excluded.enable_mail,
                 enable_sms=excluded.enable_sms,
                 enable_push=excluded.enable_push,
                 action=excluded.action""",
            (
                name,
                item.get("description") or name,
                int(item.get("severity") or 0),
                1 if _flag(item.get("enable_mail")) else 0,
                1 if _flag(item.get("enable_sms")) else 0,
                1 if _flag(item.get("enable_push")) else 0,
                item.get("action") or "",
            ),
        )


def maybe_notify(conn, classtype, sig_name, severity=3):
    """Best-effort DSM notify. Control Panel still owns mail/SMS/push transport."""
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
    title = kv_get(conn, "subject_prefix", "Threat Prevention") or "Threat Prevention"
    msg = "%s: %s" % (classtype or "alert", sig_name or "")
    sent = _dsm_notify(title, msg)
    kv_set(conn, "last_notify_ts", str(now))
    kv_set(conn, "last_notify_msg", msg[:200])
    return sent


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
