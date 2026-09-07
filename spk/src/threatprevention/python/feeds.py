"""Extra suricata-update feed list (additive to ET Open/Pro)."""
import ipaddress
import json
import os
import re
import sqlite3
import time
from urllib.parse import urlparse

from paths import FEEDS_JSON, PKGETC

FEED_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def migrate_feeds(conn):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS rule_feed (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            url TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created INTEGER NOT NULL DEFAULT 0
        )"""
    )


def feed_name_ok(name):
    return bool(name and FEED_NAME_RE.match(name) and not str(name).startswith("et-"))


def _host_blocked(host):
    if not host:
        return True
    h = host.strip("[]").lower()
    if h in ("localhost", "metadata.google.internal"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return h.endswith(".local")
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if ip == ipaddress.ip_address("169.254.169.254"):
        return True
    return False


def _host_rfc1918(host):
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return ip.is_private


def feed_url_ok(url):
    if not url or not isinstance(url, str):
        return False
    raw = url.strip()
    parsed = urlparse(raw)
    if parsed.scheme not in ("https", "http"):
        return False
    if parsed.username or parsed.password:
        return False
    if _host_blocked(parsed.hostname or ""):
        return False
    if parsed.scheme == "http" and not _host_rfc1918(parsed.hostname or ""):
        return False
    return True


def list_feeds(conn):
    migrate_feeds(conn)
    rows = conn.execute("SELECT id, name, url, enabled FROM rule_feed ORDER BY name")
    return [
        {"id": r["id"], "name": r["name"], "url": r["url"], "enabled": bool(r["enabled"])}
        for r in rows
    ]


def add_feed(conn, name, url, enabled=True):
    migrate_feeds(conn)
    name = (name or "").strip()
    url = (url or "").strip()
    if not feed_name_ok(name) or not feed_url_ok(url):
        return None
    try:
        conn.execute(
            "INSERT INTO rule_feed(name, url, enabled, created) VALUES (?,?,?,?)",
            (name, url, 1 if enabled else 0, int(time.time())),
        )
    except sqlite3.IntegrityError:
        return None
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def update_feed(conn, feed_id, name=None, url=None, enabled=None):
    migrate_feeds(conn)
    row = conn.execute("SELECT * FROM rule_feed WHERE id=?", (int(feed_id),)).fetchone()
    if not row:
        return False
    next_name = (name if name is not None else row["name"]).strip()
    next_url = (url if url is not None else row["url"]).strip()
    next_on = row["enabled"] if enabled is None else (1 if enabled else 0)
    if not feed_name_ok(next_name) or not feed_url_ok(next_url):
        return False
    conn.execute(
        "UPDATE rule_feed SET name=?, url=?, enabled=? WHERE id=?",
        (next_name, next_url, next_on, int(feed_id)),
    )
    return True


def delete_feed(conn, feed_id):
    migrate_feeds(conn)
    conn.execute("DELETE FROM rule_feed WHERE id=?", (int(feed_id),))
    return True


def write_feeds_json(conn):
    os.makedirs(PKGETC, exist_ok=True)
    items = [{"name": x["name"], "url": x["url"], "enabled": x["enabled"]} for x in list_feeds(conn)]
    with open(FEEDS_JSON, "w", encoding="utf-8") as fh:
        json.dump({"feeds": items}, fh)
    try:
        os.chmod(FEEDS_JSON, 0o644)
    except OSError:
        pass
