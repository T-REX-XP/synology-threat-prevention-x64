"""Load rule-source URLs from JSON. No feed URLs in Python."""
import json
import os

from paths import RULE_SOURCES_JSON, SHIPPED_RULE_SOURCES_JSON

_CACHE = None
_CACHE_PATH = None


def rule_sources_path():
    for path in (
        RULE_SOURCES_JSON,
        SHIPPED_RULE_SOURCES_JSON,
        os.path.join(os.path.dirname(__file__), "..", "package", "etc", "rule-sources.json"),
    ):
        if path and os.path.isfile(path):
            return path
    return ""


def load_rule_sources(force=False):
    global _CACHE, _CACHE_PATH
    path = rule_sources_path()
    if not force and _CACHE is not None and _CACHE_PATH == path:
        return _CACHE
    data = {"sources": {}, "catalog": []}
    if path:
        try:
            loaded = json.load(open(path, encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError, TypeError):
            pass
    _CACHE = data
    _CACHE_PATH = path
    return data


def format_source_url(url, code=""):
    text = str(url or "")
    code = str(code or "")
    return text.replace("{code}", code).replace("{oinkcode}", code)


def source_urls(kind, code=""):
    kind = str(kind or "et-open").lower().replace("_", "-")
    if kind in ("etpro", "et-pro", "et_pro"):
        kind = "et-pro"
    elif kind in ("etopen", "et-open", "et_open"):
        kind = "et-open"
    sources = load_rule_sources().get("sources") or {}
    item = sources.get(kind) or {}
    urls = item.get("urls") if isinstance(item, dict) else None
    if not isinstance(urls, list):
        urls = []
    return [format_source_url(u, code) for u in urls if u]


def catalog_entries():
    rows = []
    for item in load_rule_sources().get("catalog") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        url = str(item.get("url") or "").strip()
        if name and url:
            rows.append((name, url))
    return rows
