#!/usr/bin/env python3
"""Parse bundled Threat Prevention Suricata/ET rules into CSV + JSON summary."""

from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path("/Users/t-rex-xp/syno-router-review")
RULES_DIR = ROOT / "unpacked/package/etc/rules/extracted/rules"
OUT_DIR = ROOT / "docs/rules"

ACTIONS = ("alert", "drop", "pass", "reject", "rejectsrc", "rejectdst", "rejectboth")
ACTION_RE = re.compile(
    r"^(?P<comment>#\s*)?(?P<action>alert|drop|pass|rejectsrc|rejectdst|rejectboth|reject)\s+"
    r"(?P<rest>.*)$",
    re.IGNORECASE,
)
def split_options(opts: str) -> list[str]:
    """Split Suricata options on ';' that are not inside double quotes."""
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    escape = False
    for ch in opts:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\" and in_quote:
            buf.append(ch)
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
            buf.append(ch)
            continue
        if ch == ";" and not in_quote:
            token = "".join(buf).strip()
            if token:
                parts.append(token)
            buf = []
            continue
        buf.append(ch)
    token = "".join(buf).strip()
    if token:
        parts.append(token)
    return parts


def option_map(opts: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for token in split_options(opts):
        if ":" not in token:
            out[token.lower()].append("")
            continue
        key, val = token.split(":", 1)
        out[key.strip().lower()].append(val.strip())
    return out
HEADER_RE = re.compile(
    r"^(?P<proto>\S+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+(?P<dir>->|<>)\s+"
    r"(?P<dst>\S+)\s+(?P<dport>\S+)\s+\((?P<opts>.*)$"
)

CLASS_PRIORITY = {
    "not-suspicious": 3,
    "unknown": 3,
    "bad-unknown": 2,
    "attempted-recon": 2,
    "successful-recon-limited": 2,
    "successful-recon-largescale": 2,
    "attempted-dos": 2,
    "successful-dos": 2,
    "attempted-user": 1,
    "unsuccessful-user": 1,
    "successful-user": 1,
    "attempted-admin": 1,
    "successful-admin": 1,
    "rpc-portmap-decode": 2,
    "shellcode-detect": 1,
    "string-detect": 3,
    "suspicious-filename-detect": 2,
    "suspicious-login": 2,
    "system-call-detect": 2,
    "tcp-connection": 4,
    "trojan-activity": 1,
    "unusual-client-port-connection": 2,
    "network-scan": 3,
    "denial-of-service": 2,
    "non-standard-protocol": 2,
    "protocol-command-decode": 3,
    "web-application-activity": 2,
    "web-application-attack": 1,
    "misc-activity": 3,
    "misc-attack": 2,
    "icmp-event": 3,
    "inappropriate-content": 1,
    "policy-violation": 1,
    "default-login-attempt": 2,
    "targeted-activity": 1,
    "exploit-kit": 1,
    "external-ip-check": 2,
    "domain-c2": 1,
    "pup-activity": 2,
    "credential-theft": 1,
    "social-engineering": 2,
    "coin-mining": 2,
    "command-and-control": 1,
}

# Synology signature.conf defaults
SYNO_DROP = {
    "trojan-activity",
    "attempted-user",
    "unsuccessful-user",
    "successful-user",
    "attempted-admin",
    "successful-admin",
    "shellcode-detect",
    "web-application-attack",
    "inappropriate-content",
    "policy-violation",  # drop but enabled=no
}
SYNO_DISABLED = {"policy-violation", "misc-activity", "not-suspicious", "others"}

SEVERITY_LABEL = {1: "high", 2: "medium", 3: "low", 4: "low"}

IP_LIST_FILES = {
    "drop.rules",
    "dshield.rules",
    "ciarmy.rules",
    "compromised.rules",
    "botcc.rules",
    "botcc.portgrouped.rules",
    "tor.rules",
    "3coresec.rules",
}


def sid_license(sid: int, filename: str) -> str:
    if filename == "syno-custom-events.rules":
        return "Synology custom"
    if 1 <= sid <= 3464 or 100000000 <= sid <= 100000908:
        return "GPLv2"
    if 2100000 <= sid <= 2199999:
        return "GPLv2 (ET-GPL)"
    if 2000000 <= sid <= 2799999:
        return "BSD (Emerging Threats)"
    if 2400000 <= sid <= 2499999:
        return "BSD (ET IP lists)"
    return "Unknown / other"


def sid_family(sid: int, filename: str) -> str:
    if filename == "syno-custom-events.rules":
        return "synology"
    if 1 <= sid <= 3464 or 100000000 <= sid <= 100000908 or 2100000 <= sid <= 2199999:
        return "gpl"
    if filename in IP_LIST_FILES or 2400000 <= sid <= 2499999:
        return "et-iplist"
    if 2000000 <= sid <= 2799999:
        return "et-open"
    return "other"


def parse_metadata(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not raw:
        return out
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    i = 0
    while i < len(parts):
        token = parts[i]
        if " " in token:
            k, v = token.split(" ", 1)
            out[k.strip()] = v.strip()
        i += 1
    return out


def join_continuations(lines: list[str]) -> list[tuple[int, str]]:
    """Return (start_lineno, logical_line) merging backslash continuations."""
    result: list[tuple[int, str]] = []
    buf = ""
    start = 1
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not buf:
            start = i
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        buf += line
        result.append((start, buf.strip()))
        buf = ""
    if buf.strip():
        result.append((start, buf.strip()))
    return result


def parse_header(rest: str) -> dict[str, str] | None:
    # rest is "proto src sport -> dst dport (options...)" possibly truncated
    # options may contain nested parens; take first '(' as options start
    paren = rest.find("(")
    if paren < 0:
        return None
    header = rest[:paren].strip()
    opts = rest[paren + 1 :]
    if opts.endswith(")"):
        opts = opts[:-1]
    elif opts.endswith(";)"):
        opts = opts[:-2]
    m = re.match(
        r"^(?P<proto>\S+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+(?P<dir>->|<>)\s+"
        r"(?P<dst>\S+)\s+(?P<dport>\S+)\s*$",
        header,
    )
    if not m:
        # some IP-list rules have huge src lists; still capture proto/dir
        m2 = re.match(
            r"^(?P<proto>\S+)\s+(?P<src>.+)\s+(?P<sport>\S+)\s+(?P<dir>->|<>)\s+"
            r"(?P<dst>\S+)\s+(?P<dport>\S+)\s*$",
            header,
        )
        if not m2:
            return {"proto": "", "src": "", "sport": "", "dir": "", "dst": "", "dport": "", "opts": opts}
        d = m2.groupdict()
        d["opts"] = opts
        return d
    d = m.groupdict()
    d["opts"] = opts
    return d


def syno_policy(classtype: str) -> tuple[str, str]:
    """Return (enabled, default_action) as Threat Prevention would apply."""
    ct = classtype or "others"
    enabled = "no" if ct in SYNO_DISABLED else "yes"
    if ct in SYNO_DISABLED and ct != "policy-violation":
        action = "alert"  # class disabled entirely
    elif ct in SYNO_DROP:
        action = "drop"
    else:
        action = "alert"
    return enabled, action


def parse_file(path: Path) -> list[dict]:
    rows: list[dict] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for lineno, logical in join_continuations(text.splitlines()):
        if not logical:
            continue
        m = ACTION_RE.match(logical)
        if not m:
            continue
        commented = bool(m.group("comment"))
        action = m.group("action").lower()
        rest = m.group("rest")
        hdr = parse_header(rest)
        if hdr is None:
            continue
        opts = hdr["opts"]
        om = option_map(opts)

        def grab(name: str) -> str:
            vals = om.get(name, [])
            return vals[0] if vals else ""

        sid_s = grab("sid")
        if not sid_s:
            continue
        sid = int(sid_s)
        classtype = grab("classtype")
        msg = grab("msg").strip().strip('"')
        meta = parse_metadata(grab("metadata"))
        cves = []
        for ref in om.get("reference", []):
            if "," in ref:
                k, v = ref.split(",", 1)
                if k.strip().lower() == "cve":
                    cves.append(v.strip())
        noalert = "noalert" in om
        enabled_cls, syno_action = syno_policy(classtype)
        prio = CLASS_PRIORITY.get(classtype, 3)
        # IP count in src list
        src = hdr["src"]
        ip_count = src.count(",") + 1 if src.startswith("[") else (0 if not src else 1)
        if src in ("any", "$HOME_NET", "$EXTERNAL_NET") or src.startswith("$"):
            ip_count = 0

        rows.append(
            {
                "file": path.name,
                "line": lineno,
                "enabled_in_file": "no" if commented else "yes",
                "action": action,
                "protocol": hdr["proto"],
                "src": src[:240],
                "src_port": hdr["sport"],
                "direction": hdr["dir"],
                "dst": hdr["dst"][:120],
                "dst_port": hdr["dport"],
                "msg": msg,
                "classtype": classtype,
                "priority": prio,
                "severity": SEVERITY_LABEL.get(prio, "low"),
                "sid": sid,
                "rev": grab("rev") or "1",
                "gid": grab("gid") or "1",
                "noalert": "yes" if noalert else "no",
                "cve": ";".join(cves),
                "cve_count": len(cves),
                "created_at": meta.get("created_at", ""),
                "updated_at": meta.get("updated_at", ""),
                "signature_severity": meta.get("signature_severity", ""),
                "former_category": meta.get("former_category", ""),
                "license": sid_license(sid, path.name),
                "family": sid_family(sid, path.name),
                "syno_class_enabled": enabled_cls,
                "syno_default_action": syno_action,
                "ip_list_members": ip_count if path.name in IP_LIST_FILES else 0,
            }
        )
    return rows


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    all_rows: list[dict] = []
    for path in sorted(RULES_DIR.glob("*.rules")):
        all_rows.extend(parse_file(path))

    # Deduplicate SIDs preferring enabled copy, then non-deleted file
    by_sid: dict[int, dict] = {}
    dupes = 0
    for row in all_rows:
        sid = row["sid"]
        prev = by_sid.get(sid)
        if prev is None:
            by_sid[sid] = row
            continue
        dupes += 1
        # prefer enabled, then non-deleted filename
        score = (row["enabled_in_file"] == "yes", "deleted" not in row["file"])
        prev_score = (prev["enabled_in_file"] == "yes", "deleted" not in prev["file"])
        if score > prev_score:
            by_sid[sid] = row

    unique = list(by_sid.values())
    active = [r for r in unique if r["enabled_in_file"] == "yes"]
    disabled = [r for r in unique if r["enabled_in_file"] == "no"]

    fields = [
        "sid",
        "rev",
        "gid",
        "enabled_in_file",
        "action",
        "protocol",
        "msg",
        "classtype",
        "priority",
        "severity",
        "syno_class_enabled",
        "syno_default_action",
        "file",
        "line",
        "src_port",
        "dst_port",
        "direction",
        "noalert",
        "cve",
        "created_at",
        "updated_at",
        "signature_severity",
        "former_category",
        "license",
        "family",
        "ip_list_members",
        "src",
        "dst",
    ]

    def write_csv(name: str, rows: list[dict]) -> None:
        with (OUT_DIR / name).open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in sorted(rows, key=lambda x: (x["file"], x["sid"])):
                w.writerow(r)

    write_csv("alerts-active.csv", active)
    write_csv("alerts-all.csv", unique)

    def count_by(rows: list[dict], key: str) -> dict[str, int]:
        c: Counter[str] = Counter(str(r[key] or "(none)") for r in rows)
        return dict(c.most_common())

    def file_stats(rows: list[dict]) -> list[dict]:
        groups: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            groups[r["file"]].append(r)
        out = []
        for fn, rs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            drop_n = sum(1 for r in rs if r["syno_default_action"] == "drop" and r["syno_class_enabled"] == "yes")
            disabled_n = sum(1 for r in rs if r["syno_class_enabled"] == "no")
            cves = sum(1 for r in rs if r["cve_count"])
            out.append(
                {
                    "file": fn,
                    "active": len(rs),
                    "syno_drop": drop_n,
                    "syno_class_disabled": disabled_n,
                    "with_cve": cves,
                    "high": sum(1 for r in rs if r["severity"] == "high"),
                    "medium": sum(1 for r in rs if r["severity"] == "medium"),
                    "low": sum(1 for r in rs if r["severity"] == "low"),
                }
            )
        return out

    year_created = Counter()
    year_updated = Counter()
    for r in active:
        if r["created_at"] and len(r["created_at"]) >= 4:
            year_created[r["created_at"][:4]] += 1
        if r["updated_at"] and len(r["updated_at"]) >= 4:
            year_updated[r["updated_at"][:4]] += 1

    syno_drop_active = [
        r
        for r in active
        if r["syno_default_action"] == "drop" and r["syno_class_enabled"] == "yes" and r["noalert"] == "no"
    ]
    syno_alert_active = [
        r
        for r in active
        if r["syno_class_enabled"] == "yes"
        and r["syno_default_action"] == "alert"
        and r["noalert"] == "no"
    ]
    syno_skipped = [r for r in active if r["syno_class_enabled"] == "no"]

    cve_rules = [r for r in active if r["cve_count"]]
    unique_cves = set()
    for r in cve_rules:
        for c in r["cve"].split(";"):
            if c:
                unique_cves.add(c.upper().replace("CAN-", "CVE-"))

    proto = count_by(active, "protocol")
    # collapse http/tcp etc
    summary = {
        "source_tarball": "unpacked/package/etc/rules/emerging.rules.tar.gz",
        "et_open_version": "9840",
        "ruleset_tree": "suricata-5.0",
        "parsed_rule_lines": len(all_rows),
        "unique_sids": len(unique),
        "duplicate_sid_rows": dupes,
        "active_in_file": len(active),
        "commented_or_deleted": len(disabled),
        "action_in_file": count_by(active, "action"),
        "protocol": proto,
        "family": count_by(active, "family"),
        "license": count_by(active, "license"),
        "classtype": count_by(active, "classtype"),
        "severity": count_by(active, "severity"),
        "signature_severity_meta": count_by(active, "signature_severity"),
        "syno_runtime": {
            "would_drop": len(syno_drop_active),
            "would_alert": len(syno_alert_active),
            "class_disabled": len(syno_skipped),
            "noalert": sum(1 for r in active if r["noalert"] == "yes"),
        },
        "cve": {
            "active_rules_with_cve": len(cve_rules),
            "unique_cve_ids": len(unique_cves),
        },
        "created_year": dict(sorted(year_created.items())),
        "updated_year": dict(sorted(year_updated.items())),
        "by_file": file_stats(active),
        "synology_custom": [r for r in unique if r["file"] == "syno-custom-events.rules"],
        "thresholded_sids": [2101411, 2013504],
    }

    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    # Compact JSON catalog of active alerts for tooling (no huge src lists)
    compact = []
    for r in sorted(active, key=lambda x: x["sid"]):
        compact.append(
            {
                "sid": r["sid"],
                "rev": int(r["rev"]) if str(r["rev"]).isdigit() else r["rev"],
                "msg": r["msg"],
                "classtype": r["classtype"],
                "severity": r["severity"],
                "action": r["action"],
                "syno_action": r["syno_default_action"] if r["syno_class_enabled"] == "yes" else "disabled",
                "proto": r["protocol"],
                "file": r["file"],
                "cve": r["cve"],
                "updated": r["updated_at"],
            }
        )
    (OUT_DIR / "alerts-active.json").write_text(json.dumps(compact) + "\n", encoding="utf-8")

    print(f"parsed_lines={len(all_rows)} unique_sids={len(unique)} active={len(active)} disabled={len(disabled)}")
    print(f"syno_drop={len(syno_drop_active)} syno_alert={len(syno_alert_active)} class_disabled={len(syno_skipped)}")
    print(f"cve_rules={len(cve_rules)} unique_cves={len(unique_cves)}")
    print("top classtypes:")
    for k, v in list(summary["classtype"].items())[:15]:
        print(f"  {v:6d}  {k}")
    print("by file:")
    for row in summary["by_file"][:20]:
        print(f"  {row['active']:6d}  {row['file']}")


if __name__ == "__main__":
    main()
