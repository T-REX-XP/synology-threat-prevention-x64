#!/usr/bin/env python3
"""Parse bundled Suricata/ET rules into CSV + summary JSON."""
from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path("/Users/t-rex-xp/syno-router-review")
RULES_DIR = ROOT / "extracted" / "emerging-rules" / "rules"
CUSTOM = ROOT / "unpacked" / "package" / "etc" / "rules" / "syno-custom-events.rules"
OUT_DIR = ROOT / "docs" / "data"

ACTIONS = ("alert", "drop", "pass", "reject", "rejectsrc", "rejectdst", "rejectboth")
HEADER_RE = re.compile(
    r"^(?P<disabled>#\s*)?(?P<action>alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s+"
    r"(?P<proto>\S+)\s+(?P<header>.+?)\s*\((?P<body>.*)\)\s*$",
    re.DOTALL | re.IGNORECASE,
)
SID_RANGE_LICENSE = [
    (1, 3464, "GPLv2"),
    (100000000, 100000908, "GPLv2"),
    (2000000, 2799999, "BSD (Emerging Threats)"),
    (2400000, 2499999, "ET Open (typically)"),
]
# Synology default_action / enabled from signature.conf
SYNO_DROP_CLASSES = {
    "trojan-activity",
    "attempted-user",
    "unsuccessful-user",
    "successful-user",
    "attempted-admin",
    "successful-admin",
    "shellcode-detect",
    "web-application-attack",
    "inappropriate-content",
}
SYNO_DISABLED_CLASSES = {
    "policy-violation",
    "misc-activity",
    "not-suspicious",
    "others",
}
PRIORITY = {
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
SEV_NAME = {1: "high", 2: "medium", 3: "low", 4: "low"}


def split_options(body: str) -> list[tuple[str, str | None]]:
    opts: list[tuple[str, str | None]] = []
    i = 0
    n = len(body)
    while i < n:
        while i < n and body[i] in " \t\n\r;":
            i += 1
        if i >= n:
            break
        colon = body.find(":", i)
        semi = body.find(";", i)
        if colon == -1 or (semi != -1 and semi < colon):
            key = body[i:semi if semi != -1 else n].strip()
            if key:
                opts.append((key.lower(), None))
            i = n if semi == -1 else semi + 1
            continue
        key = body[i:colon].strip().lower()
        i = colon + 1
        while i < n and body[i] in " \t":
            i += 1
        if i < n and body[i] == '"':
            i += 1
            val_chars: list[str] = []
            while i < n:
                if body[i] == "\\" and i + 1 < n:
                    val_chars.append(body[i : i + 2])
                    i += 2
                    continue
                if body[i] == '"':
                    i += 1
                    break
                val_chars.append(body[i])
                i += 1
            opts.append((key, "".join(val_chars)))
            while i < n and body[i] != ";":
                i += 1
            if i < n:
                i += 1
        else:
            end = body.find(";", i)
            val = body[i:end if end != -1 else n].strip()
            opts.append((key, val))
            i = n if end == -1 else end + 1
    return opts


def license_for(sid: int) -> str:
    if 1 <= sid <= 3464 or 100000000 <= sid <= 100000908:
        return "GPLv2"
    if 2000000 <= sid <= 2799999:
        return "BSD (Emerging Threats)"
    if sid == 1:
        return "Synology custom"
    return "other / unknown"


def sid_family(sid: int) -> str:
    if sid == 1:
        return "synology-custom"
    if 1 <= sid <= 3464 or 100000000 <= sid <= 100000908:
        return "gpl-snort"
    if 2100000 <= sid <= 2199999:
        return "et-gpl-converted"
    if 2400000 <= sid <= 2499999:
        return "et-open"
    if 2000000 <= sid <= 2099999:
        return "et-legacy"
    if 2500000 <= sid <= 2799999:
        return "et-other"
    return "other"


def parse_file(path: Path, source_label: str | None = None) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    # Join continued lines: a line ending without ) that started a rule.
    logical: list[tuple[int, str]] = []
    buf = ""
    start_ln = 0
    for ln, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf:
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#") and not re.match(
                r"^#\s*(alert|drop|pass|reject)", stripped, re.I
            ):
                continue
            start_ln = ln
            buf = line
        else:
            buf = buf + " " + line.lstrip()
        if "(" in buf and buf.rstrip().endswith(")"):
            logical.append((start_ln, buf))
            buf = ""
        elif "(" in buf and buf.rstrip().endswith(");"):
            logical.append((start_ln, buf.rstrip()[:-1] + ")"))
            buf = ""
    if buf.strip():
        logical.append((start_ln, buf))

    rows = []
    for ln, rule in logical:
        m = HEADER_RE.match(rule.strip())
        if not m:
            continue
        opts = split_options(m.group("body"))
        kv: dict[str, str] = {}
        refs: list[str] = []
        flowbits: list[str] = []
        metadata = ""
        noalert = False
        for k, v in opts:
            if k == "reference" and v:
                refs.append(v)
            elif k == "flowbits" and v:
                flowbits.append(v)
            elif k == "metadata" and v:
                metadata = v
            elif k == "noalert":
                noalert = True
            elif v is not None and k not in kv:
                kv[k] = v
            elif v is None and k not in kv:
                kv[k] = ""
        try:
            sid = int(kv.get("sid", "0") or 0)
        except ValueError:
            sid = 0
        try:
            rev = int(kv.get("rev", "1") or 1)
        except ValueError:
            rev = 1
        classtype = kv.get("classtype", "") or ""
        prio = PRIORITY.get(classtype, 3)
        disabled = bool(m.group("disabled"))
        syno_drop = classtype in SYNO_DROP_CLASSES
        syno_enabled = classtype not in SYNO_DISABLED_CLASSES
        # policy-violation is in both drop and disabled; disabled wins
        if classtype in SYNO_DISABLED_CLASSES:
            syno_enabled = False
            syno_default_action = "disabled"
        elif syno_drop:
            syno_default_action = "drop"
        else:
            syno_default_action = "alert"
        proto = m.group("proto").lower()
        header = m.group("header").strip()
        direction = "->"
        if "<>" in header:
            direction = "<>"
            src, dst = header.split("<>", 1)
        elif "->" in header:
            src, dst = header.split("->", 1)
        else:
            src, dst = header, ""
        cves = [r.split(",", 1)[-1] for r in refs if r.lower().startswith("cve,")]
        rows.append(
            {
                "file": source_label or path.name,
                "line": ln,
                "disabled_in_file": disabled,
                "action": m.group("action").lower(),
                "proto": proto,
                "src": src.strip(),
                "dst": dst.strip(),
                "direction": direction,
                "msg": kv.get("msg", ""),
                "classtype": classtype,
                "priority": prio,
                "severity": SEV_NAME.get(prio, "low"),
                "sid": sid,
                "rev": rev,
                "gid": kv.get("gid", "1"),
                "noalert": noalert,
                "references": "|".join(refs),
                "cves": "|".join(cves),
                "metadata": metadata,
                "license": license_for(sid) if path.name != "syno-custom-events.rules" else "Synology custom",
                "sid_family": sid_family(sid) if path.name != "syno-custom-events.rules" else "synology-custom",
                "syno_default_action": syno_default_action,
                "syno_enabled": syno_enabled,
            }
        )
    return rows


def main() -> None:
    all_rows: list[dict] = []
    parse_errors = []
    for path in sorted(RULES_DIR.glob("*.rules")):
        try:
            all_rows.extend(parse_file(path))
        except Exception as e:  # noqa: BLE001
            parse_errors.append(f"{path.name}: {e}")
    all_rows.extend(parse_file(CUSTOM, "syno-custom-events.rules"))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = OUT_DIR / "bundled-alerts.csv"
    fields = [
        "sid",
        "rev",
        "file",
        "line",
        "action",
        "disabled_in_file",
        "proto",
        "msg",
        "classtype",
        "priority",
        "severity",
        "syno_default_action",
        "syno_enabled",
        "noalert",
        "sid_family",
        "license",
        "cves",
        "references",
        "src",
        "dst",
        "direction",
        "gid",
        "metadata",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in sorted(all_rows, key=lambda r: (r["file"], r["sid"], r["rev"])):
            out = dict(row)
            out["disabled_in_file"] = "yes" if row["disabled_in_file"] else "no"
            out["noalert"] = "yes" if row["noalert"] else "no"
            out["syno_enabled"] = "yes" if row["syno_enabled"] else "no"
            w.writerow(out)

    active = [r for r in all_rows if not r["disabled_in_file"]]
    commented = [r for r in all_rows if r["disabled_in_file"]]

    def count_by(rows, key):
        c = Counter(r[key] or "(none)" for r in rows)
        return dict(c.most_common())

    by_file = defaultdict(lambda: {"active": 0, "commented": 0, "drop": 0, "pass": 0, "alert": 0})
    for r in all_rows:
        b = by_file[r["file"]]
        if r["disabled_in_file"]:
            b["commented"] += 1
        else:
            b["active"] += 1
            b[r["action"]] = b.get(r["action"], 0) + 1

    file_rows = []
    for name, b in sorted(by_file.items(), key=lambda kv: -kv[1]["active"] - kv[1]["commented"]):
        file_rows.append({"file": name, **b, "total": b["active"] + b["commented"]})

    syno_drop = [r for r in active if r["syno_default_action"] == "drop"]
    syno_disabled = [r for r in active if r["syno_default_action"] == "disabled"]
    syno_alert = [r for r in active if r["syno_default_action"] == "alert"]

    cve_rows = [r for r in active if r["cves"]]
    cve_set: set[str] = set()
    for r in cve_rows:
        cve_set.update(r["cves"].split("|"))

    # duplicate SIDs
    sid_files = defaultdict(set)
    for r in all_rows:
        if r["sid"]:
            sid_files[r["sid"]].add(r["file"])
    dup_sids = {str(s): sorted(list(fs)) for s, fs in sid_files.items() if len(fs) > 1}

    msg_prefix = Counter()
    for r in active:
        msg = r["msg"]
        # ET MALWARE Foo -> ET MALWARE
        parts = msg.split()
        if len(parts) >= 2 and parts[0] in {"ET", "GPL", "ETPRO"}:
            msg_prefix[" ".join(parts[:2])] += 1
        else:
            msg_prefix[parts[0] if parts else "(empty)"] += 1

    sids = [r["sid"] for r in active if r["sid"]]
    summary = {
        "source_tarball": "unpacked/package/etc/rules/emerging.rules.tar.gz",
        "source_version_txt": "9840",
        "tarball_mtime": "2021-09-09",
        "custom_rule_file": "unpacked/package/etc/rules/syno-custom-events.rules",
        "catalog_csv": "docs/data/bundled-alerts.csv",
        "extracted_dir": "extracted/emerging-rules/rules",
        "parse_errors": parse_errors,
        "totals": {
            "parsed_rules": len(all_rows),
            "active": len(active),
            "commented_out": len(commented),
            "unique_sids_active": len(set(sids)),
            "unique_sids_all": len(sid_files),
            "duplicate_sids_across_files": len(dup_sids),
            "noalert": sum(1 for r in active if r["noalert"]),
            "with_cve_ref": len(cve_rows),
            "unique_cves": len(cve_set),
        },
        "by_action_active": count_by(active, "action"),
        "by_proto_active": count_by(active, "proto"),
        "by_severity_active": count_by(active, "severity"),
        "by_classtype_active": count_by(active, "classtype"),
        "by_license_active": count_by(active, "license"),
        "by_sid_family_active": count_by(active, "sid_family"),
        "synology_policy_on_active": {
            "default_drop": len(syno_drop),
            "default_alert": len(syno_alert),
            "disabled_class": len(syno_disabled),
        },
        "synology_drop_by_classtype": count_by(syno_drop, "classtype"),
        "synology_disabled_by_classtype": count_by(syno_disabled, "classtype"),
        "by_file": file_rows,
        "top_msg_prefixes": dict(msg_prefix.most_common(40)),
        "sid_range_active": {"min": min(sids) if sids else None, "max": max(sids) if sids else None},
        "commented_by_file": [
            {"file": n, "commented": b["commented"]}
            for n, b in sorted(by_file.items(), key=lambda kv: -kv[1]["commented"])
            if b["commented"]
        ],
        "custom_rules": [
            {k: r[k] for k in ("sid", "action", "msg", "classtype", "file")}
            for r in all_rows
            if r["file"] == "syno-custom-events.rules"
        ],
        "threshold_overrides": [
            {
                "sid": 2101411,
                "reason": "GPL SNMP public access udp flood",
                "limit": "1 / 60s by_dst",
            },
            {
                "sid": 2013504,
                "reason": "ET POLICY GNU/Linux APT User-Agent",
                "limit": "1 / 60s by_src",
            },
        ],
    }
    (OUT_DIR / "bundled-alerts-summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary["totals"], indent=2))
    print("files", len(file_rows))
    print("wrote", csv_path, "rows", len(all_rows))


if __name__ == "__main__":
    main()
