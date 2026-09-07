#!/usr/bin/env python3
"""Parse ET rules, apply policy_*, write suricata.rules."""
import os
import re
import subprocess

from paths import CLASSIFICATION, PKGDEST, PKGVAR, RULES_OUT, SIGNATURE_CONF, SURICATA_SOCKET, SURICATASC
from store import connect, init_db, parse_signature_conf

ACTION_RE = re.compile(r"^(alert|drop|pass|reject|rejectsrc|rejectdst)\s+", re.I)
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;", re.I)
REV_RE = re.compile(r"\brev\s*:\s*(\d+)\s*;", re.I)
MSG_RE = re.compile(r'\bmsg\s*:\s*"([^"]*)"', re.I)
CLASS_RE = re.compile(r"\bclasstype\s*:\s*([^;]+)\s*;", re.I)
PROTO_RE = re.compile(r"^(?:alert|drop|pass|reject)\s+(\S+)", re.I)
HEADER_RE = re.compile(
    r"^(?:alert|drop|pass|reject)\s+\S+\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)",
    re.I,
)
REF_RE = re.compile(r"\breference\s*:\s*([^,;]+)\s*,\s*([^;]+)\s*;", re.I)


def parse_refs(raw):
    refs = []
    for match in REF_RE.finditer(raw or ""):
        refs.append({
            "ref_system_name": match.group(1).strip().lower(),
            "ref_tag": match.group(2).strip(),
        })
    return refs


def parse_header(raw):
    match = HEADER_RE.search((raw or "").lstrip("# ").lstrip())
    if not match:
        return "any", "any", "any", "any"
    return match.group(1), match.group(2), match.group(3), match.group(4)


def rule_sources():
    paths = []
    catalog = os.path.join(PKGVAR, "rules", "catalog.rules")
    extracted = os.path.join(PKGDEST, "etc", "rules", "suricata", "rules")
    if os.path.isfile(catalog):
        return [catalog]
    if os.path.isdir(extracted):
        for name in sorted(os.listdir(extracted)):
            if name.endswith(".rules"):
                paths.append(os.path.join(extracted, name))
    live = os.path.join(PKGVAR, "rules", "suricata.rules")
    if not paths and os.path.isfile(live):
        paths.append(live)
    return paths


def unfold(text):
    return re.sub(r"\\\s*\n", " ", text)


def parse_rule_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if not ACTION_RE.match(line):
        return None
    sid_m = SID_RE.search(line)
    if not sid_m:
        return None
    proto_m = PROTO_RE.match(line)
    return {
        "action": ACTION_RE.match(line).group(1).lower(),
        "sig_sid": int(sid_m.group(1)),
        "sig_rev": int(REV_RE.search(line).group(1)) if REV_RE.search(line) else 1,
        "sig_name": MSG_RE.search(line).group(1) if MSG_RE.search(line) else "",
        "classtype": (CLASS_RE.search(line).group(1).strip() if CLASS_RE.search(line) else "unknown"),
        "sig_protocol": proto_m.group(1).lower() if proto_m else "ip",
        "raw": line,
    }


def import_rules(conn=None):
    own = conn is None
    conn = conn or init_db()
    class_ids = {r["sig_class_name"]: r["sig_class_id"] for r in conn.execute("SELECT sig_class_id, sig_class_name FROM sig_class")}
    seen = 0
    for path in rule_sources():
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for line in unfold(text).splitlines():
            rec = parse_rule_line(line)
            if not rec:
                continue
            cid = class_ids.get(rec["classtype"])
            if not cid:
                conn.execute(
                    "INSERT OR IGNORE INTO sig_class(sig_class_name, sig_class_description, sig_priority) VALUES (?,?,3)",
                    (rec["classtype"], rec["classtype"]),
                )
                cid = conn.execute("SELECT sig_class_id FROM sig_class WHERE sig_class_name=?", (rec["classtype"],)).fetchone()["sig_class_id"]
                class_ids[rec["classtype"]] = cid
            ip_src, port_src, ip_dst, port_dst = parse_header(rec["raw"])
            refs = parse_refs(rec["raw"])
            ref_text = ";".join("%s,%s" % (x["ref_system_name"], x["ref_tag"]) for x in refs)
            conn.execute(
                """INSERT OR REPLACE INTO signature(
                    sig_sid, sig_rev, sig_name, sig_class_id, sig_default_action, sig_action,
                    sig_protocol, sig_ip_src, sig_ip_dst, sig_port_src, sig_port_dst,
                    sig_noalert, sig_ref, sig_raw_rule, sig_using)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,0,?,?,1)""",
                (
                    rec["sig_sid"], rec["sig_rev"], rec["sig_name"], cid,
                    rec["action"], rec["action"], rec["sig_protocol"],
                    ip_src, ip_dst, port_src, port_dst, ref_text, rec["raw"],
                ),
            )
            seen += 1
    refresh_class_counts(conn)
    conn.commit()
    if own:
        conn.close()
    return seen


def refresh_class_counts(conn):
    conn.execute(
        """UPDATE sig_class SET
           sig_total_count = (SELECT COUNT(*) FROM signature s WHERE s.sig_class_id = sig_class.sig_class_id),
           sig_enabled_count = (SELECT COUNT(*) FROM signature s WHERE s.sig_class_id = sig_class.sig_class_id AND s.sig_using=1)"""
    )


def class_action(conn, class_id):
    row = conn.execute("SELECT action FROM policy_class WHERE sig_class_id=?", (class_id,)).fetchone()
    return row["action"] if row else None


def sid_action(conn, sid):
    row = conn.execute("SELECT action FROM policy_signature WHERE raw_sid=?", (sid,)).fetchone()
    return row["action"] if row else None


def apply_action(raw, action):
    if action in ("disable", "disabled", "nothing"):
        if raw.lstrip().startswith("#"):
            return raw
        return "# " + raw
    body = raw.lstrip("# ").lstrip()
    new_act = "alert"
    if action == "drop":
        new_act = "drop"
    elif action == "pass":
        new_act = "pass"
    elif action == "reject":
        new_act = "reject"
    return ACTION_RE.sub(new_act + " ", body, count=1)


def compile_rules(conn=None):
    own = conn is None
    conn = conn or init_db()
    if conn.execute("SELECT COUNT(*) FROM signature").fetchone()[0] == 0:
        import_rules(conn)
    os.makedirs(os.path.dirname(RULES_OUT), exist_ok=True)
    lines = []
    for rec in conn.execute("SELECT sig_sid, sig_class_id, sig_raw_rule, sig_action FROM signature ORDER BY sig_sid"):
        action = sid_action(conn, rec["sig_sid"])
        if action is None:
            action = class_action(conn, rec["sig_class_id"])
        if action is None:
            action = rec["sig_action"] or "alert"
        raw = rec["sig_raw_rule"]
        if not raw:
            continue
        lines.append(apply_action(raw, action))
    # filter policies: extra pass/drop lines by IP (best-effort suppress via threshold-like pass)
    for flt in conn.execute("SELECT * FROM policy_filter"):
        sid = flt["raw_sid"]
        src = flt["ip_src_str"] or "any"
        dst = flt["ip_dst_str"] or "any"
        act = "pass" if flt["action"] in ("pass", "disable") else flt["action"]
        lines.append(
            '%s ip %s any -> %s any (msg:"policy filter sid %s"; sid:%s; rev:1; classtype:not-suspicious;)'
            % (act if act in ("alert", "drop", "pass") else "pass", src, dst, sid, 4000000 + int(flt["id"] or 0))
        )
    tmp = RULES_OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.replace(tmp, RULES_OUT)
    if own:
        conn.close()
    return len(lines)


def reload_suricata():
    if os.path.isfile(SURICATASC) and os.path.exists(SURICATA_SOCKET):
        try:
            subprocess.run(
                [SURICATASC, "-c", SURICATA_SOCKET, "reload-rules"],
                timeout=60,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except (OSError, subprocess.SubprocessError):
            return False
    return False


if __name__ == "__main__":
    conn = init_db()
    print("imported", import_rules(conn))
    print("compiled", compile_rules(conn), "rules ->", RULES_OUT)
    reload_suricata()
    conn.close()
