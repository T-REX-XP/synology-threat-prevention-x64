#!/usr/bin/env python3
"""Parse ET rules, apply policy_*, write suricata.rules."""
import argparse
import os
import re
import shutil
import subprocess
import tempfile

from accel import accel_cli_sets
from engine_control import command_ok
from paths import PKGDEST, PKGVAR, RULES_OUT, SURICATA_BIN, YAML_PATH
from store import init_db

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
LEGACY_FILTER = re.compile(
    r'^(alert|drop|pass) ip .* \(msg:"policy filter sid \d+"; sid:\d+; rev:1; classtype:not-suspicious;\)$'
)


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


def import_rules(conn=None, *, catalog=None, commit=True):
    own = conn is None
    conn = conn or init_db()
    class_ids = {r["sig_class_name"]: r["sig_class_id"] for r in conn.execute("SELECT sig_class_id, sig_class_name FROM sig_class")}
    seen = 0
    if catalog is not None:
        conn.execute("DELETE FROM signature")
    for path in ([catalog] if catalog is not None else rule_sources()):
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            if catalog is not None:
                raise
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
    if catalog is not None and not seen:
        raise ValueError("Downloaded rule catalog contains no usable signatures")
    refresh_class_counts(conn)
    if commit or own:
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


def compile_rules(conn=None, path=None):
    own = conn is None
    conn = conn or init_db()
    if conn.execute("SELECT COUNT(*) FROM signature").fetchone()[0] == 0:
        import_rules(conn, commit=own)
    path = path or RULES_OUT
    os.makedirs(os.path.dirname(path), exist_ok=True)
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
    # Address-scoped exceptions are applied by ingest to the original SID.
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.replace(tmp, path)
    if own:
        conn.close()
    return len(lines)


def activate_rules(conn, *, running, catalog=None):
    """Validate the pending DB changes and publish the rules as one operation."""
    rules_dir = os.path.dirname(RULES_OUT)
    os.makedirs(rules_dir, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".activate-", dir=rules_dir) as tmp:
        candidate = os.path.join(tmp, "candidate.rules")
        live_catalog = os.path.join(rules_dir, "catalog.rules")
        published = []
        try:
            if catalog is not None:
                import_rules(conn, catalog=catalog, commit=False)
            compile_rules(conn, candidate)
            subprocess.run(
                [SURICATA_BIN, "-T", "--init-errors-fatal", "-c", YAML_PATH,
                 "-S", candidate, "-l", tmp, "--set", "unix-command.enabled=no", *accel_cli_sets()],
                check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            files = [(candidate, RULES_OUT)]
            if catalog is not None:
                staged_catalog = shutil.copyfile(catalog, os.path.join(tmp, "catalog.rules"))
                files.append((staged_catalog, live_catalog))
                marker = os.path.join(tmp, ".from-suricata-update")
                with open(marker, "w", encoding="utf-8"):
                    pass
                files.append((marker, os.path.join(rules_dir, ".from-suricata-update")))
            for staged, destination in files:
                previous = os.path.join(tmp, os.path.basename(destination) + ".previous")
                if os.path.isfile(destination):
                    shutil.copy2(destination, previous)
                else:
                    previous = None
                os.replace(staged, destination)
                published.append((destination, previous))
            if running and not command_ok("reload-rules", timeout=120):
                raise RuntimeError("Suricata rejected the rules reload")
            conn.commit()
        except Exception:
            conn.rollback()
            for destination, previous in reversed(published):
                if previous:
                    os.replace(previous, destination)
                else:
                    os.unlink(destination)
            if running and published:
                command_ok("reload-rules", timeout=120)
            raise


def remove_legacy_filters():
    """Strip only the generic IP rules generated by earlier package releases."""
    if not os.path.isfile(RULES_OUT):
        return
    with open(RULES_OUT, encoding="utf-8") as fh:
        lines = fh.readlines()
    kept = [line for line in lines if not LEGACY_FILTER.fullmatch(line.rstrip())]
    if len(kept) != len(lines):
        with open(RULES_OUT + ".migration", "w", encoding="utf-8") as fh:
            fh.writelines(kept)
        shutil.copymode(RULES_OUT, RULES_OUT + ".migration")
        os.replace(RULES_OUT + ".migration", RULES_OUT)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog")
    parser.add_argument("--remove-legacy-filters", action="store_true")
    args = parser.parse_args()
    if args.remove_legacy_filters:
        remove_legacy_filters()
    else:
        from tpsweb import engine_status

        conn = init_db()
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            activate_rules(conn, running=engine_status()[0] == "running", catalog=args.catalog)
        conn.close()
