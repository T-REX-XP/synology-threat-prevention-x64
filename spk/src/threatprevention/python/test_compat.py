#!/usr/bin/env python3
"""Local envelope checks (no NAS required)."""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ.setdefault("TPS_PKGVAR", tempfile.mkdtemp(prefix="tps-test-"))
os.environ.setdefault("TPS_PKGETC", os.environ["TPS_PKGVAR"])
os.environ.setdefault("TPS_PKGDEST", os.environ["TPS_PKGVAR"])

from compat import (  # noqa: E402
    classify_update,
    official_map,
    official_policy_write,
    official_sensor,
    official_source,
    official_storage,
    official_update_status,
)
from compiler import parse_header, parse_refs  # noqa: E402
from ingest import payload_hex  # noqa: E402


def check(cond, msg):
    if not cond:
        raise SystemExit("FAIL: " + msg)


sensor = official_sensor(
    {"enable_sensor": True, "interface_list": [{"if_id": "ovs_eth0", "enabled": True}]},
    "running",
    12,
    "ovs_eth0",
    ["ovs_eth0", "eth0"],
)
check(sensor["status"] == "engine_start", "sensor status")
check(sensor["interface"] == "ovs_eth0", "sensor interface")
check(any(x["if_id"] == "eth0" for x in sensor["interface_list"]), "live iface merge")

empty = official_sensor({"enable_sensor": True, "interface_list": ""}, "running", 1, "", ["ovs_eth0", "eth0"])
check(empty["interface"] == "ovs_eth0", "empty iface prefers ovs_eth0")
check(any(x["if_id"] == "ovs_eth0" and x["enabled"] for x in empty["interface_list"]), "empty live enable")

src = official_source("et-pro", "abc")
check(src["use_code"] == "etPro" and src["support_etpro"] is True, "source use_code")

stor = official_storage(1234, 1024, "idle")
check(stor["db_size"] == "db_size_1gb" and stor["db_size_bytes"] == 1234, "storage db_size")

upd = official_update_status("updating", "2026-09-07 12:00:00", "", "9")
check(upd["status"] == "updating" and upd["data"]["status"] == "updating", "update nested status")
check(upd["task_id"] == "9", "update task_id")

mp = official_map(None, ["7days", "30days"])
check("days7" in mp and "location" in mp["days7"], "map buckets")

check(payload_hex({"payload": "YWI="}) == "6162", "eve payload base64->hex")

check(official_policy_write(False) == {"need_force": False}, "policy write ok")
check(official_policy_write(True)["need_force"] is True, "policy need_force")
check(classify_update(False, False, False) == "new_version", "never-updated stays new")
check(classify_update(True, False, False) == "connect_error", "updated but unreachable")
check(classify_update(True, True, True) == "new_version", "remote newer")
check(classify_update(True, True, False) == "up_to_date", "current")

raw = 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"x"; reference:url,example.com/a; reference:cve,2024-1; sid:1;)'
ip_src, port_src, ip_dst, port_dst = parse_header(raw)
check(ip_src == "$HOME_NET" and port_dst == "any", "rule header")
refs = parse_refs(raw)
check(refs[0]["ref_system_name"] == "url" and refs[1]["ref_tag"] == "2024-1", "rule refs")
print("ok")
