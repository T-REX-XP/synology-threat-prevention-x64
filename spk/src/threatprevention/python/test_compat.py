#!/usr/bin/env python3
"""Local envelope checks (no NAS required)."""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs
from unittest import TestCase
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ.setdefault("TPS_PKGVAR", tempfile.mkdtemp(prefix="tps-test-"))
os.environ.setdefault("TPS_PKGETC", os.environ["TPS_PKGVAR"])
os.environ.setdefault("TPS_PKGDEST", os.environ["TPS_PKGVAR"])

from compat import (  # noqa: E402
    SETCAP_CMD,
    capture_capable,
    classify_update,
    official_devices,
    official_event,
    official_event_statistic,
    official_map,
    official_policy_list,
    official_policy_write,
    official_sensor,
    official_signature_classes,
    official_source,
    official_stat_bucket,
    official_storage,
    official_trends,
    official_update_status,
    official_variables,
    official_weekday,
    parse_weekday,
)
from compiler import RuleActivationError, activate_rules, import_rules, parse_header, parse_refs, remove_legacy_filters  # noqa: E402
from engine_control import command_ok  # noqa: E402
from geoip import COUNTRY_BEGIN, COUNTRY_CODES, is_public_ipv4, lookup as geoip_lookup  # noqa: E402
from host_info import lookup_host  # noqa: E402
from ingest import follow, insert_alert, payload_hex, rotate_raw_logs  # noqa: E402
from feeds import add_feed, feed_url_ok, list_feeds, seed_catalog_feeds  # noqa: E402
from rule_sources import catalog_entries, source_urls  # noqa: E402
from notify import list_filters, maybe_notify, notify_operation, read_telegram_conf, upsert_filters, write_telegram_conf  # noqa: E402
from corehost import _parse_isc_leases, _parse_syno_info, usb_list, systemdb_get  # noqa: E402
from store import init_db, kv_get, kv_set, rotate_if_needed, storage_size  # noqa: E402
from api_routes import BY_API, EXACT, UPDATE_PREFIX  # noqa: E402
from tpsweb import (  # noqa: E402
    SENSOR_CONF,
    _parse_multipart,
    ensure_export_dir,
    fetch_osm_tile,
    filestation_path_for,
    handle,
    read_gmaps_key,
    start_job,
    write_sensor,
    write_update_source,
)
from tpsweb import JOBS  # noqa: E402
import tpsweb as tpsweb_mod  # noqa: E402


def check(cond, msg):
    if not cond:
        raise SystemExit("FAIL: " + msg)


def check_event_map():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Path(tmp) / "GeoIP.dat"
        # A two-leaf trie for public test addresses with different first bits.
        left = (COUNTRY_BEGIN + COUNTRY_CODES.index("US")).to_bytes(3, "little")
        right = (COUNTRY_BEGIN + COUNTRY_CODES.index("DE")).to_bytes(3, "little")
        site = Path(tmp) / "map-site.json"
        with patch("geoip.geoip_files", side_effect=lambda: [str(fixture)] if fixture.exists() else []), \
                patch("geoip.time.monotonic", return_value=100) as clock, patch("compat.MAP_SITE", str(site)):
            now = int(time.time())
            with init_db(":memory:") as map_conn:
                outbound = ("192.168.1.130", "8.8.8.8", "STUN outbound", now, 2)
                inbound = ("142.250.1.1", "192.168.1.130", "Inbound", now - 8 * 86400, 1)
                lan = ("192.168.1.130", "192.168.1.1", "LAN only", now, 3)
                insert = ("INSERT INTO event(ip_src_str, ip_dst_str, sig_name, ts_epoch, impact_flag, timestamp) "
                          "VALUES (?,?,?,?,?,'2026-01-01 00:00:00')")
                map_conn.executemany(insert, [outbound, inbound, lan, outbound])
                map_conn.executemany(insert, [
                    ("192.168.1.7", "192.168.1.8", "unmappable %d" % i, now, 3)
                    for i in range(200) for _ in range(3)
                ])
                response = handle("SYNO.TPS.Event.Map", "list", {}, map_conn)
                check(response["data"]["days7"]["location"] == [], "map without GeoIP or site")
                fixture.write_bytes(left + right + bytes(1024))
                clock.return_value += 5
                response = handle("SYNO.TPS.Event.Map", "list", {"date_range": ["days7"]}, map_conn)
                locations = response["data"]["days7"]["location"]
                check(len(locations) == 1 and locations[0]["mapped_endpoint"] == "target",
                      "outbound pin survives unmappable groups above the marker limit")
                pin = locations[0]
                check((pin["ip_src"], pin["ip_dst"], pin["country"], pin["count"], pin["priority"]) ==
                      ("192.168.1.130", "8.8.8.8", "US", 2, 2), "outbound pin contract")
                check(any(row["country"] == "DE" and row["mapped_endpoint"] == "source"
                          for row in response["data"]["days30"]["location"]), "older inbound pin")
                map_conn.execute("DELETE FROM event WHERE sig_name LIKE 'unmappable %'")
                site.write_text('{"lat": 0, "lng": 2.5}', encoding="utf-8")
                locations = official_map(map_conn)["days7"]["location"]
                check(any(row["mapped_endpoint"] == "site" and row["lat"] == 0 and row["lng"] == 2.5
                          for row in locations), "LAN event at explicitly configured site")
                site.write_text('{"lat": 120, "lng": 2.5}', encoding="utf-8")
                check(len(official_map(map_conn)["days7"]["location"]) == 1, "invalid site ignored")


def check_telegram_alert():
    event = {
        "event_type": "alert", "timestamp": "2026-11-25T19:24:00+0000",
        "src_ip": "192.168.1.130", "src_port": 52500,
        "dest_ip": "2606:4700::1111", "dest_port": 3478,
        "proto": "UDP", "app_proto": "stun",
        "ether": {"src_mac": "5a:11:22:33:44:55", "dest_mac": "00:11:22:33:44:55"},
        "alert": {"signature": "STUN <binding> & reply", "category": "Test", "severity": 2,
                  "signature_id": 1234, "rev": 5, "action": "allowed"},
    }
    with init_db(":memory:") as alert_conn:
        check(insert_alert(alert_conn, event), "ingest Telegram test event")
        check(alert_conn.execute("SELECT mac_src FROM event").fetchone()[0] == event["ether"]["src_mac"],
              "ingest stores EVE Ethernet details")
        kv_set(alert_conn, "enable_telegram", "1")
        with patch("notify.read_telegram_conf", return_value={"token": "123:test", "chat": "1"}), \
                patch("host_info._local_records", return_value=({}, {})), \
                patch("host_info._run", side_effect=["", " WORKGROUP <00> - <GROUP>\n DESKTOP <00> - <ACTIVE>"]) as resolver, \
                patch("notify.urlopen") as send:
            send.return_value.__enter__.return_value.read.return_value = b'{"ok": true}'
            check(maybe_notify(alert_conn, "Test", event["alert"]["signature"], 2, event["src_ip"], event=event),
                  "Telegram alert delivered through fake transport")
            request = send.call_args[0][0]
            fields = parse_qs(request.data.decode())
            message = fields["text"][0]
            check(fields["parse_mode"] == ["HTML"] and "STUN &lt;binding&gt; &amp; reply" in message,
                  "Telegram HTML mode and escaped signature")
            check(all(value in message for value in (
                "192.168.1.130:52500", "[2606:4700::1111]:3478", "NetBIOS <code>DESKTOP</code>",
                "Captured link MAC <code>5a:11:22:33:44:55</code>", "Priority 2 (Medium)",
                "1234 rev 5", "UDP", "allowed", event["timestamp"],
            )), "Telegram endpoints and alert context")
            check(event["ether"]["dest_mac"] not in message and resolver.call_count == 2,
                  "public endpoint does not trigger local discovery")
            check(not maybe_notify(alert_conn, "Test", "another", 2, event["src_ip"], event=event),
                  "Telegram alert interval preserved")
    with patch("host_info._local_records", return_value=(
        {"192.168.1.140": "nas-client"}, {"192.168.1.140": {"mac": "5a:11:22:33:44:99"}},
    )), patch("host_info._run") as resolver:
        check(lookup_host("192.168.1.140") == {"hostname": "nas-client", "mac": "5a:11:22:33:44:99"},
              "local host inventory provides hostname and MAC")
        resolver.assert_not_called()


check_event_map()
check_telegram_alert()


def check_retention():
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "events.db")
        with init_db(db) as conn:
            kv_set(conn, "storage_limit_mb", "1")
            for i in range(350):
                cid = conn.execute("INSERT INTO event(timestamp, ts_epoch) VALUES ('test',?)", (i,)).lastrowid
                conn.execute("INSERT INTO data(sid,cid,data_payload) VALUES (1,?,?)", (cid, "a" * 4000))
            conn.commit()
            removed = rotate_if_needed(conn, db)
            remaining = [row[0] for row in conn.execute("SELECT cid FROM event ORDER BY cid")]
            check(0 < removed < 350 and remaining == list(range(removed + 1, 351)),
                  "retention removes oldest events and preserves the newest")
            check(conn.execute("SELECT COUNT(*) FROM data").fetchone()[0] == len(remaining),
                  "retention deletes matching payloads")
            check(storage_size(db) <= 1024 * 1024, "main database and WAL fit after retention")
        with init_db(str(Path(tmp) / "wal.db")) as conn:
            db = str(Path(tmp) / "wal.db")
            kv_set(conn, "storage_limit_mb", "1")
            conn.execute("INSERT INTO event(timestamp, ts_epoch) VALUES ('test',1)")
            conn.commit()
            conn.execute("PRAGMA wal_autocheckpoint=0")
            for i in range(300):
                kv_set(conn, "fixture", str(i))
                conn.commit()
            check(storage_size(db) > 1024 * 1024, "WAL fixture exceeds quota")
            check(rotate_if_needed(conn, db) == 0, "checkpoint alone avoids pruning for WAL-only growth")
            check(storage_size(db) < 1024 * 1024, "WAL is reclaimed")


def check_raw_rotation():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        eve = root / "eve.json"
        eve.write_bytes(b'{"id":1}\n{"id":2}\n')
        old = eve.stat()
        (root / "ingest.offset").write_text(
            json.dumps({"file": [old.st_dev, old.st_ino], "offset": len(b'{"id":1}\n')}), encoding="utf-8"
        )

        def reopen(_command, **_kwargs):
            eve.write_bytes(b'{"id":3}\n{"id":')
            return True

        def finish_line(_delay):
            with eve.open("ab") as fh:
                fh.write(b'4}\n')

        with patch("ingest.command_ok", side_effect=reopen):
            rotate_raw_logs(str(eve), True, limit=1)
        check((root / "eve.json.1").stat().st_ino == old.st_ino, "raw EVE is renamed for rotation")
        with patch("ingest.PKGVAR", tmp), patch("ingest.rotate_raw_logs"), patch("ingest.time.sleep") as sleep:
            def wait(delay):
                check(sleep.call_count <= 2, "rotated tail reaches the complete line")
                if sleep.call_count == 2:
                    finish_line(delay)

            sleep.side_effect = wait
            tail = follow(str(eve), lambda: None)
            check([json.loads(next(tail))["id"] for _ in range(3)] == [2, 3, 4],
                  "tail resumes the archive before the new file and waits for a complete line")
            tail.close()
        with patch("ingest.command_ok", return_value=False):
            rotate_raw_logs(str(eve), True, limit=1)
        check(eve.exists() and eve.read_bytes().startswith(b'{"id":3}'), "failed reopen restores active path")


def check_rule_activation():
    rule = ('alert tcp any any -> any 443 (msg:"Fixture"; '
            'flow:to_server; classtype:not-suspicious; sid:%d; rev:1;)\n')
    with tempfile.TemporaryDirectory() as tmp, init_db(":memory:") as conn:
        root = Path(tmp)
        active = root / "suricata.rules"
        catalog = root / "catalog.rules"
        downloaded = root / "download.rules"
        active.write_text(rule % 12345, encoding="utf-8")
        catalog.write_text(rule % 12345, encoding="utf-8")
        downloaded.write_text(rule % 12346, encoding="utf-8")
        with patch("compiler.RULES_OUT", str(active)), patch("compiler.rule_sources", return_value=[str(catalog)]), \
                patch("compiler.accel_cli_sets", return_value=[]), \
                patch("operations.OPERATIONS_LOG", str(root / "operations.log")), \
                patch("compiler.subprocess.run") as validate, patch("compiler.command_result") as engine:
            import_rules(conn)

            def invalid_rules(_command, *, stdout, **_kwargs):
                stdout.write(b"Invalid keyword in fixture from https://example.com/private-code/rules\n")
                raise subprocess.CalledProcessError(1, "suricata")

            validate.side_effect = invalid_rules
            with TestCase().assertRaises(RuleActivationError):
                activate_rules(conn, running=True, catalog=str(downloaded))
            check(active.read_text() == rule % 12345 and not engine.called, "invalid rules never replace the live file")
            diagnostics = (root / "operations.log").read_text()
            check("[validator] Invalid keyword" in diagnostics and "private-code" not in diagnostics,
                  "validation failure keeps diagnostics and redacts feed URLs")
            validate.side_effect = None
            engine.side_effect = [(False, "new rules rejected"), (True, "done")]
            with TestCase().assertRaises(RuleActivationError):
                activate_rules(conn, running=True, catalog=str(downloaded))
            check(active.read_text() == catalog.read_text() == rule % 12345 and engine.call_count == 2,
                  "failed reload restores both files and requests the old rules")
            check(conn.execute("SELECT sig_sid FROM signature").fetchone()[0] == 12345, "failed reload rolls back catalog")
            engine.side_effect = [(False, "new rules rejected"), (False, "socket unavailable")]
            with TestCase().assertRaises(RuleActivationError) as rejected:
                activate_rules(conn, running=True, catalog=str(downloaded))
            check(rejected.exception.rollback_failed, "rollback reload failure is distinguished")
            check("Rollback reload failed: socket unavailable" in (root / "operations.log").read_text(),
                  "logs failed rollback with engine reason")
            engine.side_effect = None
            engine.return_value = (True, "done")
            activate_rules(conn, running=True, catalog=str(downloaded))
            check(active.read_text() == catalog.read_text() == rule % 12346, "valid candidate is activated")
            check([row[0] for row in conn.execute("SELECT sig_sid FROM signature")] == [12346],
                  "signatures deleted upstream leave the active catalog")
            legacy = 'pass ip any any -> any any (msg:"policy filter sid 12346"; sid:4000001; rev:1; classtype:not-suspicious;)\n'
            active.write_text(rule % 12346 + legacy, encoding="utf-8")
            remove_legacy_filters()
            check(active.read_text() == rule % 12346, "upgrade removes only old synthetic exception rules")

        params = {"sid": 12346, "ip_src": "192.168.1.0/24", "ip_dst": "2606:4700::1111"}
        check(not handle("SYNO.TPS.Signature.Policy", "add", dict(params, action="drop"), conn)["success"],
              "scoped enforcement is unavailable on a passive sensor")
        check(handle("SYNO.TPS.Signature.Policy", "add", dict(params, action="disable"), conn)["success"],
              "scoped exception is saved without changing the engine rules")
        alert = {"event_type": "alert", "src_ip": "192.168.1.2", "dest_ip": "2606:4700::1111",
                 "alert": {"signature_id": 12346}}
        check(not insert_alert(conn, alert), "scoped exception requires both endpoints")
        check(insert_alert(conn, dict(alert, dest_ip="2606:4700::1001")), "same signature outside scope is retained")
        check(insert_alert(conn, dict(alert, alert={"signature_id": 12345})), "other signatures remain visible")
    with patch("engine_control.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=b'{"return":"NOK"}')):
        check(not command_ok("reload-rules"), "socket refusal can have a successful client exit")


def check_operational_alerts():
    with init_db(":memory:") as conn:
        kv_set(conn, "enable_telegram", "1")
        kv_set(conn, "last_telegram_ts", str(int(time.time())))
        conn.commit()
        with patch("notify.read_telegram_conf", return_value={"token": "fake", "chat": "1"}), \
                patch("notify.send_telegram", return_value=True) as telegram:
            check(notify_operation(conn, "rule-update", "failed"), "recent threat alerts do not block operational notice")
            check(not notify_operation(conn, "rule-update", "failed again"), "repeated update failures are rate limited")
            check(notify_operation(conn, "rule-rollback", "rollback unconfirmed"), "rollback has its own cooldown")
            check(telegram.call_count == 2, "deduplicates update notices")
        kv_set(conn, "last_updated", "known successful update")
        conn.commit()
        failure = RuleActivationError("Reloading rules failed.", rollback_failed=True)
        with patch("tpsweb.write_update_source"), patch("tpsweb.fetch_and_activate_rules", side_effect=failure), \
                patch("tpsweb.log_operation"), patch("tpsweb.notify_operation") as notify:
            for trigger in ("Manual", "Scheduled"):
                job = {}
                tpsweb_mod.run_rule_update(conn, trigger, job)
                check(job["status"] == "error" and kv_get(conn, "last_updated") == "known successful update",
                      "update failure preserves the last successful timestamp")
                check(notify.call_args.args[1] == "rule-rollback" and trigger in notify.call_args.args[2],
                      "update failure sends a trigger-specific rollback alert")
            notify.reset_mock()
            with patch("tpsweb.fetch_and_activate_rules", return_value=0):
                tpsweb_mod.run_rule_update(conn, "Scheduled")
            check(kv_get(conn, "update_status") == "up_to_date" and kv_get(conn, "last_updated") != "known successful update",
                  "successful update advances the timestamp")
            check(not notify.called, "successful rule update is logged without a Telegram alert")
            tpsweb_mod.record_capture_health(conn, "down", "test issue")
            tpsweb_mod.record_capture_health(conn, "down", "test issue")
            tpsweb_mod.record_capture_health(conn, "up")
            tpsweb_mod.record_capture_health(conn, "disabled")
            check([call.args[1] for call in notify.call_args_list] == ["capture-down", "capture-up"],
                  "capture outage and recovery are notified once and disable is silent")
    with patch("tpsweb.mirror_status", return_value={"enabled": True, "tap_present": True, "ifname": "tps0"}), \
            patch("tpsweb.engine_status", return_value=("running", 1)), \
            patch("tpsweb.command_result", return_value=(True, {"ifaces": ["ovs_eth0"]})):
        check("tps0" in tpsweb_mod.capture_health_issue(),
              "capture watcher detects engine running on the wrong interface")


check_retention()
check_raw_rotation()
check_rule_activation()
check_operational_alerts()


sensor = official_sensor(
    {"enable_sensor": True, "interface_list": [{"if_id": "ovs_eth0", "enabled": True}]},
    "running",
    12,
    "ovs_eth0",
    ["ovs_eth0", "eth0"],
)
check(sensor["status"] == "engine_start", "sensor status")
check(sensor["prevention_enforced"] is False and sensor["ips_mode"] == "ids", "ids only")
check(sensor["enable_prevention"] is False, "ids chrome keeps drop-packet off")
check(sensor["network_security_mode"] == "availability", "default mode is availability")
check(capture_capable("suricata = cap_net_raw,cap_net_admin+ep") is True, "getcap text is capable")
check(capture_capable("", True) is True, "running engine is capable")
check(capture_capable("", False, "Error: Operation not permitted") is False, "EPERM without cap is not capable")
check(SETCAP_CMD.startswith("/usr/bin/setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep "), "setcap command")
lied = official_sensor(
    {
        "enable_sensor": True,
        "enable_prevention": True,
        "network_security_mode": "security",
        "interface_list": [{"if_id": "ovs_eth0", "enabled": True}],
    },
    "running", 1, "ovs_eth0", ["ovs_eth0"],
)
check(lied["enable_prevention"] is False, "sensor get ignores prevention checkbox")
check(lied["network_security_mode"] == "security", "sensor get keeps default mode")
check(sensor["interface"] == "ovs_eth0", "sensor interface")
check(all(x["if_id"] != "eth0" for x in sensor["interface_list"]), "hide ovs-enslaved eth0 twin")
check(any(x["if_id"] == "eth1" for x in official_sensor(
    {"enable_sensor": True, "interface_list": [{"if_id": "ovs_eth0", "enabled": True}]},
    "running", 1, "ovs_eth0", ["ovs_eth0", "eth1"],
)["interface_list"]), "live iface merge keeps extra nics")

empty = official_sensor({"enable_sensor": True, "interface_list": ""}, "running", 1, "", ["ovs_eth0", "eth0"])
check(empty["interface"] == "ovs_eth0", "empty iface prefers ovs_eth0")
check(any(x["if_id"] == "ovs_eth0" and x["enabled"] for x in empty["interface_list"]), "empty live enable")
check(all(x["if_id"] != "eth0" for x in empty["interface_list"]), "empty live drops eth0 twin")
check(all(x.get("status") for x in empty["interface_list"]), "iface link status")

none = official_sensor({"enable_sensor": True, "interface_list": ""}, "running", 1, "", [])
check(len(none["interface_list"]) >= 1, "fallback iface when sysfs empty")
check(any(x.get("enabled") for x in none["interface_list"]), "fallback enabled")

mir = official_sensor(
    {"enable_sensor": True, "interface_list": [{"if_id": "ovs_eth0", "enabled": True}]},
    "running", 1, "tps0", ["ovs_eth0", "tps0"], "tps0",
)
check(mir["interface"] == "tps0", "mirror capture pin")
check(any(x["if_id"] == "tps0" and x["enabled"] for x in mir["interface_list"]), "tps0 enabled")
check(all(not x["enabled"] for x in mir["interface_list"] if x["if_id"] != "tps0"), "no dual ovs+tps")

mir_on = official_sensor(
    {"enable_sensor": True, "interface_list": [{"if_id": "ovs_eth0", "enabled": True}]},
    "running", 1, "ovs_eth0", ["ovs_eth0"], "tps0", True,
)
check(mir_on["interface"] == "tps0", "mirror_enabled pins tps0 before tap exists")
check(any(x["if_id"] == "tps0" and x["enabled"] for x in mir_on["interface_list"]), "mirror_enabled injects tps0")

write_sensor({
    "enable_sensor": True,
    "enable_prevention": True,
    "network_security_mode": "security",
    "interface_list": "ovs_eth0",
})
sensor_txt = open(SENSOR_CONF, encoding="utf-8").read()
check("enable_prevention=no" in sensor_txt, "write_sensor forces prevention off")
check("network_security_mode=security" in sensor_txt, "write_sensor keeps default mode")


def _is_hosted(api):
    api = api or ""
    if str(api).startswith("SYNO.TPS."):
        return True
    return api in (
        "SYNO.Core.Network.NSM.Device",
        "SYNO.Core.SystemDB",
        "SYNO.Core.ExternalDevice.Storage.USB",
    )


def should_steal_request(opts):
    """Keep in lockstep with tps-bridge.js shouldStealRequest.

    DSM desktop polling uses SYNO.API.Request({compound}) and expects
    data.reg_ref. Stealing those compounds takes down the DSM session.
    """
    if not opts:
        return False
    webapi = opts.get("webapi") or {}
    api = opts.get("api") or webapi.get("api") or ""
    if "Polling" in str(api):
        return False
    if opts.get("is_polling_callback"):
        return False
    compound = opts.get("compound")
    if isinstance(compound, dict) and compound.get("params") is not None:
        return any(_is_hosted((item or {}).get("api")) for item in (compound.get("params") or []))
    return _is_hosted(api)


check(not should_steal_request({
    "api": "SYNO.API.Request.Polling.List",
    "compound": {"params": [{"api": "SYNO.Core.Desktop", "method": "get"}]},
}), "never steal Polling.* APIs")
check(not should_steal_request({
    "compound": {"params": [
        {"api": "SYNO.Core.Desktop", "method": "get"},
        {"api": "SYNO.Core.System.Utilization", "method": "get"},
    ]},
    "is_polling_callback": True,
}), "never steal DSM pollingCompoundCallback")
check(not should_steal_request({
    "compound": {"params": [
        {"api": "SYNO.Core.Desktop", "method": "get"},
        {"api": "SYNO.Entry.Request", "method": "request"},
    ]},
}), "Core-only compound stays on entry.cgi (reg_ref)")
check(should_steal_request({
    "compound": {"params": [
        {"api": "SYNO.TPS.Sensor", "method": "get"},
        {"api": "SYNO.TPS.Settings.Mirror", "method": "set"},
    ]},
}), "hosted TPS compound is stolen")
check(should_steal_request({"api": "SYNO.TPS.Sensor", "method": "get"}), "hosted TPS api is stolen")
check(not should_steal_request({"api": "SYNO.Core.System.Utilization", "method": "get"}), "Core api is not stolen")

bridge_dir = os.path.join(HERE, "..", "package", "ui", "bridge")
js = "".join(
    open(os.path.join(bridge_dir, name), encoding="utf-8").read()
    for name in ("transport.js", "dsm7.js", "settings-inject.js")
)
check("shouldStealRequest" in js, "bridge defines shouldStealRequest")
check('String(api).indexOf("Polling") !== -1' in js, "bridge refuses Polling APIs")
check("isPollingCallback" in js and "compoundHasHosted" in js, "bridge keeps reg_ref guards")
check("wrappedReq.Polling = origReq.Polling" in js, "Request wrap copies .Polling")
check("gateMonitoredIfaces" not in js, "no interfaceGrid setDisabled monkeypatch")
check('item.name === "enable_prevention"' in js, "drop-packet checkbox stays disabled")
check('item.name === "enable_prevention" || item.name === "network_security_mode"' not in js, "default mode radios stay enabled")
check("f.inputValue === \"availability\"" not in js, "do not force availability radio")
check("me.clearGeneralDirty(this);" in js, "General form snaps originalValue once")
check("setTimeout(function () { me.clearGeneralDirty" not in js, "no timer dirty-clears on General")
check("fallbackBase" not in js, "no :19557 fallback helper")
check(":19557" not in js, "no mixed-content host:19557 fallback")
check("return \"/webman/tps-api\"" in js, "same-origin tps-api is primary")
check("whenClass:" in js, "bridge shares Ext.define waiter")
check("Ext.define._tpsHook" in js, "whenClass skips poll if Ext.define is hooked")
check(js.count("tries > 80") == 1, "one Ext.define poll helper")
check("watchAssign:" in js, "bridge intercepts object-literal assigns")
check("this.watchAssign(\"SYNO.SDS.TPS.Utils\", \"SignatureUpdater\"" in js,
      "SignatureUpdater uses watchAssign not setInterval")
check("++n > 80" not in js, "no SignatureUpdater 25ms poll")
check("tps_cap_note" in js, "Overview banner when capture cap missing")
check("SYNO.TPS.Settings.Accel" in js, "bridge hosts Accel API")
check("Intel Hyperscan" in js, "General Hardware acceleration fieldset")
check("accel_mode" in js, "matching is a radio group")
check("accel_dpdk" not in js, "DPDK is not a fake checkbox")
check('"SYNO.TPS.Settings.Accel|set": 0' in js, "compound ranks Accel.set first")
check(SETCAP_CMD in js, "Overview banner prints exact setcap")
postinst = open(os.path.join(HERE, "..", "scripts", "postinst"), encoding="utf-8").read()
check("sudo " + SETCAP_CMD in postinst, "postinst prints exact sudo setcap")
chart_js = open(os.path.join(HERE, "..", "package", "ui", "tps-chart.js"), encoding="utf-8").read()
check("No trend data yet" in chart_js, "LineChart empty-state label")
check("No events in this period" in chart_js, "PieChart empty-state label")
check("tps-chart-empty" in chart_js, "empty chart CSS class")

src = official_source("et-pro", "abc")
check(src["use_code"] == "etPro" and src["support_etpro"] is True, "source use_code")
check(official_weekday("daily") == "0,1,2,3,4,5,6", "weekday daily for schedulefield")
check(parse_weekday("0,1,2,3,4,5,6") == "daily", "weekday csv full week")
check(parse_weekday("0,6") == "0,6", "weekday weekend")

stor = official_storage(1234, 1024, "idle")
check(stor["db_size"] == "db_size_1gb" and stor["db_size_bytes"] == 1234, "storage db_size")
check("logStorageMaxLimit" not in stor, "omit empty usb max")
stor_usb = official_storage(1234, 1024, "idle", usb_max="1.50 GB")
check(stor_usb["logStorageMaxLimit"] == "1.50 GB", "usb max when present")

upd = official_update_status("updating", "2026-09-07 12:00:00", "", "9")
check(upd["status"] == "updating" and upd["data"]["status"] == "updating", "update nested status")
check(upd["task_id"] == "9", "update task_id")
check(official_update_status("up_to_date")["last_updated"] == "not_updated_yet", "empty last_updated sentinel")
check(official_update_status("up_to_date")["data"]["last_updated"] == "not_updated_yet", "nested last_updated sentinel")
src = official_source("et-open", "")
check(src["use_code"] == "etOpen" and src["support_etpro"] is True, "source etOpen")
src_pro = official_source("et-pro", "abc")
check(src_pro["use_code"] == "etPro" and src_pro["code"] == "abc", "source etPro")

mp = official_map(None, ["7days", "30days"])
check("days7" in mp and "location" in mp["days7"], "map buckets")

check(payload_hex({"payload": "YWI="}) == "6162", "eve payload base64->hex")
check(not is_public_ipv4("10.0.0.1") and not is_public_ipv4("192.168.1.1"), "private ipv4")
check(is_public_ipv4("8.8.8.8"), "public ipv4")
check(geoip_lookup("192.168.1.1") is None, "lan has no pin")

conn = init_db()
cur = conn.execute(
    "INSERT INTO event(timestamp, ts_epoch, sig_name, ip_src_str, ip_dst_str, ip_proto) "
    "VALUES (?,?,?,?,?,?)",
    ("2026-01-01 00:00:00", 1, "l3-fallback", "8.8.8.8", "1.1.1.1", 6),
)
conn.commit()
row = conn.execute("SELECT * FROM event WHERE cid=?", (cur.lastrowid,)).fetchone()
ev = official_event(row, conn, detail=True)
check(ev["ip_ver"] == 4 and ev["tcp_seq"] == 0, "event get L3/L4 fallback")
bucket = official_stat_bucket(conn, 0)
check("country_src" in bucket and "botnet_ip_src" in bucket, "stat geo/botnet keys")
check(bucket["country_src"] == [] or isinstance(bucket["country_src"], list), "country_src list")

# Official synoips.js Store roots / FormPanel gets (see docs/api/official-app-surface.md).
classes = official_signature_classes([
    {"name": "trojan-activity", "class_name": "trojan-activity", "enabled": 1, "total": 4, "severity": 1},
])
check(isinstance(classes["signatures"], list) and classes["signatures"][0]["name"] == "trojan-activity",
      "Signature.list root signatures")
check(classes["signatures"][0]["severity"] == 1 and "enabledCount" in classes["signatures"][0],
      "signature class severity int")
policy_rows = official_policy_list([
    {"type": "class", "sig_name": "trojan-activity", "action": "alert"},
    {"type": "signature", "raw_sid": 2100001, "sig_name": "ET SCAN", "action": "alert"},
])
check(isinstance(policy_rows["list"], list) and policy_rows["list"][0]["type"] == 1, "Policy.list root list type int")
check(policy_rows["list"][1]["type"] == 2 and policy_rows["list"][1]["sid"] == 2100001, "policy signature type 2")
devs = official_devices([{"mac": "aa:bb:cc:dd:ee:ff", "device_name": "nas", "detect": True, "online": True}])
check(isinstance(devs["device_list"], list) and isinstance(devs["devices"], list), "Device.list roots")
check(devs["device_list"][0]["mesh_re"] is False, "device mesh_re skipped")
vars_ = official_variables({"HOME_NET": "[10.0.0.0/8]"})
check(vars_["home_net"] == "[10.0.0.0/8]" and "http_ports" in vars_, "Sensor.Variables lowercase")
tr = official_trends(conn)
check(isinstance(tr["trends"], list) and "points" in tr, "Trends Store series")
estat = official_event_statistic(conn)
check(all(k in estat for k in ("days7", "days30", "all_logs")), "Event.Statistic buckets")
check(all(k in estat["days7"] for k in ("class_name", "ip_src", "ip_dst", "botnet_ip_src", "country_src")),
      "Event.Statistic pie keys")

listed = handle("SYNO.TPS.Event", "list", {"limit": 10}, conn)
check(listed["success"] and "task_id" in listed["data"] and "events" not in listed["data"],
      "Event.list is async task_id only")
lst = handle("SYNO.TPS.Event", "list_status", {"task_id": listed["data"]["task_id"]}, conn)
inner = (lst.get("data") or {}).get("data") or {}
check(lst["success"] and lst["data"].get("finish") is True and isinstance(inner.get("events"), list),
      "list_status events root")
check("now" in inner and "total" in inner, "list_status now/total")
sens = handle("SYNO.TPS.Sensor", "get", {}, conn)
check(sens["success"] and isinstance(sens["data"].get("interface_list"), list), "Sensor.get interface_list")
check(sens["data"]["prevention_enforced"] is False and sens["data"]["ips_mode"] == "ids", "Sensor.get ids")
check(isinstance(sens["data"].get("capture_capable"), bool), "Sensor.get capture_capable")
check(("SYNO.TPS.Sensor", "get") in EXACT and ("SYNO.TPS.Event", "list") in EXACT, "exact route table")
check("SYNO.TPS.Settings.Mirror" in BY_API and "SYNO.TPS.Signature.Policy" in BY_API, "by-api route table")
check("SYNO.TPS.Settings.Accel" in BY_API, "accel route")
check(UPDATE_PREFIX == "SYNO.TPS.Settings.Update", "update prefix")
miss = handle("SYNO.TPS.Event", "nope", {}, conn)
check(miss["success"] is False and miss["error"]["code"] == 101, "unknown Event method is 101")
miss_api = handle("SYNO.TPS.NoSuch", "get", {}, conn)
check(miss_api["error"]["code"] == 101, "unknown API is 101")
svar = handle("SYNO.TPS.Sensor.Variables", "get", {}, conn)
check(svar["success"] and "home_net" in svar["data"], "Variables.get home_net")
pol = handle("SYNO.TPS.Signature.Policy", "list", {}, conn)
check(pol["success"] and isinstance(pol["data"].get("list"), list), "Policy.list handle root")
nfilt = handle("SYNO.TPS.Notification.Filter", "list", {}, conn)
check(nfilt["success"] and isinstance(nfilt["data"].get("notification_filters"), list),
      "Notification.Filter list root")
sdev = handle("SYNO.TPS.Statistic.Device", "list", {}, conn)
check(sdev["success"] and isinstance(sdev["data"].get("devices"), list), "Statistic.Device Store devices")
with init_db(":memory:") as device_conn:
    now = int(time.time())
    mac = "00:11:22:33:44:aa"
    ip = "192.168.1.130"
    peer = "192.168.1.131"
    device_conn.executemany(
        """INSERT INTO event(mac_src, ip_src_str, ip_dst_str, sig_name, ts_epoch, impact_flag, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, '2026-01-01 00:00:00')""",
        [
            (mac.upper(), ip, peer, "newest", now, 1),
            (mac, peer, ip, "second", now - 30, 1),
            ("", ip, peer, "IP fallback", now - 40, 1),
            (mac, ip, peer, "medium", now - 10, 2),
            (mac, ip, peer, "outside date range", now - 8 * 86400, 1),
        ],
    )
    kv_set(device_conn, "event_offset", "37")
    rows = handle("SYNO.TPS.Statistic.Device", "list", {"days": 7, "order": "high"}, device_conn)
    check([(row["name"], row["count"]) for row in rows["data"]["devices"]] == [(mac, 2), (ip, 1)],
          "device Overview counts match high-severity MAC and IP groups")
    for name, offset, count, signature in ((mac, 0, 2, "newest"), (mac, 1, 2, "second"), (ip, 0, 1, "IP fallback")):
        task = handle("SYNO.TPS.Statistic.Device", "get", {
            "name": name, "days": 7, "severity": "high", "offset": offset, "limit": 1,
        }, device_conn)
        status = handle("SYNO.TPS.Event", "list_status", {"task_id": task["data"]["task_id"]}, device_conn)["data"]
        page = status["data"]
        check(status["finish"] and page["total"] == count and page["offset"] == offset,
              "device details resolves to a paged event task")
        check([event["sig_name"] for event in page["events"]] == [signature],
              "device details isolates the source, severity and date range")
    check(kv_get(device_conn, "event_offset") == "37", "device paging preserves the Events page offset")
    legacy = handle("SYNO.TPS.Statistic.Device", "get", {"ip": ip}, device_conn)
    check(legacy["data"] == {"ip": ip, "count": 4}, "legacy device IP count")
trend = handle("SYNO.TPS.Statistic.Trends", "get", {}, conn)
check(trend["success"] and isinstance(trend["data"].get("trends"), list), "Trends.get trends")
est = handle("SYNO.TPS.Event.Statistic", "get", {}, conn)
check(est["success"] and "days7" in est["data"], "Event.Statistic handle days7")
emap = handle("SYNO.TPS.Event.Map", "list", {}, conn)
check(emap["success"] and "days7" in emap["data"] and "location" in emap["data"]["days7"],
      "Event.Map list location")
rules = handle("SYNO.TPS.Signature.Rule", "list", {"limit": 5}, conn)
check(rules["success"] and isinstance(rules["data"].get("rules"), list), "Signature.Rule Store rules")
sigs = handle("SYNO.TPS.Signature", "list", {}, conn)
check(sigs["success"] and isinstance(sigs["data"].get("signatures"), list), "Signature.list signatures")

boundary = "----x"
body = (
    "--%s\r\nContent-Disposition: form-data; name=\"api\"\r\n\r\nSYNO.TPS.Backup\r\n"
    "--%s\r\nContent-Disposition: form-data; name=\"dss_file\"; filename=\"x.json\"\r\n"
    "Content-Type: application/json\r\n\r\n{\"kv\":[]}\r\n"
    "--%s--\r\n" % (boundary, boundary, boundary)
).encode()
fields, files = _parse_multipart(body, "multipart/form-data; boundary=" + boundary)
check(fields.get("api") == "SYNO.TPS.Backup", "multipart field")
check(b"kv" in files.get("dss_file", b""), "multipart dss_file")

upsert_filters(conn, [{"name": "trojan-activity", "enable_mail": True}])
upsert_filters(conn, [{"name": "misc-activity", "enable_sms": True}])
saved = {x["name"]: x for x in list_filters(conn)}
check(saved["trojan-activity"]["enable_mail"] is True, "filter upsert mail")
check(saved["misc-activity"]["enable_sms"] is True, "filter keep prior")
kv_set(conn, "enable_notification", "1")
kv_set(conn, "enable_mail", "1")
conn.commit()
check(maybe_notify(conn, "no-such-class", "x") is False, "notify unknown class skipped")
check(maybe_notify(conn, "trojan-activity", "sid test") is True, "notify writes log")

write_update_source("et-pro", "secret")
check(open(os.path.join(os.environ["TPS_PKGETC"], "update-source")).read().strip() == "et-pro", "et-pro sidecar")
check(open(os.path.join(os.environ["TPS_PKGETC"], "etpro.code")).read().strip() == "secret", "etpro code file")
write_update_source("et-open", "")
check(not os.path.isfile(os.path.join(os.environ["TPS_PKGETC"], "etpro.code")), "et-open clears code")
gmaps_path = os.path.join(os.environ["TPS_PKGETC"], "gmaps.key")
if os.path.isfile(gmaps_path):
    os.remove(gmaps_path)
check(read_gmaps_key() == "", "no gmaps key by default")
open(gmaps_path, "w").write("AIzaSyTestKey123\n")
check(read_gmaps_key() == "AIzaSyTestKey123", "gmaps key file")
mapped = handle("SYNO.TPS.Settings.Map", "get", {}, conn)
check(mapped["success"] and mapped["data"]["key"] == "AIzaSyTestKey123", "settings.map get")

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

check(feed_url_ok("https://example.com/extra.rules"), "https feed ok")
check(not feed_url_ok("file:///etc/passwd"), "file feed blocked")
check(not feed_url_ok("https://127.0.0.1/x"), "loopback feed blocked")
check(not feed_url_ok("http://example.com/x"), "public http blocked")
check(feed_url_ok("http://192.168.1.10/x.rules"), "rfc1918 http ok")
check(add_feed(conn, "et-open", "https://example.com/x", True) is None, "reserved feed name")
fid = add_feed(conn, "local-extra", "https://example.com/extra.rules", True)
check(fid and any(x["name"] == "local-extra" for x in list_feeds(conn)), "feed add")
listed = handle("SYNO.TPS.Settings.Feed", "list", {}, conn)
check(listed["success"] and listed["data"]["feeds"][0]["url"].startswith("https://"), "feed list api")
by_name = {x["name"]: x for x in listed["data"]["feeds"]}
catalog = catalog_entries()
check(len(catalog) >= 8 and all(n in by_name for n, _u in catalog), "OISF catalog seeded")
check(all(by_name[n]["enabled"] is False for n, _u in catalog), "catalog feeds off by default")
et_open = source_urls("et-open")
et_pro = source_urls("et-pro", "ABC123")
check(et_open and all(u.startswith("https://") for u in et_open), "et-open urls from json")
check(et_pro and all("ABC123" in u and "{code}" not in u for u in et_pro), "et-pro interpolates code")
for rel in ("tpsweb.py", "feeds.py", "rule_sources.py"):
    text = open(os.path.join(HERE, rel), encoding="utf-8").read().lower()
    check("emergingthreats.net" not in text and "emergingthreatspro.com" not in text,
          "no hardcoded et url in %s" % rel)
sh_text = open(os.path.join(HERE, "..", "scripts", "update-rules.sh"), encoding="utf-8").read().lower()
check("emergingthreats.net" not in sh_text and "emergingthreatspro.com" not in sh_text,
      "no hardcoded et url in update-rules.sh")
check(by_name["local-extra"]["enabled"] is True, "user-added feed stays enabled")
off = handle("SYNO.TPS.Settings.Feed", "save", {"feeds": [{"id": fid, "enabled": False}]}, conn)
check(off["success"], "feed save disables")
by_name = {x["name"]: x for x in handle("SYNO.TPS.Settings.Feed", "list", {}, conn)["data"]["feeds"]}
check(by_name["local-extra"]["enabled"] is False, "feed save roundtrip off")
on = handle("SYNO.TPS.Settings.Feed", "save", {"feeds": [{"id": fid, "enabled": True}]}, conn)
check(on["success"], "feed save enables")
by_name = {x["name"]: x for x in handle("SYNO.TPS.Settings.Feed", "list", {}, conn)["data"]["feeds"]}
check(by_name["local-extra"]["enabled"] is True, "feed save roundtrip on")
nfeeds = len(list_feeds(conn))
seed_catalog_feeds(conn)
check(len(list_feeds(conn)) == nfeeds, "catalog seed is idempotent")
write_telegram_conf("123:ABC", "-1001")
cfg = read_telegram_conf()
check(cfg["token"] == "123:ABC" and cfg["chat"] == "-1001", "telegram.conf")
tg = handle("SYNO.TPS.Settings.Telegram", "get", {}, conn)
check(tg["success"] and tg["data"]["has_token"] and tg["data"]["token"] == "123:ABC", "telegram get returns token")
check(tg["data"]["bot_token"] == "123:ABC", "telegram get bot_token alias")
blank = handle("SYNO.TPS.Settings.Telegram", "set", {
    "enable_telegram": True, "token": "", "chat_id": "", "min_interval_telegram": 120,
}, conn)
check(blank["success"], "telegram set empty secrets")
cfg = read_telegram_conf()
check(cfg["token"] == "123:ABC" and cfg["chat"] == "-1001", "telegram set empty does not wipe conf")
flags_only = handle("SYNO.TPS.Settings.Telegram", "set", {"enable_telegram": False}, conn)
check(flags_only["success"] and read_telegram_conf()["token"] == "123:ABC", "telegram flags-only keeps token")
upd = handle("SYNO.TPS.Settings.Telegram", "set", {"token": "999:ZZZ", "chat_id": "-42"}, conn)
check(upd["success"] and read_telegram_conf() == {"token": "999:ZZZ", "chat": "-42"}, "telegram set updates secrets")
botp = handle("SYNO.TPS.Settings.Telegram", "set", {"bot_token": "888:BOT", "token": "csrfNoColon"}, conn)
check(botp["success"] and read_telegram_conf()["token"] == "888:BOT", "bot_token wins over CSRF token")
keep = handle("SYNO.TPS.Settings.Telegram", "set", {"bot_token": "********", "enable_telegram": True}, conn)
check(keep["success"] and read_telegram_conf()["token"] == "888:BOT", "keep-mask does not wipe token")

notification_get = {"api": "SYNO.TPS.Notification", "method": "get", "version": 1}
kv_set(conn, "enable_notification", "0")
out = handle("SYNO.TPS.Compound", "request", {"compound": [notification_get]}, conn)
overview_notification = out["data"]["result"][0]["data"]
check(overview_notification["telegram_configured"] and not overview_notification["enable_notification"],
      "overview recognizes Telegram with DSM notifications off")
check(not ({"token", "bot_token", "chat", "chat_id"} & overview_notification.keys()),
      "overview notification status omits Telegram credentials")
for missing in ({"token": "", "chat": "-42"}, {"token": "888:BOT", "chat": ""}):
    with patch("tpsweb.read_telegram_conf", return_value=missing):
        data = handle("SYNO.TPS.Notification", "get", {}, conn)["data"]
        check(not data["telegram_configured"], "overview requires both Telegram credentials")
kv_set(conn, "enable_telegram", "0")
data = handle("SYNO.TPS.Notification", "get", {}, conn)["data"]
check(not data["telegram_configured"], "overview ignores saved credentials when Telegram is disabled")
kv_set(conn, "enable_telegram", "1")

leases = _parse_isc_leases(
    'lease 192.168.1.50 {\n  hardware ethernet AA:BB:CC:DD:EE:FF;\n'
    '  client-hostname "phone";\n  binding state active;\n}\n'
)
check(leases and leases[0][0] == "aa:bb:cc:dd:ee:ff" and leases[0][2] == "phone", "isc dhcp lease")
syno = _parse_syno_info("IP=10.0.0.8\nMAC=11:22:33:44:55:66\nHOSTNAME=cam\n")
check(syno and syno[0][0] == "11:22:33:44:55:66" and syno[0][2] == "cam", "syno dhcpd.info")
nsm = handle("SYNO.Core.Network.NSM.Device", "get", {}, conn)
check(nsm["success"] and isinstance(nsm["data"]["devices"], list), "nsm device list")
devlist = handle("SYNO.TPS.Device", "list", {}, conn)
check(devlist["success"] and isinstance(devlist["data"]["device_list"], list), "tps device list")
for row in devlist["data"]["device_list"]:
    check(not str(row.get("mac") or "").startswith("02:42:"), "device list skips docker mac")
check("default_detect" in devlist["data"], "device list default_detect")
usb = handle("SYNO.Core.ExternalDevice.Storage.USB", "list", {}, conn)
check(usb["success"] and isinstance(usb["data"]["devices"], list), "usb list")
for dev in usb["data"]["devices"]:
    check("partitions" in dev, "usb partitions")
sdb = handle("SYNO.Core.SystemDB", "get", {}, conn)
check(sdb["success"] and "systemdb_shares" in sdb["data"], "systemdb share")
check(systemdb_get()["systemdb_shares"] == (usb_list()["devices"][0]["partitions"][0]["share_name"] if usb_list()["devices"] else ""), "systemdb matches first usb share")
got = handle("SYNO.TPS.Settings.Storage", "get", {}, conn)
check(got["success"] and got["data"]["db_size"] == "db_size_500mb", "storage get default")
check(got["data"].get("logStorageMaxLimit"), "storage get has volume capacity")
check(usb["data"]["devices"], "usb/volume list not empty")
sched = handle("SYNO.TPS.Settings.Update.Schedule", "get", {}, conn)
check(sched["success"] and sched["data"]["weekday"] == "0,1,2,3,4,5,6", "schedule get weekday csv")
saved = handle("SYNO.TPS.Settings.Update.Schedule", "set", {"auto_update": True, "weekday": "0,6", "hour": 3, "minute": 15}, conn)
check(saved["success"] and saved["data"]["hour"] == 3 and saved["data"]["minute"] == 15, "schedule set returns payload")
sched2 = handle("SYNO.TPS.Settings.Update.Schedule", "get", {}, conn)
check(sched2["data"]["auto_update"] is True and sched2["data"]["weekday"] == "0,6", "schedule weekend roundtrip")
check(sched2["data"]["hour"] == 3 and sched2["data"]["minute"] == 15, "schedule time roundtrip")
midnight = handle("SYNO.TPS.Settings.Update.Schedule", "set", {"auto_update": True, "weekday": "0", "hour": 0, "minute": 0}, conn)
check(midnight["data"]["hour"] == 0 and midnight["data"]["minute"] == 0, "schedule midnight hour not coerced")
check(sched["data"]["last_updated"] == "not_updated_yet", "schedule get last_updated sentinel")
src_get = handle("SYNO.TPS.Settings.Update.Source", "get", {}, conn)
check(src_get["success"] and src_get["data"]["use_code"] == "etOpen", "source get default etOpen")
src_set = handle("SYNO.TPS.Settings.Update.Source", "set", {"use_code": "etPro", "code": "oink"}, conn)
check(src_set["success"] and src_set["data"]["use_code"] == "etPro" and src_set["data"]["code"] == "oink", "source set returns payload")
src_round = handle("SYNO.TPS.Settings.Update.Source", "get", {}, conn)
check(src_round["data"]["use_code"] == "etPro" and src_round["data"]["code"] == "oink", "source roundtrip")
st = handle("SYNO.TPS.Settings.Storage", "set", {"db_size": "db_size_2gb"}, conn)
check(st["success"] and st["data"]["db_size"] == "db_size_2gb", "storage set returns combo key")
got2 = handle("SYNO.TPS.Settings.Storage", "get", {}, conn)
check(got2["data"]["db_size"] == "db_size_2gb" and got2["data"]["limit"] == 2048, "storage get after set")
st_empty = handle("SYNO.TPS.Settings.Storage", "set", {"db_size": ""}, conn)
check(st_empty["data"]["db_size"] == "db_size_500mb", "empty db_size defaults to 500mb")
mirror = handle("SYNO.TPS.Settings.Mirror", "get", {}, conn)
check(mirror["success"] and mirror["data"]["capture_mode"] == "lan", "mirror default lan")
check(mirror["data"]["enabled"] is False, "mirror shipped disabled")
bad_copy = handle("SYNO.TPS.Settings.Mirror", "set", {"capture_mode": "copy", "router_ip": "not-an-ip"}, conn)
check(not bad_copy["success"], "mirror copy rejects bad router_ip")
copied = handle("SYNO.TPS.Settings.Mirror", "set", {"capture_mode": "copy", "router_ip": "192.168.1.1"}, conn)
check(copied["success"] and copied["data"]["capture_mode"] == "copy", "mirror copy set")
check(copied["data"]["enabled"] is True and copied["data"]["ifname"] == "tps0", "mirror copy flags")
check(copied["data"]["encap"] == "gretap" and copied["data"]["router_kind"] == "openwrt", "mirror default openwrt gretap")
mt = handle("SYNO.TPS.Settings.Mirror", "set", {
    "capture_mode": "copy", "router_ip": "192.168.1.1", "router_kind": "mikrotik",
}, conn)
check(mt["success"] and mt["data"]["encap"] == "tzsp" and mt["data"]["router_kind"] == "mikrotik", "mirror mikrotik tzsp")
check(mt["data"]["tzsp_port"] == 37008, "mirror tzsp port")
from tzsp_tap import parse_tzsp  # noqa: E402
eth = b"\x00" * 6 + b"\x11" * 6 + b"\x08\x00" + b"\x45\x00"
tzsp = bytes([1, 0, 0, 1, 1]) + eth
check(parse_tzsp(tzsp) == eth, "tzsp ethernet payload")
check(parse_tzsp(b"\x00\x00") is None, "tzsp rejects junk")
check(parse_tzsp(bytes([1, 0, 0, 18, 1]) + eth) is None, "tzsp rejects non-ethernet encap")
iface_pin = open(os.path.join(os.environ["TPS_PKGETC"], "interface")).read().strip()
check(iface_pin == "tps0", "copy mode pins tps0")
lan = handle("SYNO.TPS.Settings.Mirror", "set", {"capture_mode": "lan"}, conn)
check(lan["success"] and lan["data"]["capture_mode"] == "lan", "mirror lan set")
check(lan["data"]["enabled"] is False, "lan disables copy")

from accel import apply_detect_algos  # noqa: E402
check("mpm-algo: hs" in apply_detect_algos("", "hs", "hs"), "detect block appended")
sample = "detect:\n  mpm-algo: ac\n  spm-algo: bmh\n"
check("mpm-algo: hs" in apply_detect_algos(sample, "hs", "hs"), "detect keys replaced")
acc = handle("SYNO.TPS.Settings.Accel", "get", {}, conn)
check(acc["success"] and acc["data"]["hyperscan"] is True, "accel default hyperscan on")
check(acc["data"]["dpdk"] is False and acc["data"]["nic_offload"] is False, "dpdk/offload not wired")
check(acc["data"]["mpm_algo"] in ("hs", "ac"), "accel reports mpm")
off = handle("SYNO.TPS.Settings.Accel", "set", {"hyperscan": False}, conn)
check(off["success"] and off["data"]["hyperscan"] is False, "accel set off")
check(off["data"]["mpm_algo"] == "ac" and off["data"]["spm_algo"] == "bmh", "off uses ac/bmh")
on = handle("SYNO.TPS.Settings.Accel", "set", {"hyperscan": True, "dpdk": True, "nic_offload": True}, conn)
check(on["success"] and on["data"]["dpdk"] is False and on["data"]["nic_offload"] is False, "accel ignores dpdk/offload")
accel_txt = open(os.path.join(os.environ["TPS_PKGETC"], "accel.conf"), encoding="utf-8").read()
check("hyperscan=1" in accel_txt and "dpdk=0" in accel_txt, "accel.conf default policy")
yaml_txt = open(os.path.join(os.environ["TPS_PKGDEST"], "etc", "suricata", "suricata.yaml"), encoding="utf-8").read()
check("mpm-algo:" in yaml_txt and "spm-algo:" in yaml_txt, "yaml detect algos written")

ip_link_mut = []
_orig_call = tpsweb_mod.subprocess.call
_orig_popen = tpsweb_mod.subprocess.Popen
_orig_check = tpsweb_mod.subprocess.check_output


def _watch_ip(args):
    argv = list(args) if not isinstance(args, str) else args.split()
    if argv and argv[0] == "ip" and "link" in argv and ("add" in argv or "del" in argv):
        ip_link_mut.append(argv)


def _call_watch(args, *a, **kw):
    _watch_ip(args)
    return _orig_call(args, *a, **kw)


def _popen_watch(args, *a, **kw):
    _watch_ip(args)
    return _orig_popen(args, *a, **kw)


def _check_watch(args, *a, **kw):
    _watch_ip(args)
    return _orig_check(args, *a, **kw)


tpsweb_mod.subprocess.call = _call_watch
tpsweb_mod.subprocess.Popen = _popen_watch
tpsweb_mod.subprocess.check_output = _check_watch
try:
    again = handle("SYNO.TPS.Settings.Mirror", "set", {"capture_mode": "copy", "router_ip": "192.168.1.1"}, conn)
    check(again["success"], "mirror set without gretap")
    check("tap_present" in again["data"], "mirror reports tap_present")
    check(not ip_link_mut, "mirror set does not ip link add/del")
finally:
    tpsweb_mod.subprocess.call = _orig_call
    tpsweb_mod.subprocess.Popen = _orig_popen
    tpsweb_mod.subprocess.check_output = _orig_check

seq = []
_ws = tpsweb_mod.write_sensor
_wm = tpsweb_mod.write_mirror_conf
_se = tpsweb_mod.start_engine
_st = tpsweb_mod.stop_engine


def _tap_ws(data):
    seq.append("sensor")
    return _ws(data)


def _tap_wm(data):
    seq.append("mirror")
    return _wm(data)


tpsweb_mod.write_sensor = _tap_ws
tpsweb_mod.write_mirror_conf = _tap_wm
tpsweb_mod.start_engine = lambda: True
tpsweb_mod.stop_engine = lambda: None
try:
    compound = handle("SYNO.TPS.Compound", "request", {
        "compound": [
            {"api": "SYNO.TPS.Sensor", "method": "set", "params": {
                "enable_sensor": True, "interface_list": "ovs_eth0",
            }},
            {"api": "SYNO.TPS.Settings.Mirror", "method": "set", "params": {
                "capture_mode": "copy", "router_ip": "192.168.1.1",
            }},
        ],
    }, conn)
finally:
    tpsweb_mod.write_sensor = _ws
    tpsweb_mod.write_mirror_conf = _wm
    tpsweb_mod.start_engine = _se
    tpsweb_mod.stop_engine = _st
check(compound["success"], "compound request succeeds")
check(seq == ["mirror", "sensor"], "compound executes Mirror.set before Sensor.set")
rows = compound["data"]["result"]
check(rows[0]["api"] == "SYNO.TPS.Sensor" and rows[1]["api"] == "SYNO.TPS.Settings.Mirror",
      "compound result stays in request order")
check(compound["data"]["has_fail"] is False, "compound has_fail false")
nested = handle("SYNO.TPS.Compound", "request", {
    "compound": [{"api": "SYNO.TPS.Compound", "method": "request", "params": {}}],
}, conn)
check(nested["data"]["has_fail"] is True and nested["data"]["result"][0]["error"]["code"] == 102,
      "compound rejects nested Compound")

busy = start_job({"status": "updating"})
chk = handle("SYNO.TPS.Settings.Update", "start_check", {}, conn)
check(chk["success"] and str(chk["data"]["task_id"]) == str(busy), "start_check reuses in-flight update")
JOBS[str(busy)]["status"] = "up_to_date"
check(filestation_path_for("/volume1/@appdata/ThreatPrevention/export") == "", "hide @appdata from File Station")
check(filestation_path_for("/volume1/ThreatPrevention") == "/ThreatPrevention", "volume share maps to FS path")
share_root = tempfile.mkdtemp(prefix="tps-share-")
os.environ["TPS_PKGSHARES"] = tempfile.mkdtemp(prefix="tps-shares-")
os.makedirs(os.environ["TPS_PKGSHARES"], exist_ok=True)
os.symlink(share_root, os.path.join(os.environ["TPS_PKGSHARES"], "ThreatPrevention"))
import importlib
import paths as paths_mod
importlib.reload(paths_mod)
importlib.reload(tpsweb_mod)
check(tpsweb_mod.ensure_export_dir() == "/ThreatPrevention", "export folder is File Station share path")
exp = tpsweb_mod.handle("SYNO.TPS.Event.ExportFolder", "get", {}, conn)
check(exp["success"] and exp["data"]["export_folder"] == "/ThreatPrevention", "ExportFolder API share path")
check(fetch_osm_tile("nope", 0, 0) is None, "osm tile rejects junk")
check(fetch_osm_tile(2, 0, 99) is None, "osm tile rejects out-of-range y")
print("ok")
