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
    official_event,
    official_map,
    official_policy_write,
    official_sensor,
    official_source,
    official_stat_bucket,
    official_storage,
    official_update_status,
    official_weekday,
    parse_weekday,
)
from compiler import parse_header, parse_refs  # noqa: E402
from geoip import is_public_ipv4, lookup as geoip_lookup  # noqa: E402
from ingest import payload_hex  # noqa: E402
from feeds import add_feed, feed_url_ok, list_feeds  # noqa: E402
from notify import list_filters, maybe_notify, read_telegram_conf, upsert_filters, write_telegram_conf  # noqa: E402
from corehost import _parse_isc_leases, _parse_syno_info, usb_list, systemdb_get  # noqa: E402
from store import init_db, kv_set  # noqa: E402
from tpsweb import (  # noqa: E402
    _parse_multipart,
    ensure_export_dir,
    fetch_osm_tile,
    filestation_path_for,
    handle,
    read_gmaps_key,
    start_job,
    write_update_source,
)
from tpsweb import JOBS  # noqa: E402


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
check(sensor["prevention_enforced"] is False and sensor["ips_mode"] == "ids", "ids only")
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
check(fid and list_feeds(conn)[0]["name"] == "local-extra", "feed add")
listed = handle("SYNO.TPS.Settings.Feed", "list", {}, conn)
check(listed["success"] and listed["data"]["feeds"][0]["url"].startswith("https://"), "feed list api")
write_telegram_conf("123:ABC", "-1001")
cfg = read_telegram_conf()
check(cfg["token"] == "123:ABC" and cfg["chat"] == "-1001", "telegram.conf")
tg = handle("SYNO.TPS.Settings.Telegram", "get", {}, conn)
check(tg["success"] and tg["data"]["has_token"] and tg["data"]["token"] == "", "telegram get hides token")

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
iface_pin = open(os.path.join(os.environ["TPS_PKGETC"], "interface")).read().strip()
check(iface_pin == "tps0", "copy mode pins tps0")
lan = handle("SYNO.TPS.Settings.Mirror", "set", {"capture_mode": "lan"}, conn)
check(lan["success"] and lan["data"]["capture_mode"] == "lan", "mirror lan set")
check(lan["data"]["enabled"] is False, "lan disables copy")
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
import tpsweb as tpsweb_mod
importlib.reload(paths_mod)
importlib.reload(tpsweb_mod)
check(tpsweb_mod.ensure_export_dir() == "/ThreatPrevention", "export folder is File Station share path")
exp = tpsweb_mod.handle("SYNO.TPS.Event.ExportFolder", "get", {}, conn)
check(exp["success"] and exp["data"]["export_folder"] == "/ThreatPrevention", "ExportFolder API share path")
check(fetch_osm_tile("nope", 0, 0) is None, "osm tile rejects junk")
check(fetch_osm_tile(2, 0, 99) is None, "osm tile rejects out-of-range y")
print("ok")
