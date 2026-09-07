# SYNO.TPS.* contract (community rebuild)

**Official app inventory and port backlog:** [official-app-surface.md](official-app-surface.md), [backend-port-backlog.md](backend-port-backlog.md).

This file is the **simplified** community envelope. The official ExtJS app uses a stricter shape (async Event.list `task_id`, Policy `list` + int types, Statistic `days7`/`days30`/`all_logs`, Device `device_list`). That mapping lives in `spk/src/threatprevention/python/compat.py`. Why it exists: [backend-replaceability.md](../backend-replaceability.md).

Sources (no official JS in this file): [`unpacked/package/webapi/SYNO.TPS.lib`](../../unpacked/package/webapi/SYNO.TPS.lib), [`unpacked/package/schema/syno_create_postgresql`](../../unpacked/package/schema/syno_create_postgresql), `strings` on the eight `SYNO.TPS.*.so` files, and keys in [`unpacked/package/ui/texts/enu/strings`](../../unpacked/package/ui/texts/enu/strings).

Shipped as `tpsweb` (`entry.cgi`-shaped query params). Response envelope:

```json
{ "success": true, "data": {} }
{ "success": false, "error": { "code": 100 } }
```

Error codes: `100` bad request, `101` unknown API, `102` unknown method, `103` not implemented / stub, `400` busy, `403` unauthorized, `500` internal.

All APIs: admin only, versions as in `SYNO.TPS.lib`.

## SYNO.TPS.Event (v1 get / list_status; v4 list)

Params seen in Event.so: `offset`, `limit`, `date_range`, `begin`, `finish`, `key_words`, `severity`, `action`, `ip_src`, `ip_dst`, `port_src`, `port_dst`, `sig_sid`, `sig_name`, `signature_rule`.

`list` data:

```json
{
  "events": [
    {
      "sid": 1,
      "cid": 12,
      "timestamp": "2026-09-07 15:01:02",
      "ts_epoch": 1757250062,
      "sig_sid": 2100498,
      "sig_rev": 1,
      "sig_name": "ET SCAN ...",
      "sig_class_id": 3,
      "sig_class_name": "attempted-recon",
      "severity": 2,
      "action": "alert",
      "ip_src": 3232235876,
      "ip_dst": 134744072,
      "ip_src_str": "192.168.1.100",
      "ip_dst_str": "8.8.8.8",
      "port_src": 54321,
      "port_dst": 53,
      "ip_proto": 17,
      "mac_src": "",
      "mac_dst": "",
      "device_src": "",
      "device_dst": ""
    }
  ],
  "offset": 0,
  "total": 1
}
```

`get` params: `sid`, `cid`. Data is one event plus `iphdr` / `tcphdr` / `udphdr` / `icmphdr` / `data_payload` / `references`.

`list_status`: `{ "total": 1, "status": "ready" }`.

## SYNO.TPS.Event.Offset (v1 get)

`{ "offset": 0 }` — last pagination cursor.

## SYNO.TPS.Event.Statistic (v1 get)

Params: `date_range` (`7days` / `30days` / `all`). Data: `total`, `high`, `medium`, `low`, `top_class` (name/count), `top_src`, `top_dst`.

## SYNO.TPS.Event.Map (v1 list)

`{ "days7", "days30", "all_logs" }` each with `location[]` (`lat`, `lng`, `country`, `ip_src`, `signature`, `priority`, `count`) plus `begin` / `end`. Empty `location` until GeoIP exists.

## SYNO.TPS.Event.ExportFolder (v1 get)

`{ "export_folder": "/var/packages/ThreatPrevention/var/export" }`.

## SYNO.TPS.Sensor (v1 get / set)

Fields from Sensor.so + `sensor.conf`: `enable_sensor`, `enable_prevention`, `interface_list`, `network_security_mode` (`availability` | `security`), `default_detect`, `status` (`running` | `stopped` | `starting`).

`set` writes `/var/packages/ThreatPrevention/etc/interface` and `etc/sensor.conf`. Prevention mode is stored but NFQUEUE is not auto-wired (IDS only).

## SYNO.TPS.Sensor.Variables (v1 get)

Suricata address/port groups: `HOME_NET`, `EXTERNAL_NET`, `HTTP_PORTS`, `SSH_PORTS`, …

## SYNO.TPS.Signature (v1 list)

`{ "classes": [ { "sig_class_id", "name", "description", "severity", "total", "enabled", "action" } ] }`

## SYNO.TPS.Signature.Classification (v1 list)

Same class rows (full classification.config).

## SYNO.TPS.Signature.Rule (v1 list)

Params: `sig_class_id`, `offset`, `limit`, `key_words`. `{ "rules": [ { "sig_sid", "sig_rev", "sig_name", "action", "sig_class_id", "class_name", "sig_protocol" } ], "total" }`.

## SYNO.TPS.Signature.Policy (v1 CRUD; v2 delete)

`list`: `{ "policy": [ { "type": "class"|"signature"|"filter", "raw_sid", "sig_class_id", "sig_name", "action", "ip_src", "ip_dst", "comment" } ] }`.

`add` / `set` / `update` / `get` / `delete` use those fields. `delete` v2 accepts `force`. Apply compiles `var/rules/suricata.rules`.

Actions: `alert`, `drop`, `pass`, `disable` (maps to official strings Alert / Drop / Pass / Do nothing).

## SYNO.TPS.Settings.Update (v1)

`start_check` / `start_update` / `status`. Status: `checking` | `updating` | `up_to_date` | `new_version` | `connect_error` | `etpro_error`. Also `last_updated`, `remote_version`.

## SYNO.TPS.Settings.Update.Schedule (v1 get / set)

`auto_update` (bool), `weekday` (0–6 or `daily`), `minute` (hour*60+min or `hourly`).

## SYNO.TPS.Settings.Update.Source (v1 get / set)

`source`: `et-open` | `et-pro`. `code`: ET Pro oinkcode. Also `use_code` (`etOpen` / `etPro`) and `support_etpro`.

## SYNO.TPS.Settings.Storage (v1)

`get` / `set`: `db_size` (bytes), `limit` (500 | 1024 | 2048 MiB), `clear_percentage`.
`clear_log` / `start_clear_log` / `status_clear_log`: `idle` | `clearing` | `cleared`.

## SYNO.TPS.Device (v1 list / set)

`{ "devices": [ { "mac", "device_name", "detect", "loading_score", "online" } ] }`. `set`: `mac`, `detect`, `device_name`.

## SYNO.TPS.Statistic.Device (v1 list; v2 get)

Busy/concerned devices from event counts. `limit`, `offset`, `order`.

## SYNO.TPS.Statistic.Trends (v1 get)

`{ "points": [ { "ts", "high", "medium", "low", "total" } ] }` — 8-hour buckets, last 7 days.

## SYNO.TPS.Notification (v1 get / set)

`enable_notification`, `enable_mail`, `enable_push`, `enable_sms`, `min_interval_mail`, `min_interval_push`, `min_interval_sms`, `subject_prefix`. Persist only; DSM Control Panel sends mail.

## SYNO.TPS.Notification.Filter (v1 list / set)

`{ "notification_filters": [ { "name", "description", "severity", "enable_mail", "enable_sms", "enable_push" } ] }`. `set` upserts modified rows only. DSM `synodsmnotify` if present; no SMTP.

## SYNO.TPS.Backup (v1 backup / restore)

JSON (not official `.dss`). `backup` returns `{ "json": "..." }` or file body. `restore` accepts `json`.
