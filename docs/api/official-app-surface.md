# Official Threat Prevention app — API surface

Research inventory of what vanilla `synoips.js` (`SYNO.SDS.TPS.Application`) actually calls. Sources: `unpacked/package/ui/synoips.js`, `unpacked/package/webapi/SYNO.TPS.lib`, DSM `extjs-patch.bundle.js`. The eight `SYNO.TPS.*.so` modules are aarch64 and are not loaded on this NAS.

The simplified community shapes in [SYNO.TPS.contract.md](SYNO.TPS.contract.md) are **not** what the official JS reads. Official envelopes live in `spk/src/threatprevention/python/compat.py`. Port status: [backend-port-backlog.md](backend-port-backlog.md). How DSM loads ExtJS apps (JSLoad, `AppInstance`, `SYNO.ux`): [dsm-extjs-sdk.md](../dsm-extjs-sdk.md).

## Transport (not `entry.cgi` strings)

Official JS never hard-codes `/webapi/entry.cgi` for `SYNO.TPS.*`. It uses DSM Ext mixins:

| Call | Where | What it must do |
| --- | --- | --- |
| `sendWebAPI` | AppWindow, **bare `Ext.Component`** (SignatureUpdater) | POST `api` / `method` / `version` / params |
| `sendWebAPI({ compound })` | Settings, Policy, Storage, Sensor+NSM | `{ result: [{api,method,success,data}], has_fail }` |
| `SYNO.API.Store` | Signature.Rule, Statistic.Device, Notification.Filter | `root` = `rules` / `devices` / `notification_filters` |
| `pollReg` / `pollUnreg` | Sensor, Event.list_status, Trends, Update.status, Storage.clear | interval + `status_callback(ok, data)` |
| `pollList` | SignatureUpdater.check | `SYNO.API.Request.Polling.List` — `{ admin: Ext-collection }` |
| `downloadWebAPI` | Backup | file download, not JSON callback body |
| `SYNO.Entry.Request.request` | Notification tab | nested Core compound (passthrough) |
| `SYNO.SDS.AppLaunch(FileStation3)` | Export folder | `opendir: export_folder` |

HTTPS DSM → tpsweb is same-origin `/webman/tps-api` (nginx → `:19557`). Do not wrap `SYNO.API.Request` as a new function without copying `.Polling`.

## `SYNO.TPS.*` (21 APIs, 42 methods in `.lib`)

All admin-only. Versions as in `SYNO.TPS.lib`.

### Events

| API | Method | Official contract | UI |
| --- | --- | --- | --- |
| `Event` | `list` v4 | **async** `{task_id}` only | Events tab |
| `Event` | `list_status` | poll → `{finish, data:{events,total,now}}`; `now` datetime string | Events tab |
| `Event` | `get` | `params.id` = `"sid-cid"`; severity **string** `high\|medium\|low`; `ip_src`/`ip_dst` display strings; flattened `ip_ver`, `tcp_*`, `payload` hex string; `ip_proto` `"1"\|"6"\|"17"`; field `signature` | Event info |
| `Event.Offset` | `get` | `cid` → row offset (jump from Overview) | Overview |
| `Event.Statistic` | `get` | `days7` / `days30` / `all_logs` each `{class_name,ip_src,ip_dst,botnet_*,country_src,begin,end}` | Overview pies |
| `Event.Map` | `list` | same three keys; `{begin,end,location[]}` (`lat,lng,country,ip_src,signature,priority,count,encode`) | Map tab |
| `Event.ExportFolder` | `get` | `{export_folder}` realpath File Station can `opendir` | Events export |

### Sensor / engine

| API | Method | Official contract | UI |
| --- | --- | --- | --- |
| `Sensor` | `get` | `status` ∈ `engine_init` / `engine_start` / `build_signature_database` / `updating_signature` / `migrate_event` / `reset_signature_database` / `""`; `interface_list[]` `{if_id,enabled}`; `config_exist`; `enable_sensor`; `enable_prevention`; `network_security_mode`; `default_detect` | Overview poll 5s |
| `Sensor` | `set` | same fields; prevention + `security` = official NFQUEUE IPS | Settings / wizard |
| `Sensor.Variables` | `get` | lowercase `home_net`, `http_ports`, … | Policy form |

### Signatures / policy

| API | Method | Official contract | UI |
| --- | --- | --- | --- |
| `Signature` | `list` | `{signatures:[{name,enabled,enabledCount,totalCount,severity:1\|2\|3}]}` | Policy / classes |
| `Signature.Classification` | `list` | `{signatures:[…]}` name→description; numeric severity | fill-in |
| `Signature.Rule` | `list` | Store root `rules`; `baseParams.name` = **class name**; fields `msg`,`encode`,`ip_*`,`port_*`,`references`,`sig_sid` | Ruleset grid |
| `Signature.Policy` | `list` | `{list:[…]}` `type` **int** 1/2/3; severity **string** | User-defined |
| `Signature.Policy` | `get` | same as list (or one row) | |
| `Signature.Policy` | `set` | `{policy:[{class_name,action:enabled\|disabled,signatures}]}` | class toggles |
| `Signature.Policy` | `add` | `{sid,action,ip_src,ip_dst,force,comment}` → `{need_force:false}` | add dialog |
| `Signature.Policy` | `update` | `{old_sid,old_action,old_ip_*,sid,action,ip_*,force,comment}` → `{need_force}` | edit |
| `Signature.Policy` | `delete` v2 | `{classes:[{class_name}],signatures:[{sid,ip_src,ip_dst}]}` | |

### Settings / update / storage

| API | Method | Official contract | UI |
| --- | --- | --- | --- |
| `Settings.Update` | `start_check` | `{task_id}` | SignatureUpdater |
| `Settings.Update` | `start_update` | `{task_id}` | Update button |
| `Settings.Update` | `status` | **nested** `data.status`, `data.last_updated`; status `checking` / `updating` / `up_to_date` / `new_version` / `connect_error` / `etpro_error` | poll |
| `Settings.Update.Schedule` | `get`/`set` | `auto_update`, `weekday`, `hour`, `minute` (minute-of-hour) | Settings |
| `Settings.Update.Source` | `get`/`set` | `use_code` `etOpen`/`etPro`, `support_etpro`, `code` | Settings |
| `Settings.Storage` | `get`/`set` | combo `db_size` = `db_size_500mb`\|`db_size_1gb`\|`db_size_2gb` | Settings |
| `Settings.Storage` | `start_clear_log` | `{task_id}` | Clear logs |
| `Settings.Storage` | `status_clear_log` | nested `data.status`, `data.clear_percentage` | poll |
| `Settings.Storage` | `clear_log` | sync clear (lib only; JS uses start/status) | |

### Devices / stats / notify / backup

| API | Method | Official contract | UI |
| --- | --- | --- | --- |
| `Device` | `list` | `{device_list, default_detect, loading_score, mesh_re:false}`; skip `mesh_re` | Concerned devices |
| `Device` | `set` | `{default_detect, device_list}` | Settings |
| `Statistic.Device` | `list` v1 | Store root `devices` | Overview |
| `Statistic.Device` | `get` v2 | single / busy device | |
| `Statistic.Trends` | `get` | `{begin,end,trends:[{begin,end,high,medium,low,total}]}` | Overview graph |
| `Notification` | `get`/`set` | flags + intervals | Settings |
| `Notification.Filter` | `list`/`set` | `{notification_filters:[{name,description,severity,enable_mail,enable_sms,enable_push}]}` | Notify grid |
| `Backup` | `backup` | `downloadWebAPI` → official `.dss` | Settings |
| `Backup` | `restore` | upload `.dss` | Settings |

## DSM-core APIs (passthrough, not tpsweb)

These are **not** `SYNO.TPS.*`. The bridge must send them to `/webapi/entry.cgi`.

| API | Method | Why the app calls it |
| --- | --- | --- |
| `SYNO.Core.Network` | `get` | LAN context in Sensor compound |
| `SYNO.Core.Network.NSM.Device` | `get` v4 `connecttype=all` | device names / Mesh; skip `mesh_re` |
| `SYNO.Core.SystemDB` | `get` | Storage panel `systemdb_shares` (USB volume pick) |
| `SYNO.Core.ExternalDevice.Storage.USB` | `list` `additional=[all]` | max USB log volume |
| `SYNO.Core.Notification.Mail.Conf` | `get` | mask Notify tab if mail unset |
| `SYNO.Core.Notification.SMS.Conf` | `get` | same |
| `SYNO.Core.Notification.Push.Conf` | `get` | same |
| `SYNO.Core.Notification.Push.Mail` | `get` | same |
| `SYNO.Entry.Request` | `request` | wraps the four Notify compounds |

Google Maps (`SYNO.SDS.TPS.Utils.GoogleMapLoader`) is not a WebAPI. Official URL has no `key=` → `NoApiKeys`. Ad blockers turn `mapsjs/gen_204` into `ERR_BLOCKED_BY_CLIENT`. Pins need GeoIP (`location[]`). See [google-maps.md](../google-maps.md).

## SRM-only desktop widgets

`SYNO.SDS.Chart.LineChart` / `PieChart` / `CreateAxis` are **not** on DSM 7. Packed as `tps-chart.js` JSLoad module.

`SYNO.API.Request.Polling.{List,Register,Unregister}` must stay on the `Request` namespace (do not replace `Request` with a bare function).

## PoC-only APIs (bridge, not official `.lib`)

Official `synoips.js` never calls these. [`bridge/`](../../spk/src/threatprevention/package/ui/bridge/) (`transport.js`, `dsm7.js`, `settings-inject.js`) does, using the same `sendWebAPI` mixin. Host widget / JSLoad notes: [dsm-extjs-sdk.md](../dsm-extjs-sdk.md).

| API | Method | Contract |
| --- | --- | --- |
| `Settings.Map` | `get` | `{key}` from `etc/gmaps.key` (not packed) |
| `Settings.Map` | `tile` | GET `z,x,y` → OSM PNG via `/webman/tps-api` (DSM CSP `img-src`) |
| `Settings.Telegram` | `get` | `{enable_telegram,follow_mail,min_interval_telegram,has_token,chat_id,token,bot_token}` — returns stored secrets for the admin form (UI masks them until Show values) |
| `Settings.Telegram` | `set` | kv + `etc/telegram.conf` (`TOKEN=`/`CHAT=`, `0600`). Secrets via `bot_token` (not `token`, which DSM may overwrite with CSRF). Blank / `********` keep the stored token. |
| `Settings.Telegram` | `test` | `sendMessage`; `{sent:true}` or error 100/104. Uses `bot_token` or stored conf. |
| `Settings.Mirror` | `get` | `{enabled,capture_mode,router_kind,encap,router_ip,local_ip,ifname,tzsp_port,tap_present}` from `etc/mirror.conf` |
| `Settings.Mirror` | `set` | `capture_mode` `copy` requires router IPv4; `router_kind` `openwrt`\|`mikrotik` (`encap` gretap\|tzsp); writes `mirror.conf`, pins `tps0` or LAN; error 100 on bad IP |
| `Settings.Accel` | `get` | `{hyperscan,hyperscan_available,hyperscan_active,mpm_algo,spm_algo,dpdk,dpdk_available,nic_offload,nic_offload_available}` from `etc/accel.conf` |
| `Settings.Accel` | `set` | `hyperscan` bool (default on); DPDK / NIC offload ignored (always false); writes yaml `detect.mpm-algo` and restarts Suricata |
| `Settings.Feed` | `list` | `{feeds:[{id,name,url,enabled}]}`. Seeds OISF-index community sources **disabled**. |
| `Settings.Feed` | `add`/`update`/`delete` | HTTPS (or RFC1918 HTTP); name `[A-Za-z0-9._-]+`, not `et-*`; writes `etc/feeds.json`. Toggle enable, then Update Now. |
