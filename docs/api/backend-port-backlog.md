# Backend port backlog

What is still missing or wrong for the official ExtJS app against the Suricata 8 + tpsweb PoC. Handlers exist for every `SYNO.TPS.lib` method; **shape and side effects** are the work.

Do **not** implement NFQUEUE / inline IPS unless asked. Do **not** restore a community webpack UI.

Related: [official-app-surface.md](official-app-surface.md), [backend-replaceability.md](../backend-replaceability.md).

## Priority

| P | Meaning |
| --- | --- |
| P0 | App launch / Package Center / same-origin API — window never opens |
| P1 | Official tab constructs then mis-reads data (wrong root, type, or poll envelope) |
| P2 | Tab works with empty/fake data; fill from eve / DSM / GeoIP |
| P3 | Product behavior this PoC will not own (IPS, mail send, `.dss`) |

## P0 — launch and package

| ID | Item | Status | Notes |
| --- | --- | --- | --- |
| T0 | `SYNO.SDS.Chart.*` on DSM 7 | done (0020+) | `tps-chart.js` + cache-bust `synoips.js?v=8.0.6-*` |
| T1 | nginx `/webman/tps-api` → tpsweb `/api` | done (0021) | POST `/` must not serve `index.html` |
| T2 | Package start vs root-owned `etc/interface` | done (0023) | start succeeds if tpsweb is up |
| T3 | `SYNO.API.Request.Polling.List` | coded (0024) | wrapping `Request` wiped `.Polling`; SignatureUpdater.check crashed |
| T4 | `sendWebAPI` / `pollReg` on bare `Ext.Component` | coded (0024) | SignatureUpdater uses `new Ext.Component()` |
| T5 | Confirm 0024 installed + logout | done (0027) | Polling + Ext.Component hooks shipped; 0026/0027 also patch Overview/Map HTML |

## P1 — official envelopes that still lie

| ID | API.method | Gap | Work |
| --- | --- | --- | --- |
| T10 | `Signature.Policy.add` / `update` | `{need_force}` | done (0025) |
| T11 | `Signature.Policy.add` / `update` | `old_sid` / `force` / CIDR | done (0025) |
| T12 | `Signature.Rule.list` | `msg`/`encode`/`references` | done (0025) |
| T13 | `Settings.Update.start_check` | probe ET | done (0025) |
| T14 | `Settings.Update.status` | nested `data.status` | done (0025) |
| T15 | `Event.ExportFolder.get` | File Station path | done (0025); skip `@eaDir` |
| T16 | `Device.list` | ARP + `mesh_re:false` | done (0032): stub `SYNO.Core.Network.NSM.Device` on DSM (SRM-only; 0031 showed No such API) |
| T17 | `Statistic.Device.list` | `devices` + `loading` | done (0025) |
| T18 | Compound `result[]` | Settings / Policy / Storage | coded; re-test on 0027 UI |
| T19 | `Backup.restore` | `dss_file` upload | coded (0028); JSON only, not official `.dss` |

## P2 — real data behind working shapes

| ID | API.method | Gap | Work |
| --- | --- | --- | --- |
| T20 | `Event.Statistic.get` | `botnet_*` / `country_src` | coded (0028): GeoIP.dat + trojan/C2 classtypes |
| T21 | `Event.Map.list` | `location[]` | coded (0028): GeoIP on public `ip_src`; Maps key still optional — [google-maps.md](../google-maps.md) |
| T22 | `Event.get` | L3/L4 | coded (0028): synthesize IPv4/6 + proto fields when iphdr missing |
| T23 | `Notification` / `Filter` | persist + DSM notify | done (0029): upsert modified rows; `synodsmnotify` / `notify.log` |
| T24 | `Sensor.set` prevention / `security` | stored, not enforced | done (0029): `prevention_enforced:false`, `ips_mode:ids`; no NFQUEUE |
| T25 | `Settings.Update.Source` ET Pro | licensed feed | done (0029): sidecar + `update-rules.sh`; missing code → `etpro_error` |
| T26 | `Settings.Storage` USB max | Core compound | done (0029): empty USB/SystemDB shapes; `logStorageMaxLimit` fallback |
| T27 | Telegram notify | extra Settings tab | done (0031): `Settings.Telegram` + `etc/telegram.conf` |
| T28 | Extra rule feeds | extra Settings tab | done (0031): `Settings.Feed` + `etc/feeds.json` (additive to ET) |

## P3 — out of scope unless asked

| ID | Item | Why |
| --- | --- | --- |
| X1 | NFQUEUE inline IPS / per-MAC bypass | needs gateway + caps DSM will not grant unsigned (`run-as: root` → 319) |
| X2 | PostgreSQL `synotps` / rotate / `migrate_event` | SQLite eve ingest is the PoC store |
| X3 | Official `.dss` backup format | undocumented binary; JSON backup is enough to test the dialog |
| X4 | DSM mail / SMS / push send | Control Panel owns transport; we only persist filters |
| X5 | Load official aarch64 `.so` | wrong ISA |

## Suggested order

1. Install **0031** (Telegram + extra feeds + Maps key hook).
2. Drop a GeoIP Country `.dat` if Map / country pies should show pins (LAN-only events stay empty).
3. ET Pro needs a real oinkcode in Settings; empty code returns `etpro_error`.
4. Leave P3 alone (no NFQUEUE, no official `.dss`, no SMTP).

## Counts (2026-09-07, tree 8.0.6-0032)

- 21 `SYNO.TPS.*` APIs, 42 `.lib` methods — all have a tpsweb `handle()` branch.
- 9 DSM-core / Entry.Request calls — passthrough only.
- ~20 methods are official-shaped enough to drive a tab.
- ~14 methods return a success envelope with missing or wrong fields.
- 5 product areas are explicitly not ported.
