# Backend port backlog

What is still missing or wrong for the official ExtJS app against the Suricata 8 + tpsweb PoC. Handlers exist for every `SYNO.TPS.lib` method; **shape and side effects** are the work.

Do **not** implement NFQUEUE / inline IPS unless asked. Do **not** start a Vue DSM app unless asked.

Related: [official-app-surface.md](official-app-surface.md), [backend-replaceability.md](../backend-replaceability.md), [dsm-extjs-sdk.md](../dsm-extjs-sdk.md), [ootb-ui-compat-review.md](../ootb-ui-compat-review.md).

Dispatch: [`api_routes.py`](../../spk/src/threatprevention/python/api_routes.py). Envelopes: [`compat.py`](../../spk/src/threatprevention/python/compat.py). Tests: [`test_compat.py`](../../spk/src/threatprevention/python/test_compat.py).

## Priority

| P | Meaning |
| --- | --- |
| P0 | App launch / Package Center / same-origin API — window never opens |
| P1 | Official tab constructs then mis-reads data (wrong root, type, or poll envelope) |
| P2 | Tab works; fill from eve / DSM / GeoIP |
| P3 | Product behavior this PoC will not own (IPS, mail send, `.dss`) |

## P0 — launch and package (done)

| ID | Item | Status | Notes |
| --- | --- | --- | --- |
| T0 | `SYNO.SDS.Chart.*` on DSM 7 | done | `tps-chart.js` + cache-bust `synoips.js?v=<PKG_VERSION>` |
| T1 | nginx `/webman/tps-api` → tpsweb `/api` | done | POST `/` must not serve `index.html`. No browser `:19557` fallback. |
| T2 | Package start vs root-owned `etc/interface` | done | start succeeds if tpsweb is up |
| T3 | `SYNO.API.Request.Polling.List` | done | `.Polling` copied through; SignatureUpdater polls `Update.status` (`watchAssign`). Fake `Polling.List` still exists for leftover `pollList` (shim P8). |
| T4 | `sendWebAPI` / `pollReg` on bare `Ext.Component` | done | SignatureUpdater uses `new Ext.Component()` |
| T5 | Desktop reload | done | Package Center **Open** is enough; log out only if the tile or JS cache is stale |

## P1 — official envelopes (done)

| ID | API.method | Status |
| --- | --- | --- |
| T10–T12 | Policy `need_force` / CIDR; Rule `msg`/`encode`/`references` | done |
| T13–T14 | `Settings.Update.start_check` / nested `status` | done |
| T15 | `Event.ExportFolder.get` File Station path | done; skip `@eaDir` |
| T16 | `Device.list` ARP + `mesh_re:false`; stub `SYNO.Core.Network.NSM.Device` | done |
| T17 | `Statistic.Device.list` `devices` + `loading` | done |
| T18 | Compound `result[]` | done (`SYNO.TPS.Compound.request`) |
| T19 | `Backup.restore` | JSON only, not official `.dss` |

## P2 — real data behind working shapes (done unless noted)

| ID | API.method | Status |
| --- | --- | --- |
| T20 | `Event.Statistic.get` botnet / `country_src` | GeoIP.dat + trojan/C2 classtypes |
| T21 | `Event.Map.list` `location[]` | GeoIP on public `ip_src`; Maps key optional — [google-maps.md](../google-maps.md) |
| T22 | `Event.get` L3/L4 | synthesize IPv4/6 + proto fields when iphdr missing |
| T23 | `Notification` / `Filter` | upsert modified rows; `synodsmnotify` / `notify.log` |
| T24 | `Sensor.set` prevention / `security` | stored, not enforced (`prevention_enforced:false`, `ips_mode:ids`) |
| T25 | `Settings.Update.Source` ET Pro | sidecar + `update-rules.sh`; missing code → `etpro_error`. **Update Now** is the app path. |
| T26 | `Settings.Storage` USB max | empty USB/SystemDB shapes; `logStorageMaxLimit` fallback |
| T27 | Telegram | `Settings.Telegram` + `etc/telegram.conf`; blank token/chat leaves stored secrets |
| T28 | Extra rule feeds | `Settings.Feed` + `etc/feeds.json`; enable then Update Now |

## P3 — out of scope unless asked

| ID | Item | Why |
| --- | --- | --- |
| X1 | NFQUEUE inline IPS / per-MAC bypass | needs gateway + caps DSM will not grant unsigned (`run-as: root` → 319) |
| X2 | PostgreSQL `synotps` / rotate / `migrate_event` | SQLite eve ingest is the PoC store |
| X3 | Official `.dss` backup format | undocumented binary; JSON backup is enough to test the dialog |
| X4 | DSM mail / SMS / push send | Control Panel owns transport; we persist filters and optional Telegram |
| X5 | Load official aarch64 `.so` | wrong ISA |

## Suggested order (operators)

1. Install via `install.sh` (includes `setcap`).
2. Open Threat Prevention. Settings → **Update** → **Update Now** for current ET Open.
3. Drop a GeoIP Country `.dat` if Map / country pies should show pins (LAN-only events stay empty).
4. ET Pro needs a real oinkcode in Settings; empty code returns `etpro_error`.
5. Leave P3 alone (no NFQUEUE, no official `.dss`, no SMTP).

## Counts (this tree)

- 21 official `SYNO.TPS.*` APIs plus community `Settings.{Telegram,Mirror,Accel,Feed,Map}` and `Compound.request` — routed from `api_routes.py`.
- DSM-core Mail/SMS/Push stay on `entry.cgi`. NSM.Device / SystemDB / USB are stubbed in tpsweb.
- Envelope tests in `test_compat.py` lock Store roots and FormPanel gets.
- Remaining shim debt: [ootb-ui-compat-review.md](../ootb-ui-compat-review.md) P8 / P11.
