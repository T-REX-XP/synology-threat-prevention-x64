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
| T5 | Confirm 0024 installed + logout | **open** | user still on 0023 when `pollList` crashed |

## P1 — official envelopes that still lie

| ID | API.method | Gap | Work |
| --- | --- | --- | --- |
| T10 | `Signature.Policy.add` / `update` | returns `{compiled}` not `{need_force:false}` | overwrite confirm never works; always treat as success |
| T11 | `Signature.Policy.add` / `update` | `old_sid` / `force` / CIDR filters | persist `policy_filter` with ip_src/ip_dst |
| T12 | `Signature.Rule.list` | `references`, `encode`, `msg`; Store `baseParams.name` = class name | parse rule metadata; filter by class |
| T13 | `Settings.Update.start_check` | always flips to `up_to_date` | actually query ET index / `suricata-update check-versions` |
| T14 | `Settings.Update.status` | nested `data.status` / `last_updated` | verify pollReg path from Component |
| T15 | `Event.ExportFolder.get` | string under `@appdata`, File Station `opendir` may refuse | realpath share the admin can open |
| T16 | `Device.list` | ARP only; no NSM names; `mesh_re` | join passthrough `SYNO.Core.Network.NSM.Device` in compound |
| T17 | `Statistic.Device.list` | Store root `devices` + `loading` | match official fields |
| T18 | Compound `result[]` | Settings / Policy / Storage / Sensor+NSM | re-test each panel after T3/T4 |
| T19 | `Backup.restore` | JSON only | accept upload field the Ext dialog sends |

## P2 — real data behind working shapes

| ID | API.method | Gap | Work |
| --- | --- | --- | --- |
| T20 | `Event.Statistic.get` | `botnet_*`, `country_src` empty | GeoIP + optional botnet list |
| T21 | `Event.Map.list` | empty `location[]` | GeoIP on `ip_src`; Maps key is optional |
| T22 | `Event.get` | L3/L4 from eve when present | already hex payload; fill tcp/udp/icmp consistently |
| T23 | `Notification` / `Filter` | persist only | optional: call DSM notify APIs if configured |
| T24 | `Sensor.set` prevention / `security` | stored, not enforced | document IDS-only; do not fake drop counts |
| T25 | `Settings.Update.Source` ET Pro | stores code, no licensed feed | wire `suricata-update enable-source et/pro` when code set |
| T26 | `Settings.Storage` USB max | depends on Core.SystemDB + USB.list passthrough | verify compound on HTTPS |

## P3 — out of scope unless asked

| ID | Item | Why |
| --- | --- | --- |
| X1 | NFQUEUE inline IPS / per-MAC bypass | needs gateway + caps DSM will not grant unsigned (`run-as: root` → 319) |
| X2 | PostgreSQL `synotps` / rotate / `migrate_event` | SQLite eve ingest is the PoC store |
| X3 | Official `.dss` backup format | undocumented binary; JSON backup is enough to test the dialog |
| X4 | DSM mail / SMS / push send | Control Panel owns transport; we only persist filters |
| X5 | Load official aarch64 `.so` | wrong ISA |

## Suggested order

1. Install **0024** (or next) so `Polling.List` exists — T5.
2. T10–T12 so Policy / Ruleset do not surprise the official dialogs.
3. T13–T14 so Overview updater stops looping `start_check`.
4. T16–T18 so Settings + Concerned Devices match NSM.
5. T20–T21 only if the Map / country pies are required for the PoC demo.
6. Leave P3 alone.

## Counts (2026-09-07, tree 8.0.6-0024)

- 21 `SYNO.TPS.*` APIs, 42 `.lib` methods — all have a tpsweb `handle()` branch.
- 9 DSM-core / Entry.Request calls — passthrough only.
- ~20 methods are official-shaped enough to drive a tab.
- ~14 methods return a success envelope with missing or wrong fields.
- 5 product areas are explicitly not ported.
