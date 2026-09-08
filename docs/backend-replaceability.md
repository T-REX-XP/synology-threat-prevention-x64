# How hard is it to replace Synology’s Threat Prevention backend with vanilla Suricata 8?

**Scope:** research PoC, not a product and not a contribution. The official ExtJS app (`synoips.js`, `SYNO.SDS.TPS.Application`) is Synology copyright and is packed here only so we can measure the real API surface. The eight `SYNO.TPS.*.so` modules are aarch64; they will not load on this x86_64 NAS.

**Question this document answers:** if you keep the official desktop app and swap the engine for stock Suricata 8, how much Synology-specific backend do you still have to reimplement?

---

## 1. Verdict

The official app is **not** a Suricata UI. It is a DSM ExtJS client for a **21-API vendor stack** (`SYNO.TPS.*`) that happens to drive a patched Suricata 6.0.4 IPS.

Vanilla Suricata 8 gives you: packet capture, rule matching, `eve.json`, `suricatasc` reload, `suricata-update`. That is roughly **one layer** of the official stack.

To make the official app fully replaceable you still need:

| Layer | Official | Vanilla Suricata 8 | PoC replacement |
| --- | --- | --- | --- |
| Desktop | ExtJS `synoips.js` + `ui/config` `type: app` | none | pack official UI + inlined `ui/bridge/*.js` ([dsm-extjs-sdk.md](dsm-extjs-sdk.md)) |
| WebAPI transport | DSM `sendWebAPI` → `entry.cgi` → `.so` | none | bridge → same-origin `/webman/tps-api` (nginx → tpsweb) |
| 21 `SYNO.TPS.*` contracts | 8 aarch64 CGI modules + `libsynotps` | none | Python `tpsweb` + `compat.py` |
| Event store | PostgreSQL `synotps` (Barnyard2 schema) | `eve.json` only | SQLite + `ingest.py` |
| Policy compiler | `synotpsd` / `synotpstool` + `signature.conf` | rule files on disk | `compiler.py` → `var/rules/suricata.rules` |
| Engine | `synosuricata` 6.0.4 NFQUEUE IPS | Suricata 8 AF_PACKET IDS | vendored linux/amd64 Suricata 8 |
| Device / NSM | `SYNO.Core.Network.NSM.Device` + MAC table | none | ARP scrape; NSM join still missing |
| Map / GeoIP | Event.Map + Google Maps loader (no API key) | none | GeoIP Country `.dat` when present; optional `etc/gmaps.key` — [google-maps.md](google-maps.md) |
| Notify / export | DSM mail + File Station export folder | none | persist filters; `synodsmnotify` if present; Telegram via `etc/telegram.conf`; export dir for File Station |
| Inline block | NFQUEUE + `syno-bridge-nf-*` + USB swap | AF_PACKET IDS | **not replaced** |

**Complexity class:** a compatibility layer is a few thousand lines and can light up Overview / Events / Policy / Statistics / Settings **read/write against eve + SQLite**. A **full** replacement of the Synology implementation (IPS, PostgreSQL, synotpsd, NSM, GeoIP, notifications, export, rule-DB build states) is a **product-sized backend**, not a Suricata config tweak.

---

## 2. Official stack (what the app actually talks to)

```
synoips.js
    │  sendWebAPI / SYNO.API.Store / pollReg / downloadWebAPI / compound
    ▼
/webapi/entry.cgi
    │  SYNO.TPS.lib  (JSON method table)
    ▼
SYNO.TPS.{Event,Sensor,Signature,Settings,Device,Statistic,Notification,Backup}.so
    │  libsynotps
    ▼
┌─────────────┬──────────────┬─────────────────┬──────────────────┐
│ PostgreSQL  │ synotpsd     │ synosuricata    │ synotpstool      │
│ synotps     │ event ingest │ 6.0.4 NFQUEUE   │ sensor enable,   │
│ Barnyard2   │ rotate,      │ IPS + ET feed   │ scheduler patch  │
│ schema      │ cron, udev   │                 │                  │
└─────────────┴──────────────┴─────────────────┴──────────────────┘
```

Start (from official `start-stop-status`) also wires: PostgreSQL `createdb synotps`, upstart jobs, crontab (`api=SYNO.TPS.*`), syslog-ng, logrotate, udev, net-event hooks, a `/proc/sys/net/bridge/syno-bridge-nf-*` switch, and `ln -sf …/SYNO.TPS.lib /usr/syno/synoman/webapi/`.

None of that exists for an unsigned DSM 7 community package (`run-as: package`). The `.so` files are the wrong ISA. So the official transport **cannot** be reused on this NAS; only the **contract** can.

---

## 3. What the official JS assumes (the real contract)

`docs/api/SYNO.TPS.contract.md` is the simplified community shape. Official `synoips.js` is stricter. The PoC `compat.py` layer exists because of these mismatches:

### 3.1 Event.list is asynchronous

```
Event.list      →  { task_id: "N" }
Event.list_status(task_id) poll every 5s
                →  { finish: true, data: { events, total, now } }
```

Community `list` returned `{events,total}` immediately. The official Events tab would sit on “loading” forever without the handshake.

`Event.get` uses `params.id` as `"sid-cid"` (e.g. `1-42`), not `cid`. Severity is the string `high|medium|low`. `ip_src` / `ip_dst` are **display strings**. Packet fields are flattened (`ip_ver`, `tcp_seq`, `payload` hex), not nested `iphdr` only. `ip_proto` is compared as `"1"|"6"|"17"`.

`Event.Offset.get` takes `cid` and returns the **row offset** of that event (jump-to-event from Overview).

### 3.2 Sensor status is a state machine, not running/stopped

Overview polls `SYNO.TPS.Sensor.get` every 5s and switches screens on:

`engine_init` · `engine_start` · `build_signature_database` · `reset_signature_database` · `migrate_event` · `updating_signature` · empty/other → stopped

Also required: `enable_sensor`, `enable_prevention`, `enable_auto_export_events_during_postupgrade`, `network_security_mode`, `config_exist`, `interface_list[]` of `{if_id, enabled}`.

Prevention + `network_security_mode=security` in the official product means **NFQUEUE inline IPS**. Suricata 8 AF_PACKET IDS can store the flags; it cannot honor them without a gateway + queue wiring that this NAS package does not have.

### 3.3 Signature / Policy roots and types

| API | Official root / shape |
| --- | --- |
| `Signature.list` | `{ signatures: [{ name, enabled, enabledCount, totalCount }] }` — **classes**, not rules |
| `Signature.Classification.list` | `{ signatures: […] }` (name→description map) |
| `Signature.Rule.list` | `{ rules: […] }` |
| `Signature.Policy.list` | `{ list: […] }` with `type` **int** 1=class, 2=signature, 3=filter |
| `Signature.Policy.set` | `{ policy: [{ class_name, action: enabled\|disabled, signatures: […] }] }` |
| `Signature.Policy.delete` v2 | `{ classes: [{class_name}], signatures: [{sid, ip_src, ip_dst}] }` |

`Sensor.Variables.get` uses **lowercase** Suricata vars (`home_net`, `external_net`, `sql_servers`, …).

### 3.4 Statistics

`Event.Statistic.get` is **not** `{total,high,medium,low,top_*}`. It is three buckets:

`days7` / `days30` / `all_logs`, each with `class_name[]`, `ip_src[]`, `ip_dst[]`, `botnet_*`, `country_src[]`, `begin`, `end`.

`Statistic.Trends.get` is `{ begin, end, trends: [{begin,end,high,medium,low,total}] }`.

`Statistic.Device.list` uses root `devices`. `Device.list` uses root `device_list` and field `loading`. Settings Device.set sends `{ default_detect, device_list }` **and** compounds `SYNO.Core.Network.NSM.Device.get` (DSM core API — not ours).

### 3.5 Compound + Store + download

Settings and Policy load via `sendWebAPI({ compound: { params: […APIs] } })` and read `data.result[]`.

Ruleset grid and concerned-devices use `SYNO.API.Store` (entry.cgi + `SYNO.API.Info` registration).

Backup uses `downloadWebAPI` (file download), not JSON in the Ext callback.

HTTPS DSM uses same-origin `/webman/tps-api`. The browser must not call `http://host:19557` (mixed content). tpsweb still listens on loopback `:19557` and a unix socket for nginx.

---

## 4. Complexity by API (replaceability score)

Score: **S** = Suricata-native (yaml / eve / suricatasc / suricata-update). **M** = medium Python store. **H** = Synology-specific product behavior. **X** = not replaceable without other DSM subsystems or IPS.

| API | Methods | Score | Why |
| --- | --- | --- | --- |
| Event.list / list_status / get / Offset | async task + detail | M | eve ingest + SQLite is enough; handshake is vendor |
| Event.Statistic | 3-bucket + botnet + country | M–H | counts are easy; botnet/GeoIP are not in eve |
| Event.Map | list | H | GeoIP + Google Maps loader |
| Event.ExportFolder | get | H | File Station `opendir` path |
| Sensor get/set | state machine + ifaces | M + X | flags + iface file are easy; prevention is IPS |
| Sensor.Variables | get | S | yaml address/port groups |
| Signature / Classification / Rule | list | S–M | parse rules + classification.config |
| Signature.Policy | CRUD + compile + reload | M | map actions → `suricata.rules` + `suricatasc` |
| Settings.Update* | check/update/schedule/source | S–M | `suricata-update` + kv |
| Settings.Storage | size / clear | M | SQLite file size; no official rotate/pg dump |
| Device list/set | ARP + default_detect | M + H | no NSM inventory, no per-MAC NFQUEUE bypass |
| Statistic.Device / Trends | list/get | M | eve aggregates |
| Notification / Filter | get/set | H | persist only; DSM mail/push/SMS not invoked |
| Backup | backup/restore | M | JSON, not official `.dss` |

**Count:** 21 APIs, ~45 methods. About **8** are “Suricata plus a thin store.” About **10** need a real event/policy database and compiler. About **5** need DSM-core or IPS hardware path.

---

## 5. What this PoC implements

Compatibility layer on **vanilla Suricata 8** (AF_PACKET IDS; engine version in [`VERSION`](../VERSION)). Official UI is downloaded at pack time; it is not cloned or rebuilt. SPK version is the git branch or tag ([`spk/pkg-version.sh`](../spk/pkg-version.sh)).

1. **Pack official UI** from `build/official/` (`synoips.js`, texts, help, icons).
2. **`ui/bridge/*.js`** prepended into `synoips.js` at pack time (`transport.js`, `dsm7.js`, `settings-inject.js`) — hosted `SYNO.TPS.*` via `/webman/tps-api`. Core compounds stay on `entry.cgi`. `.Polling` is copied if Request is wrapped.
3. **`api_routes.py` + `compat.py` + `tpsweb`** — official envelopes: Event `task_id` / `list_status`, Sensor state names + live ifaces (OVS twins collapsed), Signature `signatures` / Policy `list`, Statistic buckets, Source `use_code`, Storage `db_size_*` + clear `task_id`. Community APIs: Telegram, Mirror, Accel, Feed, Compound.
4. **`ingest.py`** — tail `eve.json` into SQLite (payload hex, L3/L4 headers, device `loading_score`).
5. **`compiler.py`** — `signature.conf` + `policy_*` → `var/rules/suricata.rules` + reload.
6. **`SYNO.TPS.lib`** copied for Info listing. **No** aarch64 `.so`.
7. **Settings → Update → Update Now** runs `update-rules.sh` (ET Open/Pro + optional Rule Feeds), then import/compile/reload.

`INFO.dsmappname=SYNO.SDS.TPS.Application`.

### Still not replaced (honest gaps)

- **Inline IPS / drop / per-device bypass** — needs NFQUEUE (or equivalent) and a gateway topology. This NAS is IDS-only.
- **`build_signature_database` / `migrate_event` / PostgreSQL** — we skip those states; engine is `engine_start` or empty.
- **Botnet / country / map** — `country_src` / `location[]` fill when a GeoIP Country `.dat` is present and `ip_src` is public. LAN-only events stay empty. Maps tiles need an optional `etc/gmaps.key`.
- **NSM device names** — `SYNO.Core.Network.NSM.Device` is stubbed (ARP scrape). Real SRM NSM is not on DSM 7.
- **Notifications** — stored; `synodsmnotify` / Telegram when configured. DSM mail/SMS/push transport is Control Panel’s.
- **Official `.dss` backup** — JSON backup only.
- **Unsigned package cannot `setcap` or `run-as: root`** — `install.sh` applies caps; a hand-installed SPK needs admin `setcap` (error 319 otherwise).

---

## 6. Effort estimate (research, not a ship plan)

| Work | Size | Notes |
| --- | --- | --- |
| Suricata 8 + glibc vendor + AF_PACKET on DSM 7 | already done | kernel 5.10 fanout, `ovs_eth0`, setcap |
| Official-shaped Event/Sensor/Signature/Policy/Statistic | ~1–2k LOC | this PoC |
| Full Barnyard2/PostgreSQL parity + rotate/export | weeks | official schema + synotps_rotate |
| NFQUEUE IPS + per-MAC detect + security mode | product | needs routing/bridge + caps + policy path |
| GeoIP map + botnet + NSM join + DSM notify | product | other Synology packages |
| Load official `.so` on x86_64 | **not feasible** | wrong ISA; do not patch/decrypt |

**Conclusion:** making Suricata 8 a **drop-in for `synosuricata`** is the easy part. Making it a **drop-in for the Synology backend the official app is written against** is the hard part — a complete reimplementation of `SYNO.TPS.*` plus several DSM services. The PoC proves the app will run against a compatibility layer; it does not prove feature parity with SRM Threat Prevention.

---

## 7. How to read this package

| Path | Role |
| --- | --- |
| `unpacked/package/ui/synoips.js` | official app (source of truth for the contract) |
| `unpacked/package/webapi/SYNO.TPS.lib` | official method table |
| `spk/src/threatprevention/package/ui/bridge/` | research hook (`transport.js`, `dsm7.js`, `settings-inject.js`) |
| `spk/src/threatprevention/python/compat.py` | official envelopes |
| `spk/src/threatprevention/python/api_routes.py` | `SYNO.TPS.*` dispatch |
| `spk/src/threatprevention/python/tpsweb.py` | HTTP + unix API |
| `docs/api/official-app-surface.md` | official JS + `.lib` inventory |
| `docs/api/backend-port-backlog.md` | remaining gaps vs P3 out of scope |
| `docs/api/SYNO.TPS.contract.md` | simplified community contract |
| `docs/spk-deploy-and-update.md` | install, `setcap`, Update Now, troubleshooting |
| `docs/ootb-ui-compat-review.md` | hacks, landed vs remaining shim debt |

Do not publish `synoips.js` or the official texts/help as a community contribution.
