# OOTB UI on a custom Suricata backend

**Date:** 2026-09-08  
**Package:** research PoC (SPK version = git branch or tag; engine in [`VERSION`](../VERSION))  
**Scope:** How the official ExtJS Threat Prevention app (`synoips.js`) was made to launch on DSM 7 x86_64 against vanilla Suricata 8 + tpsweb, what the hacks do, and what to fix or replace.

Not a runtime audit of a NAS. Sources: [`bridge/transport.js`](../spk/src/threatprevention/package/ui/bridge/transport.js), [`dsm7.js`](../spk/src/threatprevention/package/ui/bridge/dsm7.js), [`settings-inject.js`](../spk/src/threatprevention/package/ui/bridge/settings-inject.js) (concatenated at pack time), [`tpsweb.py`](../spk/src/threatprevention/python/tpsweb.py), [`api_routes.py`](../spk/src/threatprevention/python/api_routes.py), [`compat.py`](../spk/src/threatprevention/python/compat.py), [`pack-spk.sh`](../spk/pack-spk.sh). Related: [backend-replaceability.md](backend-replaceability.md), [dsm-extjs-sdk.md](dsm-extjs-sdk.md), [backend-port-backlog.md](api/backend-port-backlog.md).

The official ExtJS app (`synoips.js`, `SYNO.SDS.TPS.Application`) is Synology copyright and is packed here only so we can measure the real API surface. Do not publish it as a community contribution.

---

## 1. Verdict

The official app is **not** a Suricata UI. It is a DSM client for a **21-API vendor stack** (`SYNO.TPS.*`) that used to talk to aarch64 CGI modules and synosuricata 6 NFQUEUE.

Vanilla Suricata 8 supplies capture, `eve.json`, and reload. Everything else — transport, envelopes, widgets, privilege — is a compatibility layer. The PoC proves the window opens and tabs round-trip JSON. It does **not** prove SRM feature parity.

| | |
| --- | --- |
| `SYNO.TPS.*` APIs shimmed | 21 |
| `bridge/*.js` | ~2.8k lines (3 files, concat at pack) |
| Capture | AF_PACKET IDS (no NFQUEUE) |
| Hack layers | 8 |

Rough split of **compatibility work** (not package bytes). Suricata 8 itself was the small part:

| Share | Work |
| --- | --- |
| ~15% | Suricata 8 + AF_PACKET |
| ~30% | Envelopes (`compat.py`) |
| ~20% | Transport hijack |
| ~25% | DSM 7 / Ext patches |
| ~10% | Privilege / nginx / setcap |

---

## 2. Runtime path

Official JS calls host mixins only. The bridge steals hosted `SYNO.TPS.*` (and NSM/USB/SystemDB stubs) and POSTs same-origin `/webman/tps-api` → nginx → tpsweb. Mail/SMS/Push compounds stay on `entry.cgi`. The browser does not call `:19557`.

```
synoips.js (official, unmodified)
    │  sendWebAPI / SYNO.API.Store / pollReg / downloadWebAPI / compound
    ▼
bridge (transport + dsm7 + settings-inject, prepended at pack time)
    │  isHosted? → tpsweb JSON : else DSM entry.cgi
    ▼
tpsweb.py + compat.py
    │  SQLite events, compiler → suricata.rules
    ▼
Suricata 8  AF_PACKET  -i ovs_eth0
```

---

## 3. Hack layers

Verdict: **Keep** = load-bearing and shaped correctly. **Must-keep** = regression-prone but required. **Fragile** = works but regresses easily. **Poor** = wrong abstraction. **Mixed** = two patterns for the same job. **Blocked** = DSM policy, not code taste.

| Layer | Verdict | Hack | Why it exists |
| --- | --- | --- | --- |
| Pack | Keep | Prepend `bridge/{transport,dsm7,settings-inject}.js` into `synoips.js` | A second `ui/config` module that depends on Application caused a JSLoad cycle and the tile never opened. |
| Transport | Fragile | Hijack `sendWebAPI` / Request / Store / `pollReg` | Official JS never writes `entry.cgi` for `SYNO.TPS.*`. Mixins must land on `AppWindow` **and** bare `Ext.Component` (SignatureUpdater). |
| Desktop poll | Must-keep | Skip non-TPS compounds on `SYNO.API.Request` | Wrapping Request globally crashed DSM `pollingCompoundCallack` (expected `data.reg_ref`). Only intercept hosted TPS compounds. |
| Envelope | Keep | `compat.py` reshapes Suricata/SQLite into SRM contracts | `Event.list` is async `{task_id}`; Sensor status is a state machine; Signature roots and Policy types are vendor-specific. |
| DSM 7 widgets | Fragile | Chart stubs, `htmlEncode`, sprite CSS, Maps/OSM | SRM widgets are missing or behave differently on DSM 7 Ext 3.4. Most Overview/Map/Storage bugs are host diffs, not Suricata. |
| Forms | Poor | `isValid` / `isDirty` / `setTimeout` originalValue | Official Apply refuses empty iface grids and hidden ET Pro code. Dirty detection for schedule and capture mode is patched after the fact. |
| Injected UI | Mixed | Telegram, extra feeds, capture/GRE mode | Two strategies: strip fields from official `Notification.set` vs fieldset `webapi` for Mirror. Inconsistent and easy to break Apply. |
| Privilege | Blocked | `run-as: package` + manual `setcap` + nginx snippet | Unsigned DSM 7 cannot `run-as: root` (error 319). AF_PACKET needs `CAP_NET_ADMIN` after every install. |

---

## 4. Concrete hooks

| Hook | What it papers over |
| --- | --- |
| JSLoad | Bridge prepended into `synoips.js`; `tps-chart.js` is a separate `type:lib` because Overview depends on `SYNO.SDS.Chart.*` |
| `knownAPI` | `injectInfo` writes `SYNO.TPS.*` into `Manager.knownAPI` so Store/FormPanel think the APIs exist on DSM |
| `sendWebAPI` | Wrapped on `AppWindow`, `AppInstance`, and `Ext.Component`; dispatch only if `isHosted` |
| Request/Manager | `requestAjaxAPI` rewrite would send TPS to `entry.cgi`; hook intercepts hosted APIs before that |
| `pollReg` | Replaced with `setInterval` calling tpsweb. Unregister clears numeric ids. Must copy `.Polling` onto `Request` |
| `Event.list` | Immediate `{events}` became `{task_id}` + `list_status` poll — otherwise the Events grid spins forever |
| `Sensor.get` | `running` → `engine_start`; live `/sys/class/net` merge; hide `ethN` when `ovs_ethN` exists |
| `htmlEncode` | DSM 7 encodes Overview HTML; `patchDisplayHtml` + pathlink capture click + skip restore when `<a>` already live |
| Sprite | Selected sidebar used the white SRM frame on DSM 7 light-blue chrome; CSS forces `0 -24px` (blue) |
| Maps | Google loader needs a key; OSM tiles proxied same-origin because DSM CSP is `img-src 'self'` |
| Storage/USB | `SYNO.Core.ExternalDevice.Storage.USB` and SystemDB stubbed; `logStorageMaxLimit` faked from volume size |
| `NSM.Device` | SRM-only Core API; stub on DSM so Device tab compounds do not 102 |
| `setcap` | Unsigned packages cannot declare file capabilities. Admin must `setcap` suricata after every install or start fails |

---

## 5. Poor or brittle functionality

These are the places the shim fights the official app instead of meeting the contract, or where the UI advertises behavior the backend cannot do.

| ID | Sev | Issue | What happens | Fix |
| --- | --- | --- | --- | --- |
| P1 | High | **Landed.** IDS-only chrome | Drop-packet stays off. `prevention_enforced:false`. Mode flags are saved; packets are not dropped. | — |
| P2 | High | **Guarded, still wrap Request** | `shouldStealRequest` refuses Polling APIs, polling callbacks, and Core-only compounds. Easy to regress. | Keep hosted-only steal; never wrap Request without copying `.Polling`. |
| P3 | High | **Landed.** DisplayField HTML | `htmlEncode:false` on official fragments; capture-phase pathlink clicks. | — |
| P4 | Med | **Landed.** General dirty snap | `processReturnData` snaps `originalValue` once via `clearGeneralDirty`. No 0ms/50ms timers. | — |
| P5 | Med | **Landed.** Capture radios | `syncCaptureMode` after official Sensor get. Single `check` handler. No `interfaceGrid.setDisabled` wrap. | — |
| P6 | Med | **Landed.** Chart stubs | `setChartItems`/`draw` plot official series; empty/all-zero shows a DSM note. | — |
| P7 | Med | **Landed.** Server-side compound | `SYNO.TPS.Compound.request` applies Accel → Mirror → Sensor → Schedule → Source. | — |
| P8 | Med | Fake `Polling.List` still present | SignatureUpdater `update()` polls `Update.status`, but `Polling.List` is still synthesized for leftover `pollList` callers. | Drop the fake List if nothing still calls `pollList`. |
| P9 | Med | **Landed.** God files | `api_routes.py` dispatch. `watchAssign` for SignatureUpdater. | — |
| P10 | Med | **Landed.** gretap at start only | `settings_mirror` writes conf + pin; `tap_present` is honest. `tps0` in `start-stop-status`. | — |
| P11 | Low | Two extra-feature patterns | Telegram on official Notify `fillConfig`; Mirror fieldset on General; Feeds is a new tab. | One pattern would be cleaner; not required for the PoC. |
| P12 | Low | **Landed.** No `:19557` fallback | Bridge posts `/webman/tps-api`, then same-origin package `/api`. Fail closed if both miss. | — |

---

## 6. What already works (do not rip out)

**Envelope layer.** `compat.py` is the right idea: one place that maps eve/SQLite onto official roots (`signatures`, `rules`, `list`, `days7` buckets, `use_code`, `db_size_*`). Expand [`test_compat.py`](../spk/src/threatprevention/python/test_compat.py) per tab rather than rewriting handlers ad hoc.

**Hosted-only dispatch.** After the `reg_ref` incident, dispatch refuses DSM polling compounds and non-TPS APIs. Keep that allowlist. Adding a new API means `Bridge.apis`, an `api_routes.py` entry, and a tpsweb handler.

**JSLoad prepend.** Do not register the bridge as its own `ui/config` module. Pack-time concat is the supported way to run before `Ext.define` of TPS classes. Chart stubs as a separate `type:lib` is also correct.

**IDS topology.** Capture is AF_PACKET on the NAS LAN (typically `ovs_eth0`). This package is not a gateway.

**Hyperscan.** Default MPM/SPM is Intel Hyperscan when the binary has `libhs`. Settings **Hardware acceleration** writes `etc/accel.conf`. DPDK and NIC offload stay unwired. [hw-acceleration.md](hw-acceleration.md).

---

## 7. Improvement plan

| When | Theme | Work | Detail |
| --- | --- | --- | --- |
| Landed | Honesty | IDS-only chrome | Drop-packet checkbox stays off. Default mode (availability vs security) is saved; packets are not dropped. Sensor get/set force `enable_prevention=no`, `prevention_enforced:false`. |
| Landed | Ops | Hyperscan default | `etc/accel.conf` `hyperscan=1`; yaml `mpm-algo: hs`. DPDK / NIC offload listed but disabled. Settings **Hardware acceleration**. |
| Landed | Safety | Narrow the Request hook | `shouldStealRequest` refuses Polling APIs, polling callbacks, and Core-only compounds. `test_compat.py` locks the `reg_ref` contract. |
| Landed | Forms | One post-load snap | `processReturnData` snaps `originalValue` once via `clearGeneralDirty`. No 0ms/50ms General dirty timers. |
| Landed | Capture | Un-monkey `setDisabled` | `syncCaptureMode` after official Sensor get. Radios: single `check` handler. No `interfaceGrid.setDisabled` wrap. |
| Landed | API | Server-side compound | `SYNO.TPS.Compound.request` applies Accel → Mirror → Sensor → Schedule → Source. Result rows stay in request order. |
| Landed | Ops | gretap only at package start | `settings_mirror` writes conf + pin; `tap_present` is honest. `ensure_gretap` lives in `start-stop-status`. |
| Landed | Code | Split the bridge at pack time | `bridge/transport.js`, `dsm7.js`, `settings-inject.js` concatenated in `pack-spk.sh`. Same JSLoad prepend. |
| Landed | Tests | Envelope fixtures from `synoips.js` | Store roots (`signatures`, `rules`, `list`, `devices`, `notification_filters`, `events`, `days7`, `trends`) plus FormPanel gets in `test_compat.py`. Capture-mode Apply order is the Compound Mirror-then-Sensor case. |
| Landed | Transport | Drop `:19557` fallback | Bridge posts `/webman/tps-api`, then same-origin `/webman/3rdparty/ThreatPrevention/api`. No `http://host:19557`. |
| Landed | Charts | Real Overview graphs or a stub label | `LineChart` / `PieChart` draw SVG from official `setChartItems` data. All-zero / empty series show a DSM note instead of a blank graph. |
| Landed | Ops | setcap + nginx in one operator path | `postinst` prints the exact `sudo setcap`. Sensor.get includes `capture_capable`. Overview banner if cap missing. |
| Landed | Code | Split tpsweb routers | `api_routes.py` maps `SYNO.TPS.*` to tpsweb implementations. `handle()` is a one-line dispatch. SignatureUpdater is intercepted with `watchAssign` (no 25ms poll). |
| Exit | Product | Vue DSM app, Suricata-native API | Stop shipping `synoips.js`. Official UI is research-only and Synology copyright. |

**Recommended next cuts if you stay on the shim**

Later cuts from this review (charts, setcap banner, `api_routes.py`, SignatureUpdater `watchAssign`, compound, IDS chrome) are in this tree. Remaining shim debt is P8 (`Polling.List`) and P11 (three inject styles). Do not start a Vue DSM app unless asked.

---

## 8. Strategic fork

### Stay on the shim (keep `synoips.js`)

Best if the goal is still “does the official window run.” Tighten transport, envelopes, and honesty of IDS vs IPS. Never edit `unpacked/package/ui/synoips.js`; wrap prototypes only.

Cost: every DSM 7.x host change can break `htmlEncode`, Request, or FormPanel dirty. Official UI remains Synology copyright — research-only, not a community app to publish.

### Exit: new DSM Vue app

Official current SDK is Vue (`v-app-window`). A small app that talks a Suricata-native JSON API (`eve`, `suricata-update`, policy files, capture mode) drops ~80% of the bridge.

Cost: rewrite Overview / Events / Policy / Settings. Gain: no envelope fiction, no Request wrap, no sprite-frame CSS, legal clarity. Keep tpsweb as the backend; delete `compat.py` shapes that exist only for `synoips.js`.
