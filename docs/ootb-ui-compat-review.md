# OOTB UI on a custom Suricata backend

**Date:** 2026-09-08  
**Package:** research PoC `8.0.6-0056`  
**Scope:** How the official ExtJS Threat Prevention app (`synoips.js`) was made to launch on DSM 7 x86_64 against vanilla Suricata 8 + tpsweb, what the hacks do, and what to fix or replace.

Not a runtime audit of a NAS. Sources: [`bridge/transport.js`](../spk/src/threatprevention/package/ui/bridge/transport.js), [`dsm7.js`](../spk/src/threatprevention/package/ui/bridge/dsm7.js), [`settings-inject.js`](../spk/src/threatprevention/package/ui/bridge/settings-inject.js) (concatenated at pack time), [`tpsweb.py`](../spk/src/threatprevention/python/tpsweb.py), [`compat.py`](../spk/src/threatprevention/python/compat.py), [`pack-spk.sh`](../spk/pack-spk.sh). Related: [backend-replaceability.md](backend-replaceability.md), [dsm-extjs-sdk.md](dsm-extjs-sdk.md), [backend-port-backlog.md](api/backend-port-backlog.md).

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

Official JS calls host mixins only. The bridge steals hosted `SYNO.TPS.*` (and a few Core stubs) and POSTs same-origin `/webman/tps-api` → nginx → tpsweb `:19557`. Core APIs stay on `entry.cgi`.

```
synoips.js (official, unmodified)
    │  sendWebAPI / SYNO.API.Store / pollReg / downloadWebAPI / compound
    ▼
tps-bridge (transport + dsm7 + settings-inject, inlined at pack time)
    │  isHosted? → tpsweb JSON : else DSM entry.cgi
    ▼
tpsweb.py + compat.py
    │  SQLite events, compiler → suricata.rules
    ▼
Suricata 8  AF_PACKET  -i ovs_eth0 | tps0
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
| Privilege | Blocked | `run-as: package` + manual `setcap` + nginx snippet | Unsigned DSM 7 cannot `run-as: root` (error 319). AF_PACKET and gretap need `CAP_NET_ADMIN` after every install. |

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
| `Sensor.get` | `running` → `engine_start`; live `/sys/class/net` merge; hide `ethN` when `ovs_ethN` exists; pin `tps0` in copy mode |
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
| P1 | High | Prevention checkbox is a lie | `enable_prevention` and `network_security_mode=security` are stored. Capture stays AF_PACKET IDS. Users think packets will drop. | Disable or relabel the checkbox; return `prevention_enforced:false` everywhere; never imply NFQUEUE. |
| P2 | High | Global `SYNO.API.Request` wrap | Almost took down DSM desktop polling. Guard is `compoundHasHosted` + `isPollingCallback`, easy to regress. | Stop wrapping Request. Only wrap TPS mixins (`sendWebAPI`, Store for hosted APIs, `pollReg`). Let Core compounds hit `entry.cgi`. |
| P3 | High | DisplayField `innerHTML` rewrite | DSM 7 `htmlEncode` + `restoreOfficialMarkup` replaced live `<a class="pathlink">` and dropped `afterrender` click handlers. | Set `htmlEncode:false` on those fields. Bind clicks with capture-phase delegation. Never replace `innerHTML` of live widgets. |
| P4 | Med | General form dirty/valid patch pile | Fake `ovs_eth0` rows, `allowBlank` on code/weekday, `CheckUpdateSettingsDirty` always includes Schedule.set, `clearDirty` at 0ms and 50ms. | After official `processReturnData`, snap `originalValue` once. Drive `isValid` from real data. Do not inject phantom NICs except as a last-resort fallback. |
| P5 | Med | Capture mode `setDisabled` gate | Monkey-patches `interfaceGrid.setDisabled` so official Sensor load cannot re-enable the grid. Radios bound via handler+check+click. | One check handler, same pattern as `onEnableSensorChecked`. No prototype wrap. Official load then our sync, in that order only. |
| P6 | Med | Chart stubs look like charts | `SYNO.SDS.Chart.*` SVG placeholders let Overview construct. Empty series used to look like a blank product graph. | Landed: `setChartItems`/`draw` plot official `[index,y]` series; all-zero / empty shows a DSM note. |
| P7 | Med | Compound = N sequential HTTP posts | Settings Apply fans out each `SYNO.TPS.*` call. Order `Sensor.set` vs `Mirror.set` races capture pin. | Add one tpsweb compound method that applies the list server-side in a defined order (Mirror then Sensor). |
| P8 | Med | Fake `Polling.List` admin collection | SignatureUpdater expected DSM job names `SYNO.TPS_Updater`. Bridge synthesizes a collection then rewrites `update()` to poll `Update.status`. | Keep the updater patch (it is the right contract) but drop the fake List once `update()` no longer calls `pollList`. |
| P9 | Med | God files | `tpsweb.handle()` was a long if-ladder. Timing retries waited for `Ext.define`. | Landed: `api_routes.py` dispatch. `hookExtDefine` + `whenClass` for Ext classes; `watchAssign` for SignatureUpdater (object literal). |
| P10 | Med | gretap from the package user | UI writes `mirror.conf`; tpsweb `ip link add` often fails without `CAP_NET_ADMIN`. Tunnel only appears after `synopkg restart` as root. | Create `tps0` only in `start-stop-status`. UI set writes conf + pin; return `tap_present` honestly; tell the user to restart the package. |
| P11 | Low | Two extra-feature patterns | Telegram stripped from `Notification.set`; Mirror uses fieldset `webapi`; Feeds is a new tab with `useDefaultBtn:false`. | One pattern: extra Settings tab for all community fields. Do not splice official `fillConfig` except for capture source if it must sit next to the iface grid. |
| P12 | Low | HTTPS DSM mixed content | tpsweb is HTTP `:19557`. Same-origin nginx `/webman/tps-api` is the fix; leftover `:19557` fallback still exists in the bridge. | Remove the host:19557 fallback. Fail closed if `/webman/tps-api` (then same-origin legacy) is missing. |

---

## 6. What already works (do not rip out)

**Envelope layer.** `compat.py` is the right idea: one place that maps eve/SQLite onto official roots (`signatures`, `rules`, `list`, `days7` buckets, `use_code`, `db_size_*`). Expand [`test_compat.py`](../spk/src/threatprevention/python/test_compat.py) per tab rather than rewriting handlers ad hoc.

**Hosted-only dispatch.** After the `reg_ref` incident, dispatch refuses DSM polling compounds and non-TPS APIs. Keep that allowlist. Adding a new API means `Bridge.apis` plus a tpsweb branch — that rule is sound.

**JSLoad prepend.** Do not register the bridge as its own `ui/config` module. Pack-time concat is the supported way to run before `Ext.define` of TPS classes. Chart stubs as a separate `type:lib` is also correct.

**IDS topology.** The NAS is not the gateway. LAN listen vs OpenWrt GRE / MikroTik TZSP copy is a real product choice. Keep `mirror.conf` + `start-stop-status` tap create. Stop creating tunnels from tpsweb as the package user. Operator docs: [router-traffic-copy.md](router-traffic-copy.md), DSM Help **Router traffic copy**, `target/etc/openwrt/` and `target/etc/mikrotik/`.

---

## 7. Improvement plan

| When | Theme | Work | Detail |
| --- | --- | --- | --- |
| Landed | Honesty | IDS-only chrome | Prevention / security-mode widgets disabled. Overview + Settings notes. Sensor get/set force `enable_prevention=no`, `availability`, `prevention_enforced:false`. |
| Landed | Safety | Narrow the Request hook | `shouldStealRequest` refuses Polling APIs, polling callbacks, and Core-only compounds. `test_compat.py` locks the `reg_ref` contract. |
| Landed | Forms | One post-load snap | `processReturnData` snaps `originalValue` once via `clearGeneralDirty`. No 0ms/50ms General dirty timers. |
| Landed | Capture | Un-monkey `setDisabled` | `syncCaptureMode` after official Sensor get. Radios: single `check` handler. No `interfaceGrid.setDisabled` wrap. |
| Landed | API | Server-side compound | `SYNO.TPS.Compound.request` applies Mirror → Sensor → Schedule → Source. Result rows stay in request order. |
| Landed | Ops | gretap only at package start | `settings_mirror` writes conf + pin; `tap_present` is honest. `ensure_gretap` lives in `start-stop-status`. |
| Landed | Code | Split the bridge at pack time | `bridge/transport.js`, `dsm7.js`, `settings-inject.js` concatenated in `pack-spk.sh`. Same JSLoad prepend. |
| Landed | Tests | Envelope fixtures from `synoips.js` | Store roots (`signatures`, `rules`, `list`, `devices`, `notification_filters`, `events`, `days7`, `trends`) plus FormPanel gets in `test_compat.py`. Capture-mode Apply order is the Compound Mirror-then-Sensor case. |
| Landed | Transport | Drop `:19557` fallback | Bridge posts `/webman/tps-api`, then same-origin `/webman/3rdparty/ThreatPrevention/api`. No `http://host:19557`. |
| Landed | Charts | Real Overview graphs or a stub label | `LineChart` / `PieChart` draw SVG from official `setChartItems` data. All-zero / empty series show a DSM note instead of a blank graph. |
| Landed | Ops | setcap + nginx in one operator path | `postinst` prints the exact `sudo setcap`. Sensor.get includes `capture_capable`. Overview banner if cap missing. |
| Landed | Code | Split tpsweb routers | `api_routes.py` maps `SYNO.TPS.*` to tpsweb implementations. `handle()` is a one-line dispatch. SignatureUpdater is intercepted with `watchAssign` (no 25ms poll). |
| Exit | Product | Vue DSM app, Suricata-native API | Stop shipping `synoips.js`. Official UI is research-only and Synology copyright. |

**Recommended next cuts if you stay on the shim**

The review Later cuts (charts, setcap banner, `handle()` routers, Ext.define / SignatureUpdater waits) are in this tree. Further work on this PoC is the Exit fork: a Vue DSM app and a Suricata-native API, not more shim tightening.

---

## 8. Strategic fork

### Stay on the shim (keep `synoips.js`)

Best if the goal is still “does the official window run.” Tighten transport, envelopes, and honesty of IDS vs IPS. Never edit `unpacked/package/ui/synoips.js`; wrap prototypes only.

Cost: every DSM 7.x host change can break `htmlEncode`, Request, or FormPanel dirty. Official UI remains Synology copyright — research-only, not a community app to publish.

### Exit: new DSM Vue app

Official current SDK is Vue (`v-app-window`). A small app that talks a Suricata-native JSON API (`eve`, `suricata-update`, policy files, capture mode) drops ~80% of the bridge.

Cost: rewrite Overview / Events / Policy / Settings. Gain: no envelope fiction, no Request wrap, no sprite-frame CSS, legal clarity. Keep tpsweb as the backend; delete `compat.py` shapes that exist only for `synoips.js`.
