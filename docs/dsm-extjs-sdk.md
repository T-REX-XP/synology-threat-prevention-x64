# DSM ExtJS package-app SDK (recovered)

**Date:** 2026-09-07  
**Recovered on:** Synology SA6400 (`synology_epyc7002_sa6400`), DSM **7.4.1**-90080  
**Scope:** How Synology Start Menu apps are loaded, what APIs official Threat Prevention uses, and what this PoC may touch. Not a Synology-licensed SDK dump.

There is **no public ExtJS SDK tarball** from Synology. The current [Developer Guide](https://help.synology.com/developer-guide/synology_package/package_tgz/launch_app.html) documents a **Vue** “DSM UI Framework.” SRM Threat Prevention (`synoips.js`) is the older path: **Ext JS 3.4** plus Synology `SYNO.SDS.*` / `SYNO.ux.*` wrappers that already live on every DSM 7 NAS.

This note recovers that older contract from:

| Source | What we take |
| --- | --- |
| Official [launch an app](https://help.synology.com/developer-guide/synology_package/package_tgz/launch_app.html), [desktop application](https://help.synology.com/developer-guide/integrate_dsm/desktopapp.html), [application config](https://help.synology.com/developer-guide/integrate_dsm/config.html) | `dsmuidir`, `dsmappname`, `ui/config` |
| [`unpacked/package/ui/config`](../unpacked/package/ui/config) + `synoips.js` class list | JSLoad graph, mixins, xtypes |
| This NAS (name inventory only — no host JS copied into git) | Real DSM 7.4 paths, `SYNO.ux` / `SYNO.API` names |
| This package’s packer / bridge | What breaks JSLoad and how we extend Settings |

Do **not** copy `sds.bundle.js`, `extjs-patch.bundle.js`, `ux-all.js`, `ext-all.js`, or official `synoips.js` into a new app. Those files are Synology (and Sencha) copyright. Use them **in the browser on DSM** as the host already shipped.

---

## 1. Two SDKs, one desktop

```
Start Menu click
    → JSLoad reads ui/config
    → loads listed JS modules in depend order
    → constructs type:app class (SYNO.SDS.AppInstance)
    → opens appWindow (SYNO.SDS.AppWindow / PageListAppWindow)
```

| Era | Official docs | This PoC |
| --- | --- | --- |
| **Legacy ExtJS** (DSM 5–7 desktop, SRM apps) | Undocumented. Host: Ext 3.4 + `SYNO.SDS.*` | Official TPS UI |
| **Current Vue** | `v-app-instance` / `v-app-window`, webpack, `config.define` | Not used |

A third option, also official, is `type: url` in `ui/config` (iframe / 3rdparty HTML). Early community builds used that; **8.0.6-0018+** does not. A second `type: app` next to `SYNO.SDS.TPS.Application` fights the Start Menu.

On this NAS both stacks exist: Ext 3.4 + SDS bundles **and** `/usr/syno/synoman/scripts/vue` + `syno-vue-components`. `extjs-patch.bundle.js` even defines `SYNO.SDS.VuePanel` so a Vue page can sit inside an Ext window. **This SPK stays Ext-only.** Mixing Vue `v-app-window` and Ext `PageListAppWindow` in one `ui/config` is unsupported.

---

## 2. Files DSM 7.4 actually loads (on the NAS)

Community wikis still list `/usr/syno/synoman/synoSDSjslib/sds.js`. That file is **gone** on DSM 7.4. The desktop is webpack-split:

| Role | Path on this NAS | Notes |
| --- | --- | --- |
| Ext JS 3.4 | `/usr/syno/synoman/scripts/ext-3.4/ext-all.js` | Sencha 3.4 GPL |
| Synology UX widgets | `/usr/syno/synoman/scripts/ext-3.4/ux/ux-all.js` | `SYNO.ux.*`, `syno_*` xtypes |
| UX polyfill | `/usr/syno/synoman/scripts/ext-3.4/ux/ux-syno-polyfill.js` | DSM 7 extras |
| JSLoad / AppLaunch / Desktop | `/usr/syno/synoman/synoSDSjslib/dist/sds.bundle.js` | ~149 KB. No `AppWindow` here |
| AppWindow / FormPanel / WebAPI mixins | `/usr/syno/synoman/synoSDSjslib/dist/extjs-patch.bundle.js` | ~276 KB. This is the “SDK” |
| Vendor chunk | `/usr/syno/synoman/synoSDSjslib/dist/vendor.bundle.js` | no `Ext.define` |
| WebAPI helper | `/usr/syno/synoman/scripts/synowebapi.js/synowebapi.min.js` | directory, not a `.js` file |
| Package UI symlink | `/usr/syno/synoman/webman/3rdparty/ThreatPrevention` → `target/ui` | |
| Sencha 3.4 API (GPL, not Synology) | https://cdn.sencha.com/ext/gpl/3.4.1.1/docs/ | |

Older DSM / [SimpleExtJSApp wiki](https://github.com/DigitalBox98/SimpleExtJSApp/wiki/Synology-DSM-info) (2024) still documents `sds.js`. Treat that as DSM 6 / early 7. Same *names* (`JSLoad`, `AppInstance`); different files.

`INFO` must set:

```
dsmuidir="ui"
dsmappname="SYNO.SDS.TPS.Application"
```

`dsmappname` is what Package Center **Open** launches ([optional INFO fields](https://help.synology.com/developer-guide/synology_package/INFO_optional_fields.html)).

---

## 3. `ui/config` — the JSLoad SDK

JSON map: **js filename → class name → metadata**. DSM’s loader (`SYNO.SDS.JSLoad` / `JSLoadPromise` / `JSLoader`) walks `depend` and `type`.

Official Threat Prevention (trimmed):

```json
{
  "synoips.js": {
    "SYNO.SDS.TPS.Application": {
      "type": "app",
      "appWindow": "SYNO.SDS.TPS.MainWindow",
      "allUsers": false,
      "allowMultiInstance": true,
      "maxInstance": 1,
      "texts": "texts",
      "icon": "images/IDS_IPS_{0}.png",
      "depend": ["SYNO.SDS.TPS.MainWindow"]
    },
    "SYNO.SDS.TPS.MainWindow": {
      "type": "lib",
      "depend": [
        "SYNO.SDS.TPS.Overview.Panel",
        "SYNO.SDS.TPS.Event.EventPanel",
        "SYNO.SDS.TPS.UserDefined.TabPanel",
        "SYNO.SDS.TPS.Statistic.TabPanel",
        "SYNO.SDS.TPS.Settings.TabPanel"
      ]
    }
  }
}
```

| Field | Meaning |
| --- | --- |
| `type: app` | Start Menu tile. **Exactly one** per package for this PoC |
| `type: lib` | Loaded only as a dependency |
| `appWindow` | Class constructed when the tile opens |
| `depend` | Other **class names** that must exist first (may live in another JS file) |
| `texts` | i18n dir (`ui/texts/<lang>/strings`) |
| `icon` | `images/foo_{0}.png` with `{0}` ∈ 16, 24, 32, 48, 64, 72, 256 |
| `version` | Query string on the JS URL. Packer sets this to INFO version to bust cache |
| `grantPrivilege` | `admin` if only administrators should see the tile |

**JSLoad cycle (this package already hit it):** do **not** register `ui/bridge/*.js` as its own module that `depend`s on `SYNO.SDS.TPS.Application` while Application `depend`s on the bridge. DSM logs `loop detected` and AppLaunch dies. The packer **prepends** [`transport.js`](../spk/src/threatprevention/package/ui/bridge/transport.js) + [`dsm7.js`](../spk/src/threatprevention/package/ui/bridge/dsm7.js) + [`settings-inject.js`](../spk/src/threatprevention/package/ui/bridge/settings-inject.js) into `synoips.js` and lists Chart stubs only as [`tps-chart.js`](../spk/src/threatprevention/package/ui/tps-chart.js).

SRM-only classes official Overview `depend`s on, missing on DSM 7:

- `SYNO.SDS.Chart.LineChart`
- `SYNO.SDS.Chart.PieChart`
- `SYNO.SDS.Chart.CreateAxis`

Those are registered as a separate `type: lib` module so they exist **before** Overview constructs.

---

## 4. Desktop object model (legacy SDK)

Recovered from official TPS `Ext.define` `extend:` lines **and** DSM 7.4 `extjs-patch.bundle.js` (`Ext.define` vs `Ext.extend`).

| Class | How the host defines it | Role |
| --- | --- | --- |
| `SYNO.SDS.AppInstance` | `Ext.extend` in patch | Process; holds `appWindowName` |
| `SYNO.SDS.AppWindow` | `Ext.define` in patch | Single-page window |
| `SYNO.SDS.PageListAppWindow` | referenced from TPS; lives in patch | Multi-page window (Overview / Events / …) |
| `SYNO.SDS.ModalWindow` | `Ext.define` | Modal over the app window |
| `SYNO.SDS.AbstractWindow` / `BaseWindow` / `LegacyAppWindow` | patch | Window ancestry |
| `SYNO.SDS.Utils.TabPanel` | `Ext.extend` | Tab strip + Apply/Reset chrome |
| `SYNO.SDS.Utils.FormPanel` | `Ext.extend` | `webapi:{api,methods,version}` auto get/set |
| `SYNO.SDS.Utils.GridPanel` / `EditorGridPanel` | `Ext.extend` | DSM-styled grids |
| `SYNO.ux.GridPanel` / `FormPanel` / `TabPanel` | `ux-all.js` | Lower-level widgets the Utils classes wrap |

`PageListAppWindow` items are `{title, fn:"Class.Name"}`. `fn` is also `dsmapppage` if INFO wants Package Center to open a specific page.

Also on the host (do not need for TPS, useful if writing a new Ext app): `SYNO.SDS.Wizard.*` (`BaseWindow`, `AppWindow`, `ModalWindow`, `Step`, `WelcomeStep`, `ApplyStep`, `SummaryStep`), `SYNO.SDS.WidgetWindow`, `SYNO.SDS.MessageBoxV5`, `SYNO.SDS.ToastBox`.

`sds.bundle.js` owns desktop chrome, not windows: `SYNO.SDS.JSLoad`, `JSLoadPromise`, `JSLoader`, `AppLaunch`, `Desktop`, `StatusNotifier`, `Config`, plus helpers under `SYNO.SDS.Utils` (`GetAppIcon`, `Logout`, `Notify`, language / Punycode).

### Mixins every Ext component on the desktop may have

Official TPS never writes `/webapi/entry.cgi` for `SYNO.TPS.*`. It calls host mixins (see [official-app-surface.md](api/official-app-surface.md)). On DSM 7.4 the function bodies live in **`extjs-patch.bundle.js`** (`sendWebAPI=function`, `pollReg=function`, `downloadWebAPI=function`, `findAppWindow=function`).

| Method | Typical owner | Contract |
| --- | --- | --- |
| `sendWebAPI({api,method,version,params,callback,scope})` | `AppWindow`, **and** bare `Ext.Component` | `{success, data}` or `{success:false, error:{code}}` |
| `sendWebAPI({compound:{stopwhenerror, params:[…]}})` | Settings / Policy | `{result:[{api,method,success,data}], has_fail}` |
| `pollReg` / `pollUnreg` | same | interval seconds + `status_callback(ok, data)` |
| `pollList` | `new Ext.Component()` (SignatureUpdater) | `SYNO.API.Request.Polling.List` → `{admin: collection}` |
| `downloadWebAPI` | Backup | file download, not JSON body |
| `SYNO.API.Store` | Rule / Device / Filter grids | `api`, `method`, JsonReader `root` |
| `SYNO.API.CompoundReader` | compound responses | defined in patch |
| `SYNO.Entry.Request.request` | Notification tab | nested Core compound |
| `SYNO.SDS.AppLaunch` | Export folder | e.g. File Station `opendir` |
| `findAppWindow()` | almost every panel | owning `AppWindow` |
| `getMsgBox()` | progress / error | `Desktop.getMsgBox` or the window |

`webapi:{api,methods:{get,set},version}` on a `FormPanel` makes official Apply issue `get` then dirty `set`. Extra fields we inject on Notification **must not** join that dirty form: strip `enable_telegram` / token fields from `SYNO.TPS.Notification` `set` and call `SYNO.TPS.Settings.Telegram` ourselves. The Rule feeds tab uses `useDefaultBtn: false` so official Apply never sees it.

**Bridge rule:** if you wrap `SYNO.API.Request`, copy `.Polling`. Replacing `Request` with a bare function deletes `Polling.List` and SignatureUpdater crashes. Same for `SYNO.Entry.Request.Polling`.

---

## 5. Widget toolkit (`xtype` / `SYNO.ux`)

`ux-all.js` registers `syno_*` xtypes. Official TPS (and this bridge) should use these, not raw `Ext.form.TextField`.

### Used by official TPS or this bridge

| xtype | Class | Use |
| --- | --- | --- |
| `syno_checkbox` | `SYNO.ux.Checkbox` | Settings / Telegram enable |
| `syno_textfield` | `SYNO.ux.TextField` | Forms |
| `syno_passwordfield` | `SYNO.ux.PasswordField` (also re-defined in patch) | Bot token |
| `syno_textarea` | `SYNO.ux.TextArea` | |
| `syno_numberfield` | `SYNO.ux.NumberField` | Intervals |
| `syno_combobox` | `SYNO.ux.ComboBox` | `db_size`, ET Open/Pro |
| `syno_radio` | `SYNO.ux.Radio` | `network_security_mode` |
| `syno_displayfield` | `SYNO.ux.DisplayField` | HTML status (DSM 7 may `htmlEncode`) |
| `syno_fieldset` | `SYNO.ux.FieldSet` | Grouped Settings |
| `syno_button` / `syno_filebutton` | `SYNO.ux.Button` / `FileButton` | Actions / backup upload |
| `syno_gridpanel` | `SYNO.ux.GridPanel` | Devices / filters / feeds |
| `syno_formpanel` | `SYNO.ux.FormPanel` | Prefer `SYNO.SDS.Utils.FormPanel` for Apply chrome |
| `syno_schedulefield` | `SYNO.ux.ScheduleField` | Auto-update schedule |
| `syno_textfilter` / `syno_searchfield` | `SYNO.ux.TextFilter` / `SearchField` | Events search |
| `syno_compositefield` | `SYNO.ux.CompositeField` | Side-by-side buttons |

### Also on this NAS (unused by TPS)

`syno_datefield`, `syno_datetimefield`, `syno_datetimepickerfield`, `syno_timefield`, `syno_timepickerfield`, `syno_radiogroup`, `syno_switch`, `syno_treepanel`, `syno_tabpanel`, `syno_toolbar`, `syno_menu`, `syno_editorgrid`, `syno_paging`, `syno_pageless`, `syno_sliderfield`, `syno_singleslider`, `syno_splitbutton`, `syno_superboxselect`, `syno_colorfield`, `syno_coverpanel`, `syno_modulelist`, `syno_storage_combobox`, `syno_message_combobox`, `syno_inversefieldset`, `syno_mactextfield`, `syno_statebuttongroup`, `syno_whitequicktip`, `syno_invalidquicktip`.

Other `SYNO.ux.*` names: `EnableColumn`, `SwitchColumn`, `DateField`, `Menu`, `Toolbar`, `EditorGridPanel`, `PagingToolbar`, `TreePanel`, `Utils`.

i18n:

- `this.helper.T("section","key")` — package `ui/texts/<lang>/strings`
- `_T("common","colon")` / `_T("common","add")` / `_T("common","enabled")` — DSM core strings

Help: [`ui/helptoc.conf`](../unpacked/package/ui/helptoc.conf) + `ui/help/<lang>/`. Search keywords: [`ui/index.conf`](../unpacked/package/ui/index.conf). DSM Help Center only lists a package after `conf/resource` `indexdb.help-index` (and `app-index`) plus `pkgindexer_add` on start — see [`dsm-help.sh`](../spk/src/threatprevention/scripts/dsm-help.sh). Official SRM topics stay; pack prepends community pages `threatprevention_dsm.html` (IDS / setcap) and `threatprevention_router.html` (OpenWrt GRE or MikroTik TZSP copy). Operator copy of the router steps also ships in `target/etc/openwrt/` and `target/etc/mikrotik/`. Canonical write-up: [router-traffic-copy.md](router-traffic-copy.md).

---

## 6. Host WebAPI objects (recovered names)

Present in `sds.bundle.js` / `synowebapi.min.js`. Names only — do not reimplement.

| Name | Role |
| --- | --- |
| `SYNO.API.Request` | Ajax wrapper. **Keep `.Polling`** |
| `SYNO.API.Request.Polling` | `List` / `Register` / `Unregister` |
| `SYNO.API.RequestPromise` | Promise variant |
| `SYNO.API.Manager` / `_Manager` / `currentManager` | `queryAPI`, `requestAjaxAPI`, `getKnownAPI` |
| `SYNO.API.Info` / `InfoObject` / `GetKnownAPI` | `SYNO.API.Info` query |
| `SYNO.API.Auth` | session |
| `SYNO.API.EncodeParams` / `DecodeParams` / `EncodeURL` | param flatten |
| `SYNO.API.Errors` / `getErrorString` / `CheckServerError` | error catalog |
| `SYNO.API.Store` | Ext Store bound to a WebAPI (in patch) |
| `SYNO.API.CompoundReader` | compound `result[]` (in patch) |
| `SYNO.Entry.Request` / `Entry.Request.Polling` | `/webapi/entry.cgi` compound |
| `SYNO.Entry.SocketIo` | desktop push |

Core APIs official TPS calls (`SYNO.Core.Network`, `Notification.*`, `SystemDB`, USB list) stay on `entry.cgi`. The bridge must not send those to tpsweb. See [official-app-surface.md](api/official-app-surface.md).

---

## 7. Official TPS class tree (recovered)

`Ext.define` count in `synoips.js`: **53**. Launch path:

```
SYNO.SDS.TPS.Application          (AppInstance)
  └─ SYNO.SDS.TPS.MainWindow      (PageListAppWindow)
       ├─ Overview.Panel
       │    StatusPanel, StatisticPanel, ConcernedDevicePanel
       ├─ Event.EventPanel
       ├─ UserDefined.TabPanel    (self-defined policy)
       ├─ Statistic.TabPanel      (Map + Trends; needs Chart.*)
       ├─ Notification.TabPanel
       └─ Settings.TabPanel
            GeneralPanel, DevicePanel, NotificationPanel,
            BackupRestorePanel, LogStoragePanel
            + FeedPanel          (bridge add(); not in official JS)
```

Injection points in [`bridge/`](../spk/src/threatprevention/package/ui/bridge/) (`transport.js`, `dsm7.js`, `settings-inject.js`) — wrap official prototypes; do **not** edit `unpacked/package/ui/synoips.js`:

| Hook | Where | Why |
| --- | --- | --- |
| `injectSettingsTabs` | `Settings.TabPanel` `initComponent` / `afterrender` | `add()` Rule feeds `FormPanel` |
| `patchNotificationTelegram` | `Settings.NotificationPanel.fillConfig` | Telegram `syno_fieldset` on the official Notify tab |
| `patchGeneralSettings` | `Settings.GeneralPanel.fillConfig` | Capture source radios (`Settings.Mirror`) before Monitored Interfaces |
| `patchDisplayHtml` | `syno_displayfield` | DSM 7 html-encodes Overview HTML |
| `patchMapSeverity` / `patchGmapsKey` / `patchOsmTiles` | Map panel / `GoogleMapLoader` | DSM 7 map quirks + optional key |
| `patchLogStorage` / `patchDeviceCellClick` / `patchGmapObserver` | Storage / Overview / Map | Ext 3 vs DSM 7 Collection / MutationObserver |

---

## 8. How this package uses the SDK

| Piece | Rule |
| --- | --- |
| Official UI | Copy `unpacked/package/ui/` as-is |
| Bridge | Prepend into `synoips.js` at pack time — **not** a `ui/config` module |
| Chart stubs | Own JSLoad module `tps-chart.js` |
| Extra Settings | Runtime `TabPanel.add` + Notification `fillConfig` after official class exists |
| Extra widgets | Same `syno_*` xtypes as official forms (`syno_checkbox`, `syno_textfield`, `syno_gridpanel`, …) |
| API host | Mixins → `/webman/tps-api` → tpsweb. Core APIs stay `entry.cgi` |
| Leftover community SPA | `postinst` deletes `index.html` / `app.js` / `threatprevention.js` so the tile stays `SYNO.SDS.TPS.Application` |

Packer: [`spk/pack-spk.sh`](../spk/pack-spk.sh). Source `spk/src/threatprevention/package/ui/config` is a leftover webpack app config and is **not** what gets packed.

PoC-only WebAPIs the official JS does not know about (`Settings.Telegram`, `Settings.Feed`, `Settings.Map`, `Settings.Mirror`) are called from the bridge with the same `sendWebAPI` mixin. Contracts: [official-app-surface.md](api/official-app-surface.md).

---

## 9. Minimal ExtJS app (if you ever write one)

Host already provides `Ext` and `SYNO.SDS`. A new file `myapp.js` + `ui/config` entry:

```javascript
Ext.define("SYNO.SDS.Example.Application", {
    extend: "SYNO.SDS.AppInstance",
    appWindowName: "SYNO.SDS.Example.MainWindow"
});
Ext.define("SYNO.SDS.Example.MainWindow", {
    extend: "SYNO.SDS.AppWindow",
    constructor: function (cfg) {
        this.appInstance = cfg.appInstance;
        this.callParent([Ext.apply({
            width: 720,
            height: 480,
            resizable: true,
            layout: "fit",
            items: [{xtype: "syno_displayfield", value: "hello"}]
        }, cfg)]);
    }
});
```

```json
{
  "myapp.js": {
    "SYNO.SDS.Example.Application": {
      "type": "app",
      "appWindow": "SYNO.SDS.Example.MainWindow",
      "title": "Example",
      "icon": "images/example_{0}.png",
      "depend": ["SYNO.SDS.Example.MainWindow"]
    },
    "SYNO.SDS.Example.MainWindow": {"type": "lib", "depend": []}
  }
}
```

This PoC does **not** ship a second Application. Extra features hang off the official window.

Community samples (not Synology): [SimpleExtJSApp](https://github.com/DigitalBox98/SimpleExtJSApp), [SynoAppsDocs](https://github.com/DigitalBox98/SynoAppsDocs). Paths in those repos may still say `sds.js`.

---

## 10. Modern official SDK (Vue) — do not mix in this SPK

Synology’s current package UI path (`app.config` + `config.define` + webpack + `Vue.extend` / `<v-app-instance>`) is documented under [Launch an App](https://help.synology.com/developer-guide/synology_package/package_tgz/launch_app.html). Wizards on DSM 7.2.2+ are also Vue (`SYNO.SDS.Wizard.*` in the Ext patch is the *old* wizard).

On this NAS:

- `/usr/syno/synoman/scripts/vue/vue.min.js`
- `/usr/syno/synoman/scripts/syno-vue-components/syno-vue-components.min.js`
- `SYNO.SDS.VuePanel` in `extjs-patch.bundle.js`

Keep Threat Prevention on ExtJS + bridge.

---

## 11. Related

- Transport and `SYNO.TPS.*` envelopes: [official-app-surface.md](api/official-app-surface.md)
- Why the backend is a compatibility layer: [backend-replaceability.md](backend-replaceability.md)
- Shim hacks and how to improve them: [ootb-ui-compat-review.md](ootb-ui-compat-review.md)
- Port status: [backend-port-backlog.md](api/backend-port-backlog.md)
- Maps loader (not a WebAPI): [google-maps.md](google-maps.md)
- Deploy / `dsmappname`: [spk-deploy-and-update.md](spk-deploy-and-update.md)
