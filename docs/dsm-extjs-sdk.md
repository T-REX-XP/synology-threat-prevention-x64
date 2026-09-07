# DSM ExtJS package-app SDK (recovered)

**Date:** 2026-09-07  
**Scope:** How Synology Start Menu apps are loaded, what APIs official Threat Prevention uses, and what this PoC may touch. Not a Synology-licensed SDK dump.

There is **no public ExtJS SDK tarball** from Synology. The current [Developer Guide](https://help.synology.com/developer-guide/synology_package/package_tgz/launch_app.html) documents a **Vue** “DSM UI Framework.” SRM Threat Prevention (`synoips.js`) is the older path: **Ext JS 3.4** plus Synology `SYNO.SDS.*` / `SYNO.ux.*` wrappers that already live on every DSM 7 NAS.

This note recovers that older contract from:

| Source | What we take |
| --- | --- |
| Official [launch an app](https://help.synology.com/developer-guide/synology_package/package_tgz/launch_app.html), [desktop application](https://help.synology.com/developer-guide/integrate_dsm/desktopapp.html), [application config](https://help.synology.com/developer-guide/integrate_dsm/config.html) | `dsmuidir`, `dsmappname`, `ui/config` |
| [`unpacked/package/ui/config`](../unpacked/package/ui/config) + `synoips.js` class list | JSLoad graph, mixins, xtypes |
| NAS runtime (community map) | Where Ext / SDS / UX actually load |
| This package’s packer / bridge | What breaks JSLoad and how we extend Settings |

Do **not** copy `sds.js`, `ux-all.js`, `ext-all.js`, or official `synoips.js` into a new app. Those files are Synology (and Sencha) copyright. Use them **in the browser on DSM** as the host already shipped.

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

---

## 2. Files DSM actually loads (on the NAS)

Recovered from [SimpleExtJSApp wiki](https://github.com/DigitalBox98/SimpleExtJSApp/wiki/Synology-DSM-info) and DSM 7 layout. Paths are on the **NAS**, not in this git tree.

| Role | Path |
| --- | --- |
| Ext JS 3.4 | `/usr/syno/synoman/scripts/ext-3.4/ext-all.js` |
| Synology UX widgets | `/usr/syno/synoman/scripts/ext-3.4/ux/ux-all.js` |
| Desktop / JSLoad / AppInstance | `/usr/syno/synoman/synoSDSjslib/sds.js` |
| Package UI symlink | `/usr/syno/synoman/webman/3rdparty/ThreatPrevention` → `target/ui` |
| Sencha 3.4 API (GPL, not Synology) | https://cdn.sencha.com/ext/gpl/3.4.1.1/docs/ |

`INFO` must set:

```
dsmuidir="ui"
dsmappname="SYNO.SDS.TPS.Application"
```

`dsmappname` is what Package Center **Open** launches ([optional INFO fields](https://help.synology.com/developer-guide/synology_package/INFO_optional_fields.html)).

---

## 3. `ui/config` — the JSLoad SDK

JSON map: **js filename → class name → metadata**. DSM’s loader (`JSLoad`) walks `depend` and `type`.

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

**JSLoad cycle (this package already hit it):** do **not** register `tps-bridge.js` as its own module that `depend`s on `SYNO.SDS.TPS.Application` while Application `depend`s on the bridge. DSM logs `loop detected` and AppLaunch dies. The packer **prepends** [`tps-bridge.js`](../spk/src/threatprevention/package/ui/tps-bridge.js) into `synoips.js` and lists Chart stubs only as [`tps-chart.js`](../spk/src/threatprevention/package/ui/tps-chart.js).

SRM-only classes official Overview `depend`s on, missing on DSM 7:

- `SYNO.SDS.Chart.LineChart`
- `SYNO.SDS.Chart.PieChart`
- `SYNO.SDS.Chart.CreateAxis`

Those are registered as a separate `type: lib` module so they exist **before** Overview constructs.

---

## 4. Desktop object model (legacy SDK)

Recovered from official `Ext.define` `extend:` lines.

| Class | Extends | Role |
| --- | --- | --- |
| `SYNO.SDS.TPS.Application` | `SYNO.SDS.AppInstance` | Process; holds `appWindowName` |
| `SYNO.SDS.TPS.MainWindow` | `SYNO.SDS.PageListAppWindow` | Multi-page window (Overview / Events / …) |
| Settings / Policy / Statistics tabs | `SYNO.SDS.Utils.TabPanel` | Tab strip + Apply/Reset chrome |
| Most forms | `SYNO.SDS.Utils.FormPanel` | `webapi:{api,methods,version}` auto get/set |
| Grids | `SYNO.ux.GridPanel` / `EditorGridPanel` | DSM-styled Ext grid |
| Dialogs | `SYNO.SDS.ModalWindow` | Modal over the app window |

`PageListAppWindow` items are `{title, fn:"Class.Name"}`. `fn` is also `dsmapppage` if INFO wants Package Center to open a specific page.

### Mixins every Ext component on the desktop may have

Official TPS never writes `/webapi/entry.cgi` for `SYNO.TPS.*`. It calls host mixins (see [official-app-surface.md](api/official-app-surface.md)):

| Method | Typical owner | Contract |
| --- | --- | --- |
| `sendWebAPI({api,method,version,params,callback,scope})` | `AppWindow`, **and** bare `Ext.Component` | `{success, data}` or `{success:false, error:{code}}` |
| `sendWebAPI({compound:{stopwhenerror, params:[…]}})` | Settings / Policy | `{result:[{api,method,success,data}], has_fail}` |
| `pollReg` / `pollUnreg` | same | interval seconds + `status_callback(ok, data)` |
| `pollList` | `new Ext.Component()` (SignatureUpdater) | `SYNO.API.Request.Polling.List` → `{admin: collection}` |
| `downloadWebAPI` | Backup | file download, not JSON body |
| `SYNO.API.Store` | Rule / Device / Filter grids | `api`, `method`, JsonReader `root` |
| `SYNO.Entry.Request.request` | Notification tab | nested Core compound |
| `SYNO.SDS.AppLaunch` | Export folder | e.g. File Station `opendir` |
| `findAppWindow()` | almost every panel | owning `AppWindow` |
| `getMsgBox()` | progress / error | desktop message box |

`webapi:{api,methods:{get,set},version}` on a `FormPanel` makes official Apply issue `get` then dirty `set`. Extra tabs we inject **must not** join that dirty form; they call `SYNO.TPS.Settings.Telegram` / `Feed` themselves.

**Bridge rule:** if you wrap `SYNO.API.Request`, copy `.Polling`. Replacing `Request` with a bare function deletes `Polling.List` and SignatureUpdater crashes.

---

## 5. Widget toolkit (`xtype` / `SYNO.ux`)

Host widgets (from `ux-all.js`) used by official TPS:

| xtype | Class | Use |
| --- | --- | --- |
| `syno_checkbox` | | Settings enable flags |
| `syno_textfield` / `syno_textarea` / `syno_numberfield` | | Forms |
| `syno_combobox` | `SYNO.ux.ComboBox` | `db_size`, ET Open/Pro |
| `syno_radio` | | `network_security_mode` |
| `syno_displayfield` | `SYNO.ux.DisplayField` | HTML status (DSM 7 may `htmlEncode`) |
| `syno_fieldset` | | Grouped Settings |
| `syno_button` / `syno_filebutton` | `SYNO.ux.Button` | Actions / backup upload |
| `syno_gridpanel` | `SYNO.ux.GridPanel` | Devices / filters |
| `syno_schedulefield` | | Auto-update schedule |
| `syno_textfilter` | `SYNO.ux.SearchField` | Events search |
| `syno_compositefield` | | Side-by-side fields |

Other `SYNO.ux.*` names referenced: `EnableColumn`, `DateField`, `Menu`, `Toolbar`, `EditorGridPanel`, `Utils`.

i18n:

- `this.helper.T("section","key")` — package `ui/texts/<lang>/strings`
- `_T("common","colon")` — DSM core strings

Help: [`ui/helptoc.conf`](../unpacked/package/ui/helptoc.conf) + `ui/help/<lang>/`. Search keywords: [`ui/index.conf`](../unpacked/package/ui/index.conf).

---

## 6. Official TPS class tree (recovered)

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
```

`Settings.TabPanel` is the injection point for PoC-only **Telegram** and **Rule feeds** tabs ([`tps-bridge.js` `injectSettingsTabs`](../spk/src/threatprevention/package/ui/tps-bridge.js)): wrap `initComponent` / `afterrender` and `add()` extra `FormPanel`s. Do not edit `unpacked/package/ui/synoips.js`.

---

## 7. How this package uses the SDK

| Piece | Rule |
| --- | --- |
| Official UI | Copy `unpacked/package/ui/` as-is |
| Bridge | Prepend into `synoips.js` at pack time — **not** a `ui/config` module |
| Chart stubs | Own JSLoad module `tps-chart.js` |
| Extra Settings | Runtime `TabPanel.add` after official class exists |
| API host | Mixins → `/webman/tps-api` → tpsweb. Core APIs stay `entry.cgi` |
| Leftover community SPA | `postinst` deletes `index.html` / `app.js` / `threatprevention.js` so the tile stays `SYNO.SDS.TPS.Application` |

Packer: [`spk/pack-spk.sh`](../spk/pack-spk.sh). Source `spk/src/threatprevention/package/ui/config` is a leftover webpack app config and is **not** what gets packed.

---

## 8. Minimal ExtJS app (if you ever write one)

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

Community samples (not Synology): [SimpleExtJSApp](https://github.com/DigitalBox98/SimpleExtJSApp), [SynoAppsDocs](https://github.com/DigitalBox98/SynoAppsDocs).

---

## 9. Modern official SDK (Vue) — do not mix in this SPK

Synology’s current package UI path (`app.config` + `config.define` + webpack + `Vue.extend` / `<v-app-instance>`) is documented under [Launch an App](https://help.synology.com/developer-guide/synology_package/package_tgz/launch_app.html). Wizards on DSM 7.2.2 are also Vue.

Mixing Vue `v-app-window` and Ext `PageListAppWindow` in one `ui/config` is unsupported. Keep Threat Prevention on ExtJS + bridge.

---

## 10. Related

- Transport and `SYNO.TPS.*` envelopes: [official-app-surface.md](api/official-app-surface.md)
- Why the backend is a compatibility layer: [backend-replaceability.md](backend-replaceability.md)
- Port status: [backend-port-backlog.md](api/backend-port-backlog.md)
- Maps loader (not a WebAPI): [google-maps.md](google-maps.md)
- Deploy / `dsmappname`: [spk-deploy-and-update.md](spk-deploy-and-update.md)
