# Threat Prevention 1.3.3-0926 — Package Review

**Artifact:** `artifact/ThreatPrevention-cypress-1.3.3-0926.spk`  
**Unpacked tree:** `unpacked/spk/` (SPK) and `unpacked/package/` (`package.tgz`)  
**Review date:** 2026-08-31  
**Scope:** Static unpack of the Synology Router Manager (SRM) package: metadata, lifecycle scripts, configuration, WebAPI surface, AppArmor, Suricata engine, signature feed, and UI. Binaries are stripped aarch64 ELF; no dynamic runtime test was performed.

---

## 1. Verdict

Threat Prevention is Synology’s inline IPS for SRM routers. This Cypress build is a coherent, vendor-signed successor to the older Intrusion Prevention package: a patched Suricata 6.0.4 engine in NFQUEUE inline mode, Emerging Threats (ET) Open/Pro signatures, a PostgreSQL event store, an ExtJS DSM/SRM UI, and a set of `SYNO.TPS.*` WebAPI modules.

It is **not** a third-party or unofficial package. It **is** dated in engine and ruleset generation, overly privileged in AppArmor, and carries several lifecycle and default-policy issues that matter on a perimeter device.

**Recommendation for Cypress (RT6600ax):** acceptable to install from Synology Package Center on SRM 5.2, with the caveats in §8. Do not treat the bundled ET Open snapshot as current. Prefer automatic signature updates, keep USB/eMMC storage stable, and treat AppArmor + WebAPI as the main local-attack surface if an admin session is compromised.

---

## 2. Package identity

| Field | Value |
| --- | --- |
| Package name | `ThreatPrevention` |
| Version | `1.3.3-0926` |
| Display name | Threat Prevention |
| Maintainer | Synology Inc. |
| Architecture | `cypress` (RT6600ax; ET Pro enabled for this model) |
| Minimum firmware | SRM `5.2-9283` (`toolkit_version` 9283) |
| Build time | `2026-05-12 13:17:36` (from `INFO` `create_time`) |
| SPK size | 6.9 MiB (POSIX tar) |
| Extracted payload | ~18.9 MiB (`extractsize=18896`) |
| DSM/SRM app id | `SYNO.SDS.TPS.Application` |
| UI directory | `ui` |
| Topology | `router` and `bridge` (`support_topology`) |
| Start dependency | PostgreSQL (`start_dep_services=pgsql`) |
| Silent upgrade | yes |
| Predecessor | `IntrusionPrevention` (uninstalled from `postinst`) |

Help text states Threat Prevention is **not available on MR2200ac**, requires **Wireless Router** mode (not AP-only), and **allocates space on attached storage**. The start banner warns operators not to unplug that storage and to keep at least 3 GB free.

ET Pro model gate (`etc/rules/support_etpro_model.conf`):

```
synology_cypress_rt6600ax=yes
```

All other listed platforms (`rt1900ac`, `rt2600ac`, `mr2200ac`, `wrx560`) are `no` in this Cypress SPK.

---

## 3. How the SPK is laid out

An SPK is a GNU tar. This one contains:

```
INFO
PACKAGE_ICON.PNG
PACKAGE_ICON_256.PNG
WIZARD_UIFILES/          uninstall + upgrade wizards (per-locale)
conf/resource            package resource hooks (CSP, syslog, UDC)
package.tgz              payload (~6.7 MiB compressed)
scripts/                 pre/post inst, upgrade, start-stop-status
syno_signature.asc       Synology PGP signature
```

`package.tgz` expands to:

| Path | Role | Size (approx.) |
| --- | --- | --- |
| `bin/synosuricata` | Suricata 6.0.4 IPS engine (`Syno-Suricata-Main`) | 5.3 MiB |
| `bin/ionice` | Bundled ionice for log rotation niceness | 16 KiB |
| `lib/` | `libsynotps`, libhtp 0.5.39, libmagic, libyaml | 1.5 MiB |
| `tool/` | `synotpsd`, `synotpstool`, `synoipsuserdatacollector` | 84 KiB |
| `webapi/` | Eight `SYNO.TPS.*.so` CGI modules + `SYNO.TPS.lib` | 296 KiB |
| `etc/` | Suricata template, ET rules tarball, sensor/signature defaults | 5.9 MiB |
| `ui/` | ExtJS app, help, i18n, icons | 1.7 MiB |
| `indexdb/` | Prebuilt DSM help/app search indexes | 3.1 MiB |
| `schema/` | PostgreSQL DDL (`synotps`) | 12 KiB |
| `scripts/` | Rotate, reload, net-event hooks | 24 KiB |
| `upstart/` | `synosuricata`, `synotpsd`, reset-db, event trigger | 16 KiB |
| `apparmor/` | `pkg_ThreatPrevention` CGI profiles | 16 KiB |
| `udev/` | WAN port add/remove reload for RT1900ac leftover | 4 KiB |

All 17 ELF objects are **aarch64 PIE**, dynamically linked, **stripped** (`no section header`).

---

## 4. Architecture

```
                    WAN / LAN bridges
                           |
                    iptables NFQUEUE 557
                           |
                    synosuricata (IPS, nfq mode=repeat)
                      |        |
                 synodb     syno-loading
                 output     (per-IP packet counts)
                      |        |
                      v        v
                 PostgreSQL db "synotps"
                      ^
                      |
                 synotpsd  ---- notifications, MAC/name map, sensor restart
                      |
                 synotpstool  (CLI: sensor, rules, export, reset)
                      |
                 SYNO.TPS.* WebAPI  <----  ExtJS UI (admin only)
                      |
                 wget --> rules.emergingthreats.net / emergingthreatspro.com
```

### 4.1 Packet path (IPS)

Upstart `synosuricata.conf` starts the engine as:

```
synosuricata -c .../suricata.yaml --pidfile /var/run/synosuricata.pid -q 557 -l <pgsql-volume>/synosuricata --init-ioidle
```

Help text is explicit: **IDS is no longer available**; only IPS is used. The upstart job still has a leftover `MODE=ids` branch that would pass `--nflog`, but the product path is NFQUEUE.

NFQUEUE settings in `suricata.yaml.template`:

- `mode: repeat` with mark/mask `0x100000` (non-terminal verdict so the rest of the iptables policy still runs)
- bypass mark `0x2000000` (fast-path once a flow is judged)
- `fail-open: @_syno_fail_open` — substituted from sensor config
- Default `network_security_mode=availability` in `sensor.conf`

**Availability mode + fail-open** means: if Suricata cannot keep up, the kernel accepts packets rather than dropping them. That is a deliberate latency/availability trade-off on a consumer router. The UI exposes a “network security” dialog to change this.

A procfs switch enables the Synology bridge netfilter hook:

```
/proc/sys/net/bridge/syno-bridge-nf-cond-call-netfilter-threat-prevention
```

`start-stop-status` writes `off` there on stop. Sensor WebAPI AppArmor also allows write access to Qualcomm ECM NSS debugfs stop nodes (`/sys/kernel/debug/ecm/...`) so acceleration can be disabled when inspection is on.

Default sensor policy:

```
enable_sensor=yes
enable_prevention=yes
default_detect=yes
network_security_mode=availability
```

High-risk ET classes default to **drop** (`etc/rules/signature.conf`): trojan, user/admin privilege, shellcode, web-application-attack, inappropriate-content. `policy-violation`, `misc-activity`, `not-suspicious`, and `others` are disabled by default.

### 4.2 Event store

Database name: `synotps`. Schema is a Synology-extended Barnyard2/Snort layout:

- `event`, `iphdr`, `tcphdr`, `udphdr`, `icmphdr`, `data` — alerts and packet headers
- `signature`, `sig_class`, `modified_signature` — compiled rules
- `policy_class`, `policy_signature`, `policy_filter` — operator overrides
- `device` — MAC → name, detect flag, loading score
- `loading` — per-IP packet counts for the “busy device” UI

Suricata writes via a custom `synodb` output (not eve.json; EVE is disabled). `synotpsd` polls new events, fills MAC/name, and sends notifications.

Log rotation (`synotps_rotate.py`) runs from crontab at minute 2 of every hour. It deletes oldest events until DB size is under the user cap (default 500 MB; UI allows 500 MB / 1 GB / 2 GB) and then `VACUUM FULL`. Scripts talk to PostgreSQL as user `postgres`.

### 4.3 Signature pipeline

Bundled feed: `etc/rules/emerging.rules.tar.gz` (2.9 MiB), ET Open **version 9840**, Suricata **5.0** rule syntax.

| Metric | Count |
| --- | --- |
| Files in tarball | 59 |
| Lines in `*.rules` | 68,197 |
| `alert` rules | 23,028 |
| `drop` rules in tarball | 0 |

Drops are applied later by Synology when compiling signatures from class defaults and policies into `.../suricata/signatures`. One Synology custom pass rule (`syno-custom-events.rules`) exempts Google Voice STUN traffic to `74.125.39.90`.

Full inventory of every bundled signature (33,723 parsed, 23,029 active), class-policy mapping, and the CSV catalog: [ThreatPrevention-1.3.3-0926-bundled-rules.md](ThreatPrevention-1.3.3-0926-bundled-rules.md).

Live updates (`libsynotps` / `RulesetUpdater`):

- ET Open: `https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz`
- ET Pro: `https://rules.emergingthreatspro.com/<oinkcode>/suricata-5.0/etpro.rules.tar.gz`

Fetch tool: `/usr/bin/wget`. UI string `update_status_etpro_code_error_desc` = “Invalid ET Pro code”. Cypress is the only model in this SPK with ET Pro enabled.

**Engine vs ruleset mismatch:** the binary is Suricata **6.0.4**; downloads still use the **suricata-5.0** tree. That is compatible for most ET rules but skips 6.x keywords and does not pick up 6.0/7.0 feed folders.

### 4.4 Daemons and hooks

| Unit | Start | Purpose |
| --- | --- | --- |
| `synosuricata.conf` | via `synotpstool --sensor -e` | IPS engine; USB swap priority tweak; overwrites `kernel.core_pattern`; copies `vm.min_free_kbytes=50000` sysctl |
| `synotpsd.conf` | same | Event daemon; respawn 5 times / 10 s |
| `synotps-reset-database.conf` | task | `synotpstool -R` |
| `synotps_event_trigger.conf` | `synowifid.dhcp.*` | `touch /tmp/.synotps_restart_sensor` |

Network events `ipv4_change`, `gateway_change`, `topology_change` symlink `tps_restart_sensor.sh`. Udev rule `50-tps-reload.rules` is a leftover for RT1900ac `roboswitch` ports 0/1.

---

## 5. WebAPI and UI

`SYNO.TPS.lib` is installed to `/usr/syno/synoman/webapi/SYNO.TPS.lib` on start.

All APIs: `authLevel: 1`, `allowUser: admin.local | admin.domain | admin.ldap`. No ordinary user access. `grantByDefault: true` on **every** method, including mutating ones.

| API | Methods | Demo |
| --- | --- | --- |
| `SYNO.TPS.Backup` | backup, restore | **true** (incl. restore upload) |
| `SYNO.TPS.Device` | list, set | true |
| `SYNO.TPS.Event` (+ Map, Statistic, Offset, ExportFolder) | get, list, list_status | true |
| `SYNO.TPS.Notification` / `.Filter` | get/list, set | set is `allowDemo: false` |
| `SYNO.TPS.Sensor` / `.Variables` | get, set | set is `allowDemo: false` |
| `SYNO.TPS.Settings.Update` | start_update, start_check, status | start_update `allowDemo: false` |
| `SYNO.TPS.Settings.Update.Schedule/Source` | get, set | set `allowDemo: false` |
| `SYNO.TPS.Settings.Storage` | get, set, clear_log | mutating `allowDemo: false` |
| `SYNO.TPS.Signature` / `.Rule` / `.Classification` | list | Classification `allowDemo: false` |
| `SYNO.TPS.Signature.Policy` | add, get, set, update, list, delete | **all true**, including delete |
| `SYNO.TPS.Statistic.Device` / `.Trends` | list/get | true |

UI is ExtJS (`synoips.js`, ~192 KiB). Screens: Overview, Events, Self-Defined Policy, Statistics (Google Maps / OpenStreetMap), Settings (general, device, notification, backup/restore `.dss`, log storage).

Maps load `https://maps.google.com/maps/api/js?libraries=places`. Marker clusterer still references **HTTP** `google-maps-utility-library-v3.googlecode.com`. CSP (`etc/csp/csp-rule`) allows `https://*.googleapis.com`, `https://*.gstatic.com`, `https://*.google.com`, and `http://*.googlecode.com` for images.

---

## 6. Lifecycle

### Install (`postinst`)

1. Unpack ET rules into `target/etc/rules/suricata/` if missing; keep prior USB-resident rules if present.
2. Create `synotps` DB and apply schema (unless upgrade).
3. Copy default `sensor.conf`, `notification_filter.conf`, `signature.conf`, `map.conf`, `misc.conf`.
4. Register `synotps-database.json` with SRM data-update project list.
5. Force notification tags to `mail,sms,mobile`.
6. Migrate configs from `IntrusionPrevention` and `synopkg uninstall IntrusionPrevention &` (background).
7. Unconditional `ALTER TABLE` / `CREATE TABLE loading` for pre-0741 schema (errors on already-migrated DBs are ignored by the shell).
8. `synotpstool --mkdir-for-export-events`.

### Start / stop

Start requires postgres, creates DB if needed, installs upstart jobs, crontab, syslog-ng pattern, logrotate, UDC config, udev, net-event hooks, WebAPI symlink, then `synotpstool --sensor -e`.

Stop disables the sensor, kills leftover tools, removes hooks. **`status)` is empty** — package status always reports success (`exit 0`).

### Upgrade / uninstall wizards

- Upgrade: optional CSV export of events to USB (clears events on success). Silent upgrade uses `enable_auto_export_events_during_postupgrade` (default `no`).
- Uninstall: optional truncate/drop of DB and configs. Wizards are localized.

---

## 7. Telemetry

`etc/user.data.conf/ThreatPrevention.config` registers `/var/packages/ThreatPrevention/target/tool/synoipsuserdatacollector`.

Symbols in that binary: `collectLanCounts`, `collectSensorConfig`, `collectKeywordInfo`, `collectWizardSettings`, `collectRules`, `collectEventStatistics`, `collectUdcCounts`, `collectDeviceInfo`, `collectUpdaterConfig`, `collectEvents`.

This is Synology’s standard User Data Collection hook. Whether it actually uploads depends on the router-wide UDC consent. The collector is small (8 KiB) and delegates to `libsynotps`.

---

## 8. Findings

Severity is for a **perimeter router** running this package as shipped.

### High

| ID | Finding | Where |
| --- | --- | --- |
| H1 | **Suricata 6.0.4 (2022) with 5.0 ET feeds.** Multiple Suricata CVEs were issued after 6.0.4. Engine is stripped; no Hyperscan; no libnet. Rules download path is still `suricata-5.0`. | `bin/synosuricata`, `libsynotps` URL strings |
| H2 | **AppArmor is both too wide and incomplete.** Sensor/Settings.Update allow `ThreatPrevention/**` rwk. Backup allows `/volume*/@tmp/*` and `/volume*/*/@tmp/*`. Signature.Rule and Sensor can write `dhcpd.conf` / `dhcpd.info`. Sensor may `ix` `initctl`, `ifconfig`, `brctl`, `ip`, `tar`, `pppoe-status`, and write ECM NSS stop nodes and IPv6 disable sysctls. Several live APIs have **no** profile (`Device`, `Settings.Storage`, `Statistic.*`). Stale profile for missing `SYNO.TPS.Overview.so`. | `apparmor/pkg_ThreatPrevention` vs `SYNO.TPS.lib` |
| H3 | **Default fail-open / availability.** Sensor default is `network_security_mode=availability` and NFQUEUE `fail-open` is templated. Under load, inspection is skipped rather than blocking. Combined with H1, a DoS on Suricata becomes a bypass. | `sensor.conf`, `suricata.yaml.template` |

### Medium

| ID | Finding | Where |
| --- | --- | --- |
| M1 | **CGI runs as a highly privileged admin WebAPI.** `grantByDefault: true` on restore, policy add/delete, sensor set, signature update. `allowDemo: true` on backup/restore and all policy mutations. Compromise of an admin session (or demo mode) is full IPS control. | `webapi/SYNO.TPS.lib` |
| M2 | **PostgreSQL as superuser `postgres`** from shell/Python, with some SQL built by concatenation (`synotps_rotate.py` `DELETE ... WHERE cid<`). Values are numeric from the DB, but the pattern is brittle. `postinst` issues schema ALTERs on every install. | `scripts/*.py`, `postinst` |
| M3 | **Global `kernel.core_pattern` rewritten** for the Suricata process lifetime to dump cores onto the pgsql volume. A crash writes potentially sensitive packet memory to attached storage. USB swap is `swapoff`/`swapon` in pre-start. | `upstart/synosuricata.conf` |
| M4 | **Python 2** (`#!/usr/bin/python`, `print` without parentheses in `synotps_storage_info.py`). Fine on current SRM 5.2 if Python 2 remains; a liability for any later userspace. | `package/scripts/*.py` |
| M5 | **Hardcoded third-party pass rule** for Google Voice IP `74.125.39.90`. Stale anycast/IP changes become either false positives or an unnecessary bypass. | `etc/rules/syno-custom-events.rules` |
| M6 | **User-data collector** gathers events, devices, rules, wizard and sensor config. Depends on global UDC opt-in, but the surface exists. | `tool/synoipsuserdatacollector` |
| M7 | **HTTP mixed content** for map clusterer images (`googlecode.com`) plus CSP `img-src http://*.googlecode.com`. | `ui/synoips_no_check.js`, `etc/csp/csp-rule` |

### Low / quality

| ID | Finding | Where |
| --- | --- | --- |
| L1 | `start-stop-status` `status` case is empty; DSM/SRM cannot detect a dead IPS. | `scripts/start-stop-status` |
| L2 | `postinst` uses `local` outside a function (`upgrade` branch) — not POSIX `sh`. | `scripts/postinst` |
| L3 | `tps_reload.sh` calls `hook_handler` with no argument; `ips_utils.sh` then logs “unknown option”. WAN add/remove on roboswitch may not restart the sensor. | `scripts/tps_reload.sh` |
| L4 | `conf/resource` syslog paths (`etc/syslog-ng/syslog-ng.conf`, `logrotate.conf`) do not match shipped files (`synotps.conf`, `etc/logrotate.d/synotps`). Start script installs the real files by hand. | `conf/resource` vs `etc/` |
| L5 | `synopkg uninstall IntrusionPrevention &` races with the rest of `postinst`. | `scripts/postinst` |
| L6 | `synotpsd` respawn limit `5 10` is aggressive vs Suricata `5 600`. A DB blip can thrash the event daemon. | `upstart/synotpsd.conf` |
| L7 | `vm.min_free_kbytes=50000` applied system-wide while Suricata runs — can increase reclaim pressure on 512 MB–1 GB routers. | `etc/sysctlconf/synotps.conf` |
| L8 | Uninstall wizard typo: “erased **afer** uninstallation.” | `WIZARD_UIFILES/uninstall_uifile` |
| L9 | `display/map.conf` still lists `rt1900ac` / `mr2200ac` map zoom values; Cypress/RT6600ax not listed. Statistics map defaults may be wrong for this hardware. | `etc/display/map.conf` |

---

## 9. What this package does well

- Admin-only WebAPI (`authLevel` 1); not exposed to local users.
- Inline IPS with NFQUEUE repeat mode so Synology’s own firewall still applies.
- Class-based default drops for high-severity ET categories, with operator overrides and per-device skip.
- Event schema stores packet headers and payload for investigation; GeoIP + map UI.
- Upgrade path can export events to USB so schema migrations do not stall.
- Signed SPK (`syno_signature.asc`); silent upgrade and AA profile / topology flags match SRM packaging norms.
- Crontab rotation + logrotate + syslog-ng isolation of `synotps` logs.
- Migration from Intrusion Prevention instead of leaving two IPS stacks.

---

## 10. Operator notes (Cypress / RT6600ax)

1. Confirm SRM is in **Wireless Router** mode and attached storage has **≥ 3 GB** free. Do not yank the USB/eMMC volume while the package runs.
2. After install, open Threat Prevention → Settings and set **network security** to the stricter mode if you prefer fail-closed under load.
3. Enable **automatic signature updates** (and ET Pro oinkcode if licensed). The bundled ET Open snapshot is version **9840** and is not a live feed.
4. Review Self-Defined Policy and device skip-list; new devices can be excluded via “Skip filtering packets for new devices.”
5. Watch `/var/log/synotps.log` and PostgreSQL size. Rotation keeps a floor of 1000 events.
6. Treat backup `.dss` files as sensitive (policies + possibly rule state).

---

## 11. Suggested vendor follow-ups

1. Rebase `synosuricata` to a maintained Suricata 7.x (or current 6.0.x LTS) and switch the updater URLs to the matching ET tree.
2. Split AppArmor profiles to least privilege; drop `dhcpd.conf` write, ECM debugfs, and `/**` on package etc from CGI. Add profiles for Device, Storage, Statistic. Remove Overview.
3. Implement a real `status` in `start-stop-status` (pid of `Syno-Suricata-Main` + `synotpsd` + postgres).
4. Replace Python 2 helpers with `/usr/bin/python3` or C in `synotpstool`.
5. Stop rewriting global `core_pattern`; use a dedicated `coredump.conf` or disable dumps in production.
6. Fix `tps_reload.sh` to call `hook_handler restart_sensor`.
7. Default `network_security_mode` to security/fail-closed on high-end Cypress, or prompt in the install wizard.
8. Remove or parameterize the Google Voice pass SID; update map CSP to HTTPS-only.

---

## 12. Unpack commands (reproducible)

```sh
mkdir -p unpacked/spk unpacked/package
tar -xf artifact/ThreatPrevention-cypress-1.3.3-0926.spk -C unpacked/spk
tar -xzf unpacked/spk/package.tgz -C unpacked/package
```

Source of truth for this document: those trees plus `strings` on stripped ELF files. No package was installed on a router during this review.
