# Threat Prevention SPK — deploy and update

Unsigned DSM 7 x86_64 research PoC. Official ExtJS app with a `tpsweb` backend (bridge prepended into `synoips.js` at pack time; Chart stubs in `tps-chart.js`). Not a product. See [backend-replaceability.md](backend-replaceability.md).

SPK scripts that matter: `postinst`, `start-stop-status`, `update-rules.sh`, `install-nginx-api.sh`. DSM will not let an unsigned package declare `run-as: root` or file capabilities (`synopkg` error 319). `start-stop-status` may try `setcap`; it is a no-op when Package Center starts the unit as the package user.

**Verified:** DSM 7.4.1, SA6400 (`synology_epyc7002_sa6400`), glibc 2.36.

## Versions

| What | Where | Example |
| --- | --- | --- |
| Suricata engine | [`VERSION`](../VERSION) `SURICATA_VERSION` | `8.0.6` |
| SPK / `INFO` / `synoips.js?v=` | git **branch**, or **tag** if HEAD is detached ([`spk/pkg-version.sh`](../spk/pkg-version.sh)) | `main`, `v0.2.0` |
| Override | env `TPS_PKG_VERSION` | |

`VERSION` does not store a package number. Artifact name: `artifact/ThreatPrevention-x86_64-<PKG_VERSION>.spk`.

Package Center upgrade requires the new `INFO` version to be **greater** than the installed one. Branch names (`main`) do not increase. Pin `TPS_PKG_VERSION` (or install from a newer tag) when you need a strictly increasing upgrade.

## Paths

| What | Where |
| --- | --- |
| Install root | `/var/packages/ThreatPrevention/target` |
| Logs, pid, live rules | `/var/packages/ThreatPrevention/var/` |
| Capture iface override | `/var/packages/ThreatPrevention/etc/interface` (one line). Router copy pins this to `tps0`. |
| Traffic copy (gretap / TZSP) | `/var/packages/ThreatPrevention/etc/mirror.conf` — [router-traffic-copy.md](router-traffic-copy.md) |
| Hardware acceleration | `/var/packages/ThreatPrevention/etc/accel.conf` — [hw-acceleration.md](hw-acceleration.md) |
| Telegram | `/var/packages/ThreatPrevention/etc/telegram.conf` (`0600`; do not print `TOKEN`) |
| Rule feeds | `/var/packages/ThreatPrevention/etc/feeds.json` |
| Feed URL catalog | `target/etc/rule-sources.json`; override with `etc/rule-sources.json` |
| Start Menu UI | `/usr/syno/synoman/webman/3rdparty/ThreatPrevention` → `target/ui` |
| Browser API | same-origin `/webman/tps-api` (nginx → tpsweb). Do not open `:19557` from the desktop. |
| tpsweb (loopback) | `http://127.0.0.1:19557/` and unix `var/tpsweb.sock` |
| Event DB | `/var/packages/ThreatPrevention/var/tps.db` |
| Package log | `/var/log/synopkg.log` |
| Engine log | `/var/packages/ThreatPrevention/var/log/suricata.log` |
| Alerts | `/var/packages/ThreatPrevention/var/log/eve.json` |
| Rule update log | `/var/packages/ThreatPrevention/var/log/suricata-update.log` |
| Secure RUNPATH | `/var/lib/tps` → `target/lib` (file caps ignore `$ORIGIN`) |

On the NAS, prefer **`install.sh`** from [the root README](../README.md): latest installer from `main`, latest engine from GitHub `/releases/latest/download/`, official UI at pack time, then `synopkg install` + `setcap`.

Developer pack (no Docker): `./build.sh --from-release`. Native compile: `./build.sh`.

```sh
./build.sh --from-release
# artifact/ThreatPrevention-x86_64-<PKG_VERSION>.spk
```

---

## First install

### Pre-deploy

1. DSM **7.0+**, Intel/AMD (`arch=x86_64`). This binary will not run on ARM NAS.
2. **Package Center → Settings → General → Trust Level:** allow unsigned packages.
3. Prefer `install.sh`. If you copy an SPK by hand, DSM `scp` SFTP often fails — pipe with `ssh … 'cat > /tmp/….spk'`.
4. Capture defaults to **`ovs_eth0`** on SA6400 (`eth0` is an OVS slave and is collapsed in Settings). Change later in the app (Settings → General) or by writing `etc/interface`.
5. Expect **no official Synology signature**. Community rebuild, not SRM Threat Prevention.

### Deploy

**`install.sh`** packs, installs, `setcap`s, and restarts. That is the supported path.

Manual: Package Center → Manual Install, or:

```sh
sudo synopkg install /tmp/ThreatPrevention-x86_64-<PKG_VERSION>.spk
sudo /usr/bin/setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep \
  /var/packages/ThreatPrevention/target/bin/suricata
sudo synopkg restart ThreatPrevention
```

What `postinst` does (as the package user): unpacks the bundled ET 2021 tarball if missing, concatenates `*.rules` into `/var/packages/ThreatPrevention/var/rules/suricata.rules`. It cannot apply `setcap` (unsigned, synopkg 319) and does **not** fetch current ET Open. It prints the exact admin command.

Install may report “started” while Suricata later dies on `AF_PACKET … Operation not permitted`. That is expected until `setcap`. Overview shows a banner when `Sensor.get` reports `capture_capable: false`.

### After install (from the app)

Open **Threat Prevention** from Package Center (**Open**) or the Start Menu. Log out of DSM only if the tile is missing or `synoips.js?v=` still shows `1.3.3-0926` (dead cache; it should be the current `INFO` version).

| | |
| --- | --- |
| **Capture** | Already `ovs_eth0` on SA6400. Change under Settings → General if needed. |
| **Current rules** | Settings → **Update** → **Update Now** (ET Open). Extra sources: Settings → **Rule Feeds**. First download can take several minutes; the engine reloads when it finishes. |
| **setcap** | Already done by `install.sh`. If Overview shows the capabilities banner, run the printed command once — the app cannot apply file caps. |

Confirm:

```sh
getcap /var/packages/ThreatPrevention/target/bin/suricata
# … cap_net_admin,cap_net_raw,cap_ipc_lock+ep

ps -o user,pid,cmd -p "$(cat /var/packages/ThreatPrevention/var/suricata.pid)"
grep -E "Engine started|af-packet|Operation not permitted" \
  /var/packages/ThreatPrevention/var/log/suricata.log | tail
```

Optional iface pin (then restart). **Do not pin `ovs_eth0` while router copy is enabled** — start will recreate `tps0` and rewrite `etc/interface`.

```sh
echo ovs_eth0 | sudo tee /var/packages/ThreatPrevention/etc/interface
sudo synopkg restart ThreatPrevention
```

**Start Menu:** one app, `SYNO.SDS.TPS.Application`. Remove any leftover community `SYNO.SDS.ThreatPrevention.Application` pin. The bridge POSTs `/webman/tps-api`, then same-origin `/webman/3rdparty/ThreatPrevention/api`. It does not fall back to `http://host:19557`.

Feed URLs live in `target/etc/rule-sources.json`. Override with `/var/packages/ThreatPrevention/etc/rule-sources.json`; `{code}` is replaced with the ET Pro license. CLI fallback (same script as Update Now): `sudo /var/packages/ThreatPrevention/scripts/update-rules.sh`. Success creates `var/rules/.from-suricata-update`.

### Router traffic copy (LAN↔WAN IDS)

The NAS is not the gateway. LAN listen only sees NAS traffic. To inspect client LAN↔WAN flows, the gateway copies FORWARD frames onto `tps0` — OpenWrt via GRE tap, MikroTik via TZSP (UDP 37008). Full steps: [router-traffic-copy.md](router-traffic-copy.md).

On the NAS after install, the same text is in DSM Help (**Router traffic copy**). Copy `target/etc/openwrt/` or `target/etc/mikrotik/` to the router; do **not** let the SPK rewrite the gateway.

```sh
# OpenWrt
NAS_IP=192.168.1.130 sh apply-tps-mirror.sh
# MikroTik (after editing NasIp/WanIf/LanIf)
/import file-name=apply-tps-mirror.rsc
```

Then Settings → General → **Receive a traffic copy from the router**, pick OpenWrt or MikroTik, Apply, then `synopkg restart` (tap is created at package start). `setcap` must already be on `bin/suricata`.

### Hardware acceleration (Hyperscan)

Default policy is **Intel Hyperscan** (`mpm-algo: hs`). Settings radios choose Hyperscan vs portable `ac`/`bmh`. DPDK and NIC flow offload are notes, not controls. [hw-acceleration.md](hw-acceleration.md).

```sh
/var/packages/ThreatPrevention/target/bin/suricata --build-info | grep -i hyperscan
cat /var/packages/ThreatPrevention/etc/accel.conf
```

---

## Package upgrade (new SPK)

`preupgrade` / `postupgrade` are no-ops. DSM still runs **stop → replace `target/` → postinst → start**. The new `bin/suricata` has **no** file capabilities.

### Pre-upgrade

1. Live rules from `suricata-update` live under **var** (`var/rules/.from-suricata-update`). They survive `target/` replace. Do not delete `var/` unless you want the bundled 2021 tarball again.
2. Copy the new SPK. `INFO` version must be greater than the installed one (see [Versions](#versions)).
3. Plan a capture gap: stop/start is several seconds, plus ~15–20 s of rule load.

### Upgrade

```sh
sudo synopkg install /tmp/ThreatPrevention-x86_64-<PKG_VERSION>.spk
sudo setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep \
  /var/packages/ThreatPrevention/target/bin/suricata
sudo synopkg start ThreatPrevention
```

`install.sh` does install + setcap + restart. If the desktop still shows old chrome, log out of DSM (or confirm `synoips.js?v=<PKG_VERSION>`).

Latest ET Open: Settings → **Update** → **Update Now**.

---

## Rules-only update (no new SPK)

The bootstrap file is ET Open **for Suricata 5** (feed 9840, 2021-09). Suricata 8 rejects part of that syntax; the engine still starts. Pull current signatures from the app: Settings → **Update** → **Update Now** (ET Open by default). Settings → **Rule Feeds** lists free OISF-index sources **disabled**; enable, Apply, then Update Now. ET Pro stays on General (license code).

CLI fallback:

```sh
sudo /var/packages/ThreatPrevention/scripts/update-rules.sh
```

To revert to the bundled tarball, remove `var/rules/suricata.rules` and `var/rules/.from-suricata-update`, then reinstall (or re-run `postinst` logic). `postinst` concatenates extracted `*.rules` only if `suricata.rules` is missing.

---

## Uninstall

`preuninst` / `postuninst` do not wipe `var/`. DSM usually keeps `@appdata/ThreatPrevention` until you remove it by hand.

```sh
sudo synopkg uninstall ThreatPrevention
# optional: sudo rm -rf /volume1/@appdata/ThreatPrevention
```

---

## Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Installed, Start in Package Center fails / flaps | Missing `liblz4` (setcap + `$ORIGIN` RUNPATH ignored); AF_PACKET denied; root-owned `etc/interface` (`0600`) | Confirm `/var/lib/tps` → `target/lib` and `getcap`. Then `setcap` + `synopkg start`. If `interface` is `root:root`: `sudo chown ThreatPrevention:ThreatPrevention /var/packages/ThreatPrevention/etc/interface && sudo chmod 644 …`. |
| `Operation not permitted` on `ovs_eth0` | Package user, no file caps | Post-deploy `setcap` (see above). |
| `error 319 invalid package privilege content` | SPK declared `run-as: root` or `tool.capabilities` | Unsigned packages cannot; keep `conf/privilege` as `run-as: package`. |
| No Start Menu icon | DSM desktop cache | Package Center **Open**, or log out/in. One tile: `SYNO.SDS.TPS.Application`. |
| `fanout not supported` | `cluster_flow` on this kernel | Harmless if `Engine started` with `W: 1`. Current yaml omits fanout. |
| Stale pidfile abort | Previous crash left `var/suricata.pid` | Current start script removes it if the pid is dead. |
| `Cannot read properties of undefined (reading 'LineChart')` | DSM 7 has no SRM `SYNO.SDS.Chart.*`; stale `synoips.js?v=1.3.3-0926` | Hard-refresh or log out. JSLoad should fetch `tps-chart.js` and `synoips.js?v=<PKG_VERSION>`. |
| `POST …/ThreatPrevention/api` or `/webman/tps-api` 404 | nginx snippet missing or not reloaded | `sudo nginx -s reload`. Confirm: `curl -sS -d 'api=SYNO.TPS.Sensor&method=get&version=1' http://127.0.0.1:19557/api`. |
| `NoApiKeys` / `mapsjs/gen_204` `ERR_BLOCKED_BY_CLIENT` | Official Maps loader has no key; ad blocker | Ignore, or own key + GeoIP: [google-maps.md](google-maps.md). |
| `tps0` missing after enabling router copy | Tap is created only at package start; no `CAP_NET_ADMIN` | `setcap` then `synopkg restart`. [router-traffic-copy.md](router-traffic-copy.md). |
| `tps0` UP but only NAS traffic in Events | DSM Firewall blocking GRE/TZSP, OpenWrt WAN not L3, or MikroTik fasttrack | Allow proto 47 or UDP 37008 from the router LAN IP; set WAN ifname; disable fasttrack. |
| Engine fails after enabling Hyperscan | Binary has no `libhs` | `accel.conf` falls back to `ac`/`bmh`. Confirm `--build-info` Hyperscan yes. [hw-acceleration.md](hw-acceleration.md). |
| Telegram Apply empties `telegram.conf` | Password field sent `""` | Leave the token blank to keep the stored value; second Apply must not truncate `TOKEN=`. |

Do not set `LD_LIBRARY_PATH` to `target/lib` in a root shell: that Ubuntu `libc.so.6` will break DSM tools in the same environment. The ELF interpreter is already patched to `target/lib/ld-linux-x86-64.so.2`. File caps need RUNPATH `/var/lib/tps`, not `$ORIGIN`.
