# Threat Prevention SPK — deploy and update

Unsigned DSM 7 x86_64 research PoC (`ThreatPrevention`, current `8.0.6-0062`). Official ExtJS app with a custom `tpsweb` backend (bridge inlined into `synoips.js` at pack time; Chart stubs in `tps-chart.js`). Not a product. See [backend-replaceability.md](backend-replaceability.md).  
SPK scripts under `spk/src/threatprevention/scripts/` are stubs except `postinst`, `start-stop-status`, and `update-rules.sh`. **Most of the work that makes capture actually run is admin-side:** DSM will not let an unsigned package declare `run-as: root` or file capabilities (`synopkg` error 319). `start-stop-status` tries `setcap` but it is a no-op when Package Center starts the unit as the package user.

Target verified: DSM 7.4.1, SA6400 (`synology_epyc7002_sa6400`), glibc 2.36.

## Paths

| What | Where |
| --- | --- |
| Install root | `/var/packages/ThreatPrevention/target` |
| Logs, pid, live rules | `/var/packages/ThreatPrevention/var/` |
| Capture iface override | `/var/packages/ThreatPrevention/etc/interface` (one line). When router copy is on, this is `tps0`. |
| Traffic copy (gretap / TZSP) | `/var/packages/ThreatPrevention/etc/mirror.conf` — see [router-traffic-copy.md](router-traffic-copy.md) |
| Hardware acceleration | `/var/packages/ThreatPrevention/etc/accel.conf` — Hyperscan default on; see [hw-acceleration.md](hw-acceleration.md) |
| Start Menu UI | `/usr/syno/synoman/webman/3rdparty/ThreatPrevention` → `target/ui` |
| tpsweb API / SPA | `http://<nas>:19557/` (also unix `var/tpsweb.sock`) |
| Event DB | `/var/packages/ThreatPrevention/var/tps.db` |
| Package log | `/var/log/synopkg.log` |
| Engine log | `/var/packages/ThreatPrevention/var/log/suricata.log` |
| Alerts | `/var/packages/ThreatPrevention/var/log/eve.json` |
| Rule update log | `/var/packages/ThreatPrevention/var/log/suricata-update.log` |

Rebuild the SPK on a Mac/Linux host with Docker:

```sh
./spk/pack-spk.sh
# artifact/ThreatPrevention-x86_64-8.0.6-NNNN.spk
```

---

## First install

### Pre-deploy

1. DSM **7.0+**, Intel/AMD (`arch=x86_64`). This binary will not run on ARM NAS.
2. **Package Center → Settings → General → Trust Level:** allow any publisher / unsigned packages.
3. Copy the SPK to the NAS (`scp -O` on DSM; modern SFTP-only `scp` often fails).
4. Know the LAN iface. On SA6400, **`ovs_eth0` is the LAN bridge**; `eth0` is an OVS slave and is the wrong capture device. Override if needed *after* install by writing `etc/interface`.
5. Expect **no official Synology signature**. This is a community rebuild, not SRM Threat Prevention.

### Deploy

Package Center → Manual Install, or:

```sh
sudo synopkg install /tmp/ThreatPrevention-x86_64-8.0.6-0010.spk
```

What `postinst` does (as the package user): unpacks the bundled ET 2021 tarball if missing, concatenates `*.rules` into `/var/packages/ThreatPrevention/var/rules/suricata.rules` so the engine has a bootstrap ruleset. It cannot apply `setcap` (unsigned packages, synopkg 319) and does **not** fetch current ET Open. It **does** print the exact admin command to stderr:

```
sudo /usr/bin/setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep /var/packages/ThreatPrevention/target/bin/suricata
sudo synopkg restart ThreatPrevention
```

Install may report “started” while Suricata later dies on `AF_PACKET … Operation not permitted`. That is expected until the post-deploy cap is set. Overview also shows a banner when `Sensor.get` reports `capture_capable: false`.

### Post-deploy (required)

SSH as an administrator and apply raw-socket capabilities on the **new** ELF (DSM replaces `bin/suricata` on every install/upgrade, so caps never persist from the previous binary):

```sh
sudo setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep \
  /var/packages/ThreatPrevention/target/bin/suricata
sudo synopkg start ThreatPrevention
sudo synopkg status ThreatPrevention
```

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

### Router traffic copy (LAN↔WAN IDS)

The NAS is not the gateway. LAN listen only sees NAS traffic. To inspect client LAN↔WAN flows, the gateway copies FORWARD frames onto `tps0` — OpenWrt via GRE tap, MikroTik via TZSP (UDP 37008). Full steps: [router-traffic-copy.md](router-traffic-copy.md).

On the NAS after install, the same text is in DSM Help (**Router traffic copy**). Copy `target/etc/openwrt/` or `target/etc/mikrotik/` to the router; do **not** let the SPK rewrite the gateway.

```sh
# OpenWrt
NAS_IP=192.168.1.130 sh apply-tps-mirror.sh
# MikroTik (after editing NasIp/WanIf/LanIf)
/import file-name=apply-tps-mirror.rsc
```

Then Settings → General → **Receive a traffic copy from the router**, pick OpenWrt or MikroTik, Apply, `setcap`, `synopkg restart`.

### Hardware acceleration (Hyperscan)

Default policy is **Intel Hyperscan** for signature matching (`mpm-algo: hs`). Settings radios choose Hyperscan vs portable `ac`/`bmh`. DPDK and NIC flow offload are not wired (notes, not checkboxes). Full steps: [hw-acceleration.md](hw-acceleration.md). After install, confirm:

```sh
/var/packages/ThreatPrevention/target/bin/suricata --build-info | grep -i hyperscan
cat /var/packages/ThreatPrevention/etc/accel.conf
```

**Start Menu tile:** one app, `SYNO.SDS.TPS.Application`. After install, **log out of DSM and back in** and remove any leftover community `SYNO.SDS.ThreatPrevention.Application` pin. The bridge calls same-origin `/webman/tps-api` (nginx → tpsweb `:19557`). After UI/`config` changes, confirm the script URL is `synoips.js?v=8.0.6-0062` or newer — `?v=1.3.3-0926` is a stale cache.

Optional but recommended — replace the 2021 Suricata-5 ET dump with a current Suricata 8 feed (do **not** convert the old files):

```sh
sudo /var/packages/ThreatPrevention/scripts/update-rules.sh
sudo synopkg restart ThreatPrevention
```

Needs outbound HTTPS to the hosts in `target/etc/rule-sources.json` (ET Open/Pro URLs and the Rule Feeds catalog). Override by copying that file to `/var/packages/ThreatPrevention/etc/rule-sources.json`; `{code}` is replaced with the ET Pro license. Log: `var/log/suricata-update.log`. Success creates `var/rules/.from-suricata-update`.

---

## Package upgrade (new SPK)

`preupgrade` / `postupgrade` are no-ops. DSM still runs **stop → replace `target/` → postinst → start**.

### Pre-upgrade

1. Note whether live rules already came from `suricata-update` (`test -f /var/packages/ThreatPrevention/var/rules/.from-suricata-update`). That file and `var/rules/suricata.rules` live under **var**, so they survive `target/` replace. Do not delete `var/` unless you want to fall back to the bundled 2021 tarball.
2. Copy the new SPK to the NAS. Version in `INFO` must be **greater** than the installed one (`8.0.6-0006` beats `8.0.6-0005`).
3. Plan a capture gap: stop/start is several seconds, plus ~15–20 s of rule load.

### Upgrade

```sh
sudo synopkg install /tmp/ThreatPrevention-x86_64-8.0.6-NNNN.spk
```

or Package Center → the newer SPK.

### Post-upgrade (required)

The new `bin/suricata` has **no** file capabilities. Repeat:

```sh
sudo setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep \
  /var/packages/ThreatPrevention/target/bin/suricata
sudo synopkg start ThreatPrevention
```

If the UI `config` or icons changed, log out of DSM and back in.

If you want the latest ET Open on this engine version:

```sh
sudo /var/packages/ThreatPrevention/scripts/update-rules.sh
sudo synopkg restart ThreatPrevention
```

---

## Rules-only update (no new SPK)

Not a package upgrade. The bootstrap file is ET Open **for Suricata 5** (feed 9840, 2021-09). Suricata 8 rejects part of that syntax; the engine still starts. Current signatures must be pulled with `suricata-update` (ET Open is the default source). Settings → **Rule Feeds** lists free OISF-index sources (Abuse.ch, Traffic ID, …) **disabled**; enable what you want there, then Update Now. ET Pro stays on General (license code).

```sh
sudo /var/packages/ThreatPrevention/scripts/update-rules.sh
sudo synopkg restart ThreatPrevention
```

To revert to the bundled tarball, remove `var/rules/suricata.rules` and `var/rules/.from-suricata-update`, then run `postinst` logic (or reinstall); `postinst` will concatenate the extracted `*.rules` again only if `suricata.rules` is missing.

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
| Installed, Start in Package Center fails / flaps | Missing `liblz4` / GLIBC 2.38 on old SPKs; AF_PACKET denied; or root-owned `etc/interface` (`0600`) so the package user cannot read the iface pin | Use ≥ `8.0.6-0023`. `start-stop-status` ignores an unreadable pin and treats tpsweb as started. Then `setcap` + `synopkg start`. If a leftover `interface` file is still `root:root`, `sudo chown ThreatPrevention:ThreatPrevention /var/packages/ThreatPrevention/etc/interface && sudo chmod 644 /var/packages/ThreatPrevention/etc/interface`. |
| `Operation not permitted` on `ovs_eth0` | Package user, no file caps | Post-deploy `setcap` (see above). |
| `error 319 invalid package privilege content` | SPK declared `run-as: root` or `tool.capabilities` | Unsigned packages cannot; keep `conf/privilege` as `run-as: package`. |
| No Start Menu icon | Missing `dsmuidir` (fixed in `0006`) or DSM cache | Install ≥ `0006`, log out/in. |
| `fanout not supported` | `cluster_flow` on this kernel | Harmless if `Engine started` with `W: 1`. Current yaml omits fanout. |
| Stale pidfile abort | Previous crash left `var/suricata.pid` | Current start script removes it if the pid is dead. |
| `Cannot read properties of undefined (reading 'LineChart')` | DSM 7 has no SRM `SYNO.SDS.Chart.*`; or browser still has `synoips.js?v=1.3.3-0926` | Install ≥ `0021`, log out/in, hard-refresh. JSLoad should fetch `tps-chart.js` and `synoips.js?v=8.0.6-0021`. |
| `POST …/ThreatPrevention/api` or `/webman/tps-api` 404 | nginx rewrote the POST to `/` and tpsweb served missing `index.html` (≤0019); or nginx not reloaded | Install ≥ `0021`. Then `sudo nginx -s reload`. Confirm: `curl -sS -d 'api=SYNO.TPS.Sensor&method=get&version=1' http://127.0.0.1:19557/api`. |
| `NoApiKeys` / `mapsjs/gen_204` `ERR_BLOCKED_BY_CLIENT` | Official Maps loader has no key; ad blocker drops Google’s `gen_204` probe | Ignore. Not tpsweb. No demo key. Own key + GeoIP: [google-maps.md](google-maps.md). |
| `tps0` missing after enabling router copy | Tap is created only at package start; no `CAP_NET_ADMIN` | `setcap` then `synopkg restart`. [router-traffic-copy.md](router-traffic-copy.md). |
| `tps0` UP but only NAS traffic in Events | DSM Firewall blocking GRE/TZSP, OpenWrt WAN not L3, or MikroTik fasttrack | Allow proto 47 or UDP 37008 from the router LAN IP; set WAN ifname; disable fasttrack. |
| Engine fails after enabling Hyperscan | Binary has no `libhs` | `accel.conf` falls back to `ac`/`bmh`. Confirm `--build-info` Hyperscan yes. [hw-acceleration.md](hw-acceleration.md). |

Do not set `LD_LIBRARY_PATH` to `target/lib` in a root shell: that Ubuntu `libc.so.6` will break DSM tools (`tail`, etc.) in the same environment. The ELF interpreter is already patched to `target/lib/ld-linux-x86-64.so.2`.
