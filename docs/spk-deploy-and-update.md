# Threat Prevention SPK — deploy and update

Unsigned DSM 7 x86_64 package (`ThreatPrevention`, current `8.0.6-0009`). Native desktop UI + `tpsweb` API on port **19557** ([native-app-plan.md](native-app-plan.md)).  
SPK scripts under `spk/src/threatprevention/scripts/` are stubs except `postinst`, `start-stop-status`, and `update-rules.sh`. **Most of the work that makes capture actually run is admin-side:** DSM will not let an unsigned package declare `run-as: root` or file capabilities (`synopkg` error 319). `start-stop-status` tries `setcap` but it is a no-op when Package Center starts the unit as the package user.

Target verified: DSM 7.4.1, SA6400 (`synology_epyc7002_sa6400`), glibc 2.36.

## Paths

| What | Where |
| --- | --- |
| Install root | `/var/packages/ThreatPrevention/target` |
| Logs, pid, live rules | `/var/packages/ThreatPrevention/var/` |
| Capture iface override | `/var/packages/ThreatPrevention/etc/interface` (one line, e.g. `ovs_eth0`) |
| Start Menu UI | `/usr/syno/synoman/webman/3rdparty/ThreatPrevention` → `target/ui` |
| tpsweb API / SPA | `http://<nas>:19557/` (also unix `var/tpsweb.sock`) |
| Event DB | `/var/packages/ThreatPrevention/var/tps.db` |
| Package log | `/var/log/synopkg.log` |
| Engine log | `/var/packages/ThreatPrevention/var/log/suricata.log` |
| Alerts | `/var/packages/ThreatPrevention/var/log/eve.json` |
| Rule update log | `/var/packages/ThreatPrevention/var/log/suricata-update.log` |

Rebuild the SPK on a Mac/Linux host with Docker:

```sh
./build/spk/pack-spk.sh
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
sudo synopkg install /tmp/ThreatPrevention-x86_64-8.0.6-0009.spk
```

What `postinst` does (as the package user): unpacks the bundled ET 2021 tarball if missing, concatenates `*.rules` into `/var/packages/ThreatPrevention/var/rules/suricata.rules` so the engine has a bootstrap ruleset. It does **not** apply `setcap` and does **not** fetch current ET Open.

Install may report “started” while Suricata later dies on `AF_PACKET … Operation not permitted`. That is expected until the post-deploy cap is set.

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

Optional iface pin (then restart):

```sh
echo ovs_eth0 | sudo tee /var/packages/ThreatPrevention/etc/interface
sudo synopkg restart ThreatPrevention
```

**Start Menu tile:** `INFO` has `dsmuidir="ui"` and `dsmappname="SYNO.SDS.ThreatPrevention.Application"`. After install, **log out of DSM and back in**. The tile is admin-only. The SPA talks to `tpsweb` on port **19557** (Package Center → Open uses the same port). If the browser blocks mixed HTTP on an HTTPS DSM session, open `http://<nas>:19557/` directly.

Optional but recommended — replace the 2021 Suricata-5 ET dump with a current Suricata 8 feed (do **not** convert the old files):

```sh
sudo /var/packages/ThreatPrevention/scripts/update-rules.sh
sudo synopkg restart ThreatPrevention
```

Needs outbound HTTPS to the ET / Open Information Security Foundation index. Log: `var/log/suricata-update.log`. Success creates `var/rules/.from-suricata-update`.

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

Not a package upgrade. The bootstrap file is ET Open **for Suricata 5** (feed 9840, 2021-09). Suricata 8 rejects part of that syntax; the engine still starts. Current signatures must be pulled with `suricata-update` (ET Open is the default source). Optional extras after `update-sources`: Abuse.ch SSLBL, ET Pro (license), and other index sources — enable them with `suricata-update enable-source …` using the same `--data-dir` / `--output` as `scripts/update-rules.sh`.

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
| Installed, Start in Package Center fails / flaps | Missing `liblz4` / GLIBC 2.38 on old SPKs; or AF_PACKET denied | Use ≥ `8.0.6-0005` (vendored glibc+libs). Then `setcap` + `synopkg start`. |
| `Operation not permitted` on `ovs_eth0` | Package user, no file caps | Post-deploy `setcap` (see above). |
| `error 319 invalid package privilege content` | SPK declared `run-as: root` or `tool.capabilities` | Unsigned packages cannot; keep `conf/privilege` as `run-as: package`. |
| No Start Menu icon | Missing `dsmuidir` (fixed in `0006`) or DSM cache | Install ≥ `0006`, log out/in. |
| `fanout not supported` | `cluster_flow` on this kernel | Harmless if `Engine started` with `W: 1`. Current yaml omits fanout. |
| Stale pidfile abort | Previous crash left `var/suricata.pid` | Current start script removes it if the pid is dead. |

Do not set `LD_LIBRARY_PATH` to `target/lib` in a root shell: that Ubuntu `libc.so.6` will break DSM tools (`tail`, etc.) in the same environment. The ELF interpreter is already patched to `target/lib/ld-linux-x86-64.so.2`.
