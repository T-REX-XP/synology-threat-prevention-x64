# x64 DSM migration plan (Suricata 8)

**Target:** Synology DSM 7 x86_64 NAS (not SRM Cypress)  
**Engine:** Suricata **8.0.6** (7.x is EOL as of 2026-07)  
**Date:** 2026-09-07

## Verdict

The Cypress SPK cannot be retargeted. All 17 ELF objects are stripped aarch64; there is no source for `synosuricata`, `libsynotps`, `synotpsd`, or `SYNO.TPS.*.so`. DSM is a different OS (systemd, no SRM bridge NFQUEUE hook, no Qualcomm ECM NSS).

A new package around **stock Suricata 8.0.6** is the viable path. Inline IPS only if the NAS forwards traffic; otherwise IDS on selected NICs.

## What shipped (this tree)

The plan below is the 2026-09-07 research note. The package that exists today:

- Unsigned DSM 7 SPK (codecs-style tar, not pkgscripts-ng). SPK version = git branch or tag.
- Official ExtJS window + `tpsweb` compatibility layer — **not** a native Vue SPA. See [native-app-plan.md](native-app-plan.md).
- AF_PACKET IDS only. NFQUEUE is compiled into the engine binary but not wired.
- glibc: vendor Ubuntu libs; RUNPATH `/var/lib/tps` under `setcap` (not `$ORIGIN`).
- Rules: Settings → Update → Update Now (`suricata-update` / ET Open). Bundled 2021 tarball is bootstrap only.

Operator path: [spk-deploy-and-update.md](spk-deploy-and-update.md).

## Engine choice

| Item | Decision |
| --- | --- |
| Version | 8.0.6 (https://www.openinfosecfoundation.org/download/suricata-8.0.6.tar.gz) |
| Capture | `af-packet` (IDS) and `--enable-nfqueue` (IPS) |
| Alerts | eve-log JSON (unix socket or file). No Synology `synodb` |
| Portable CPU | `--disable-gccmarch-native` so the binary runs on geminilake / v1000 / denverton / r1000 |
| Hyperscan | **Default on** for this x86_64 build (`libhs`). Settings → Hardware acceleration. DPDK / NIC offload not wired. [hw-acceleration.md](hw-acceleration.md) |
| Rules | ET Open via `suricata-update` (Suricata 8 tree), not the bundled 2021 `suricata-5.0` tarball as the live feed |

Build tree: `build/suricata-8/` (Docker `linux/amd64`). Install prefix: `/opt/tps-suricata`.

## Portable vs rewrite

**Portable:** ET rules as a seed, [`unpacked/package/etc/rules/signature.conf`](unpacked/package/etc/rules/signature.conf), classification, PostgreSQL schema, threshold SIDs.

**Rewrite:** engine, ingest daemon, WebAPI, UI, systemd units, nftables/iptables, AppArmor. Do not ship Synology binaries or `ui/synoips.js`.

**Drop:** USB swap / `core_pattern` hacks, `synonettool`, `synowifid`, ECM debugfs, Python 2 rotators, Upstart.

## DSM packaging (after the linux/amd64 binary exists)

Original plan (not how this tree packs):

1. Wrap `/opt/tps-suricata` in pkgscripts-ng for `x86_64` (or per-CPU arches).
2. systemd `suricata.service`; eve socket under `/volume1/@appdata/ThreatPrevention`.
3. Default IDS; IPS only when `ip_forward=1`.
4. SQLite (or NAS pgsql) for events; Python 3 rotation.
5. New DSM 7 WebAPI + UI.

What actually shipped: codecs-style unsigned SPK (`spk/pack-spk.sh`), `start-stop-status` (not systemd), SQLite + eve ingest, `tpsweb` + official ExtJS bridge. See [What shipped](#what-shipped-this-tree).

## This repo’s first build

```sh
cd build/suricata-8
./build.sh
```

**Status (2026-09-07):** succeeded.

| Item | Value |
| --- | --- |
| Version | Suricata 8.0.6 RELEASE |
| Host | `x86_64-pc-linux-gnu` (Docker `linux/amd64`, gcc 13.3) |
| Binary | ELF x86-64 PIE, dynamically linked |
| Features | NFQ, AF_PACKET, Hyperscan, PCRE JIT, JA3/JA4, Unix socket, `suricata-update` |
| Prefix | `/opt/tps-suricata` |
| Artifact | [`artifact/suricata-8.0.6-linux-amd64.tar.gz`](../artifact/suricata-8.0.6-linux-amd64.tar.gz) (42 MiB) |
| Unpacked | `build/suricata-8/out/tps-suricata/` (`suricata` 108 MiB, not stripped) |

Capture: NFQueue **yes**, AF_PACKET **yes**. GCC march native **no**. Hyperscan **yes** (package default `mpm-algo: hs`).

**glibc:** Ubuntu 24.04 build vs DSM 2.36 is handled by vendoring libs in the SPK, not by rebuilding with pkgscripts-ng. Confirm `ldd` on the NAS only if you are debugging a missing `.so`. Under `setcap`, RUNPATH must be `/var/lib/tps` → `target/lib`.

Runtime `.so` list is in `build/suricata-8/out/tps-suricata/ldd.txt` (`libnetfilter_queue`, `libhs`, `libpcap`, `libpcre2`, `libyaml`, `libjansson`, …).
