# x64 DSM migration plan (Suricata 8)

**Target:** Synology DSM 7 x86_64 NAS (not SRM Cypress)  
**Engine:** Suricata **8.0.6** (7.x is EOL as of 2026-07)  
**Date:** 2026-09-07

## Verdict

The Cypress SPK cannot be retargeted. All 17 ELF objects are stripped aarch64; there is no source for `synosuricata`, `libsynotps`, `synotpsd`, or `SYNO.TPS.*.so`. DSM is a different OS (systemd, no SRM bridge NFQUEUE hook, no Qualcomm ECM NSS).

A new package around **stock Suricata 8.0.6** is the viable path. Inline IPS only if the NAS forwards traffic; otherwise IDS on selected NICs.

## Engine choice

| Item | Decision |
| --- | --- |
| Version | 8.0.6 (https://www.openinfosecfoundation.org/download/suricata-8.0.6.tar.gz) |
| Capture | `af-packet` (IDS) and `--enable-nfqueue` (IPS) |
| Alerts | eve-log JSON (unix socket or file). No Synology `synodb` |
| Portable CPU | `--disable-gccmarch-native` so the binary runs on geminilake / v1000 / denverton / r1000 |
| Hyperscan | Enable on x86_64 when `libhs` is available (ARM Cypress could not use it) |
| Rules | ET Open via `suricata-update` (Suricata 8 tree), not the bundled 2021 `suricata-5.0` tarball as the live feed |

Build tree: `build/suricata-8/` (Docker `linux/amd64`). Install prefix: `/opt/tps-suricata`.

## Portable vs rewrite

**Portable:** ET rules as a seed, [`unpacked/package/etc/rules/signature.conf`](unpacked/package/etc/rules/signature.conf), classification, PostgreSQL schema, threshold SIDs.

**Rewrite:** engine, ingest daemon, WebAPI, UI, systemd units, nftables/iptables, AppArmor. Do not ship Synology binaries or `ui/synoips.js`.

**Drop:** USB swap / `core_pattern` hacks, `synonettool`, `synowifid`, ECM debugfs, Python 2 rotators, Upstart.

## DSM packaging (after the linux/amd64 binary exists)

1. Wrap `/opt/tps-suricata` in pkgscripts-ng for `x86_64` (or per-CPU arches).
2. systemd `suricata.service`; eve socket under `/volume1/@appdata/ThreatPrevention`.
3. Default IDS; IPS only when `ip_forward=1`.
4. SQLite (or NAS pgsql) for events; Python 3 rotation.
5. New DSM 7 WebAPI + UI.

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

Capture: NFQueue **yes**, AF_PACKET **yes**. GCC march native **no**. Hyperscan **yes**.

**glibc caveat:** this binary was built on Ubuntu 24.04 (glibc 2.39). DSM 7 NAS images typically have an older glibc. Before installing on a NAS, rebuild with Synology `pkgscripts-ng` or an older distro matching the NAS libc (often Ubuntu 20.04 / Debian 11). Confirm with `ldd` on the target.

Runtime `.so` list is in `build/suricata-8/out/tps-suricata/ldd.txt` (`libnetfilter_queue`, `libhs`, `libpcap`, `libpcre2`, `libyaml`, `libjansson`, …).
