---
name: dsm-package-debug
description: >-
  Debug Threat Prevention on a DSM 7 NAS (tpsweb, Suricata start, Telegram
  save, setcap, noexec /tmp). Use when install fails, the package will not
  start, Settings Apply wipes files, or logs on the NAS are needed.
---

# DSM package debug

## Where to look

| What | Path |
| --- | --- |
| synopkg | `/var/log/synopkg.log` |
| Suricata | `/var/packages/ThreatPrevention/var/log/suricata.log` |
| tpsweb | `/var/packages/ThreatPrevention/var/log/tpsweb.log` |
| engine pin | `/var/packages/ThreatPrevention/var/engine.status` |
| telegram | `/var/packages/ThreatPrevention/etc/telegram.conf` (600; do not print TOKEN) |
| iface | `/var/packages/ThreatPrevention/etc/interface` |

## Start failed (272 / start-stop-status ret 1)

1. `tmpfs /tmp noexec` — pack/install tests must use `-f` not `-x` on the ELF.
2. Missing `TPSWEB_PID` / empty redirect in `start-stop-status`.
3. `liblz4` + setcap: `$ORIGIN` RUNPATH is ignored in AT_SECURE. Need `/var/lib/tps` → `target/lib` and rewritten RUNPATH.
4. Leftover root-owned Suricata holding `ovs_eth0` — `kill -9` that pid, then `synopkg start`.
5. Trace: `sh -x /var/packages/ThreatPrevention/scripts/start-stop-status start`.

## Telegram save empties conf

Empty token/chat on `SYNO.TPS.Settings.Telegram.set` must not overwrite stored secrets. Password fields need `getRawValue`. Do not print bot tokens in chat.

## UI not updating

Bridge is inlined in `target/ui/synoips.js`. Log out of DSM or bump SPK version (branch/tag) so `?v=` changes.
