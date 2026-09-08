---
name: pack-and-deploy
description: >-
  Pack the unsigned DSM 7 ThreatPrevention SPK and install it on the NAS.
  Use when the user asks to build, pack, deploy, synopkg install, or upgrade
  the package.
---

# Pack and deploy

## Pack (this repo)

```sh
python3 spk/src/threatprevention/python/test_compat.py
./build.sh --from-release
```

On macOS, `build.sh --from-release` unpacks the GitHub engine tarball (no Docker compile). Output is `artifact/ThreatPrevention-x86_64-<branch-or-tag>.spk`. SPK version is git branch (or tag if detached), not `VERSION`.

Need a native engine rebuild: `./build.sh` (Docker on macOS).

## Deploy

NAS is typically `he11kern@192.168.1.130`. DSM `scp` SFTP often fails; pipe the SPK:

```sh
ssh user@nas 'cat > /tmp/ThreatPrevention.spk' < artifact/*.spk
ssh user@nas sudo synopkg install /tmp/ThreatPrevention.spk
ssh user@nas sudo setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep /var/packages/ThreatPrevention/target/bin/suricata
ssh user@nas sudo synopkg restart ThreatPrevention
```

Confirm `synopkg status`, `getcap`, `engine.status`, and pids `suricata` / `tpsweb` / `ingest`.

Do not put passwords or tokens in commands committed to the repo. After UI changes, user must log out of DSM so `synoips.js?v=<pkgver>` reloads.
