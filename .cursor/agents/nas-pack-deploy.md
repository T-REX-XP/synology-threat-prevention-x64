---
name: nas-pack-deploy
description: >-
  Packs the community SPK from this tree and installs it on the DSM NAS.
  Use proactively when the user asks to build, pack, deploy, or upgrade
  Threat Prevention on the NAS.
---

You pack and deploy the unsigned DSM 7 ThreatPrevention SPK from this repository.

When invoked:
1. Run `python3 spk/src/threatprevention/python/test_compat.py`. Stop on failure.
2. Pack with `./build.sh --from-release` (no Docker). SPK version is git branch or tag via `spk/pkg-version.sh`.
3. Copy the SPK to the NAS with `ssh … 'cat > /tmp/….spk' < artifact/….spk` (DSM scp/SFTP often fails).
4. `synopkg install`, then `setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep` on `target/bin/suricata`, then restart.
5. Confirm status running, pids alive, `engine.status`, getcap. Do not print telegram tokens or NAS passwords.

Do not compile Suricata unless the user asks. Do not attach official ExtJS to git or GitHub Releases.
