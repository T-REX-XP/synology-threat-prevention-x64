# SPK repack evaluation (codecs method)

**Sources:** [synology_codecs/README.md](/Users/t-rex-xp/Documents/synology_codecs/README.md), [synology_codecs/build.sh](/Users/t-rex-xp/Documents/synology_codecs/build.sh)  
**Original:** `ThreatPrevention-cypress-1.3.3-0926.spk` (SRM 5.2, aarch64)  
**New engine:** Suricata 8.0.6 linux/amd64 (`build/suricata-8/out/`)

## What codecs taught us

Codecs does **not** use Synology `pkgscripts-ng`. It builds an unsigned DSM 7 SPK as a plain tar:

```
package.tgz
INFO
PACKAGE_ICON.PNG
PACKAGE_ICON_256.PNG
scripts/
conf/privilege
```

Assembly (from `build.sh`):

```sh
tar czf staging/package.tgz -C staging/package .
tar cpf out/Name-arch-ver.spk package.tgz INFO PACKAGE_ICON*.PNG scripts conf
```

INFO tricks that matter for DSM 7:

| Field | Codecs | Why |
| --- | --- | --- |
| `os_min_ver=7.0-40000` | DSM 7, not SRM `firmware=5.2` | Package Center / synopkg accept it |
| `arch=x86_64` | one SPK for all Intel/AMD | Cypress used `arch=cypress` (router SoC) |
| `version` | git branch or tag (`spk/pkg-version.sh`); override `TPS_PKG_VERSION` | Codecs used `99.0.0-9999` to beat an official package. This tree has no DSM official. |
| `silent_install/upgrade=yes` | no wizard | original TPS had wizards; skip for v1 |
| `maintainer=community` | unsigned | do not claim Synology Inc. |
| `conf/privilege` `run-as: package` | install without code signing | DSM 7 blocks unsigned root packages |

Codecs also decrypts official SPKs and patches `libsynoame-license.so`. **That pattern is not used here.** Threat Prevention’s closed aarch64 libs cannot be retargeted; we replace the engine with stock Suricata instead of patching Synology binaries.

## What can be reused from the original SPK

| Keep | Drop |
| --- | --- |
| ET Open tarball, `signature.conf`, classification, thresholds, custom pass SID 1 | `bin/synosuricata`, `libsynotps`, `synotpsd`, all `SYNO.TPS.*.so` (aarch64) |
| Package icons; official UI for **research PoC only** (downloaded at pack time) | aarch64 `SYNO.TPS.*.so`, `synosuricata`, `libsynotps` |
| Policy semantics | Upstart, USB swap, `core_pattern`, ECM/NSS AppArmor |
| | `support_topology=router bridge`, `start_dep_services=pgsql` |

## What this first SPK is (and is not)

**Start Menu / official app:** packs official ExtJS + a Suricata compatibility layer. Complexity write-up: [backend-replaceability.md](backend-replaceability.md).

**Operator steps** (`install.sh` does `setcap`; Settings → Update → Update Now for rules; log out only if the Start Menu tile is missing): [spk-deploy-and-update.md](spk-deploy-and-update.md).

**Is not:** a shippable product, PostgreSQL/`synotpsd` parity, or NFQUEUE IPS. Default start is **AF_PACKET IDS**. Official UI in the PoC SPK is research-only.

**glibc / libs:** Ubuntu 24.04 binary needs GLIBC 2.38/2.39; DSM 7.4 SA6400 has glibc 2.36 and no liblz4. The packer vendors Ubuntu libs plus `ld-linux`. File caps put ld.so in secure mode, which ignores `$ORIGIN`, so pack rewrites RUNPATH to `/var/lib/tps` and `start-stop-status`/`postinst` symlink that to `target/lib`.

**AF_PACKET:** unsigned DSM 7 packages cannot declare `run-as: root` or file capabilities in `conf/privilege` (error 319). `install.sh` applies caps. After a hand install, as admin:

```sh
sudo setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep /var/packages/ThreatPrevention/target/bin/suricata
sudo synopkg start ThreatPrevention
```

Default capture iface on SA6400 is `ovs_eth0` (eth0 is an OVS slave).

## Pack command

```sh
./build.sh
# or, no Docker: ./build.sh --from-release
```

That downloads the public `ThreatPrevention-cypress-1.3.3-0926.spk`, extracts
UI / icons / bootstrap rules into `build/official/` (gitignored), builds or
unpacks Suricata 8, and writes `artifact/ThreatPrevention-x86_64-<PKG_VERSION>.spk`
(unsigned POSIX tar / ustar on macOS; vendored libs). `spk/pack-spk.sh` is the
assembler only. CI publishes the engine tarball; NAS hosts use `./install.sh`.

Unlike codecs, this tree does **not** decrypt SPKs or patch license
libraries. The aarch64 engine is replaced, not patched.
