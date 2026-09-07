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
| `version=99.0.0-9999` | newer than official | TPS has no DSM official; we use `8.0.6-0001` (engine version) |
| `silent_install/upgrade=yes` | no wizard | original TPS had wizards; skip for v1 |
| `maintainer=community` | unsigned | do not claim Synology Inc. |
| `conf/privilege` `run-as: package` | install without code signing | DSM 7 blocks unsigned root packages |

Codecs also decrypts official SPKs and patches `libsynoame-license.so`. **That pattern is not used here.** Threat Prevention’s closed aarch64 libs cannot be retargeted; we replace the engine with stock Suricata instead of patching Synology binaries.

## What can be reused from the original SPK

| Keep | Drop |
| --- | --- |
| ET Open tarball, `signature.conf`, classification, thresholds, custom pass SID 1 | `bin/synosuricata`, `libsynotps`, `synotpsd`, all `SYNO.TPS.*.so` (aarch64) |
| Package icons | ExtJS `ui/synoips.js` (copyright + SRM-only) |
| Policy semantics | Upstart, USB swap, `core_pattern`, ECM/NSS AppArmor |
| | `support_topology=router bridge`, `start_dep_services=pgsql` |

## What this first SPK is (and is not)

**Is:** a DSM 7 **x86_64** file+daemon package: Suricata 8.0.6, bundled ET rules, original class policy files, codecs-style unsigned layout. Install with `synopkg install` on Intel/AMD NAS.

**Is not:** a drop-in clone of SRM Threat Prevention (no WebAPI, no ExtJS UI, no `synodb`, no NFQUEUE autowiring). Inline IPS still needs the NAS to be a gateway and extra nftables — the stock start script uses **AF_PACKET IDS** on the first non-loopback interface.

**glibc:** binary was built on Ubuntu 24.04 (glibc 2.39). If `synopkg` installs but `suricata` fails with GLIBC_2.3x, rebuild against pkgscripts-ng / older libc.

## Pack command

```sh
./build/spk/pack-spk.sh
```

Output: `artifact/ThreatPrevention-x86_64-8.0.6-0001.spk` (9.1 MiB, unsigned POSIX tar).

Verified members: `package.tgz`, `INFO`, icons, `scripts/`, `conf/privilege` (`run-as: package`). Inner `bin/suricata` is ELF x86-64 (stripped). `extractsize` is computed at pack time.
