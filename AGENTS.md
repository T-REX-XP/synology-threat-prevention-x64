# Threat Prevention (DSM 7 PoC)

Community Suricata 8 + `tpsweb` compatibility backend for the official ExtJS Threat Prevention app. Research PoC, **IDS only** (AF_PACKET). Not a Synology product.

## Non-negotiables

- Never edit official `synoips.js` (gitignored `unpacked/` / `build/official/`). Wrap prototypes in `spk/src/threatprevention/package/ui/bridge/` only.
- Pack concatenates `bridge/{transport,dsm7,settings-inject}.js` **into** `synoips.js`. Do not add the bridge as a `ui/config` module (JSLoad cycle).
- Do not wrap `SYNO.API.Request` unless `.Polling` is copied through. Hosted-only TPS dispatch; Core compounds stay on `entry.cgi`.
- Official ExtJS is Synology copyright. Not in git. Not on GitHub Releases. Download at pack time only.
- Do not start a Vue DSM app (Exit fork) unless the user asks.
- Unsigned DSM 7: `run-as: package`. No NFQUEUE/IPS. `setcap` after every install. Do not put capabilities in `conf/privilege` (synopkg 319).
- Do not inject GitHub tokens into curl/install. Engine URL is `/releases/latest/download/`.
- Do not commit secrets (`telegram.conf`, bot tokens, NAS passwords).

## Layout

| Path | Role |
| --- | --- |
| `VERSION` | `SURICATA_VERSION` only (engine tarball names) |
| `spk/pkg-version.sh` | SPK INFO version = git branch, or tag if detached |
| `install.sh` | NAS: latest installer + latest engine, pack, synopkg, setcap |
| `build.sh` | Dev pack; `--from-release` skips Docker compile |
| `spk/src/threatprevention/python/` | `tpsweb.py` + `api_routes.py` + `compat.py` |
| `spk/src/threatprevention/python/test_compat.py` | Envelope tests; run after backend/UI contract changes |

Default capture iface on SA6400 is `ovs_eth0`.
