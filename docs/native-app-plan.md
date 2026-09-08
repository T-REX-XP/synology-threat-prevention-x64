# Native Threat Prevention desktop app

This package packs the official ExtJS app (`synoips.js`, `SYNO.SDS.TPS.Application`) from the public SRM SPK at pack time (`build/official/`, gitignored) and talks to the community `tpsweb` backend through an inlined bridge. Official `.so` modules are aarch64 and are **not** packed. Research PoC, not a product. See [backend-replaceability.md](backend-replaceability.md).

The official sources are **not** cloned or rebuilt. Custom work is the Python `SYNO.TPS.*` compatibility layer plus `bridge/{transport,dsm7,settings-inject}.js`. DSM ExtJS host / JSLoad: [dsm-extjs-sdk.md](dsm-extjs-sdk.md).

Do not start a Vue DSM app unless the user asks. Stay on the official ExtJS window + prepended bridge.

| Piece | Path |
| --- | --- |
| API contract | [api/SYNO.TPS.contract.md](api/SYNO.TPS.contract.md) |
| Dispatch | `spk/src/threatprevention/python/api_routes.py` |
| SQLite + ingest + compiler + tpsweb | `spk/src/threatprevention/python/` |
| Bridge (concatenated into `synoips.js` at pack) | `spk/src/threatprevention/package/ui/bridge/{transport,dsm7,settings-inject}.js` |
| Official UI (packed as-is) | `unpacked/package/ui/` after extract, or `build/official/` |
| Start helpers | `spk/src/threatprevention/scripts/start-stop-status` |

Start Menu launches `SYNO.SDS.TPS.Application`. The bridge POSTs hosted `SYNO.TPS.*` to same-origin `/webman/tps-api` (nginx → tpsweb), then `/webman/3rdparty/ThreatPrevention/api`. It does not use `http://host:19557`. Core compounds stay on `entry.cgi`. Do not wrap `SYNO.API.Request` without copying `.Polling`.

Auth: DSM session cookie, SynoToken, localhost, or RFC1918 peer. Admin-only tile.

DB: `/var/packages/ThreatPrevention/var/tps.db`. Events from `eve.json`. Policy compile writes `var/rules/suricata.rules`.

Still IDS-only (AF_PACKET). `setcap` after every install/upgrade unless `install.sh` already ran it: [spk-deploy-and-update.md](spk-deploy-and-update.md).
