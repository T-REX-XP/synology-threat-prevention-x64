# Native Threat Prevention desktop app

**8.0.6-0018** packs the official ExtJS app (`synoips.js`, `SYNO.SDS.TPS.Application`) from `unpacked/package/ui/` and talks to the community `tpsweb` backend through an inlined `tps-bridge.js`. Official `.so` modules are still aarch64 and are **not** packed. This is a research PoC, not a product. See [backend-replaceability.md](backend-replaceability.md).

The official sources are **not** cloned or rebuilt. The custom work is the Python `SYNO.TPS.*` compatibility layer. DSM ExtJS host / JSLoad recovered in [dsm-extjs-sdk.md](dsm-extjs-sdk.md).

| Piece | Path |
| --- | --- |
| API contract | [api/SYNO.TPS.contract.md](api/SYNO.TPS.contract.md) |
| SQLite + ingest + compiler + tpsweb | `spk/src/threatprevention/python/` |
| Bridge (inlined at pack time) | `spk/src/threatprevention/package/ui/bridge/{transport,dsm7,settings-inject}.js` |
| Official UI (packed as-is) | `unpacked/package/ui/` |
| Start helpers | `spk/src/threatprevention/scripts/start-stop-status` |

Start Menu launches `SYNO.SDS.TPS.Application`. The bridge sends `SYNO.TPS.*` to same-origin `/webman/3rdparty/ThreatPrevention/api` (nginx → tpsweb `:19557`). HTTPS DSM needs that nginx location.

Auth: DSM session cookie, SynoToken, localhost, or RFC1918 peer. Admin-only tile.

DB: `/var/packages/ThreatPrevention/var/tps.db`. Events from `eve.json`. Policy compile writes `var/rules/suricata.rules`.

Still IDS-only (AF_PACKET). `setcap` after every install/upgrade: [spk-deploy-and-update.md](spk-deploy-and-update.md).
