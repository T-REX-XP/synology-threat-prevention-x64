# Native Threat Prevention desktop app

**8.0.6-0010** was the community ExtJS app. **8.0.6-0011** is the research PoC: official `synoips.js` packed from `unpacked/package/ui/` plus `tps-bridge.js` → tpsweb. Official `.so` modules are still aarch64 and are **not** packed. See [backend-replaceability.md](backend-replaceability.md).

Start Menu is a DSM **ExtJS** `type: app` (`threatprevention.js` → `SYNO.SDS.AppWindow`) with the official tab names. It is original community code, not a copy of `synoips.js`. It calls `SYNO.TPS.*` on tpsweb `:19557`. Package Center Open uses `dsmappname` (the ExtJS window), not a standalone HTML URL.

| Piece | Path |
| --- | --- |
| API contract | [api/SYNO.TPS.contract.md](api/SYNO.TPS.contract.md) |
| SQLite + ingest + compiler + tpsweb | `spk/src/threatprevention/python/` |
| SPA (Overview / Events / Policy / Statistics / Settings) | `spk/src/threatprevention/package/ui/` |
| Start helpers | `spk/src/threatprevention/scripts/start-stop-status` |

`tpsweb` listens on **TCP 19557** and `var/tpsweb.sock`. The Start Menu tile launches the ExtJS desktop window. The old HTML SPA remains at `/webman/3rdparty/ThreatPrevention/index.html` as a fallback. HTTPS DSM may block Ajax to HTTP `:19557` (mixed content); use HTTP DSM or open `http://<nas>:19557/`.

Auth: DSM session cookie, SynoToken, localhost, or RFC1918 peer. Admin-only tile (`grantPrivilege: admin`).

DB: `/var/packages/ThreatPrevention/var/tps.db`. Events from `eve.json`. Policy compile writes `var/rules/suricata.rules`; catalog source is `var/rules/catalog.rules` after `update-rules.sh`.

Still IDS-only (AF_PACKET). `setcap` after every install/upgrade: [spk-deploy-and-update.md](spk-deploy-and-update.md).
