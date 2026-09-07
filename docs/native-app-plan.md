# Native Threat Prevention desktop app

Implemented in **8.0.6-0009**. Official `synoips.js` / `SYNO.TPS.*.so` are **not** shipped.

| Piece | Path |
| --- | --- |
| API contract | [api/SYNO.TPS.contract.md](api/SYNO.TPS.contract.md) |
| SQLite + ingest + compiler + tpsweb | `spk/src/threatprevention/python/` |
| SPA (Overview / Events / Policy / Statistics / Settings) | `spk/src/threatprevention/package/ui/` |
| Start helpers | `spk/src/threatprevention/scripts/start-stop-status` |

`tpsweb` listens on **TCP 19557** and `var/tpsweb.sock`. The Start Menu tile still loads `/webman/3rdparty/ThreatPrevention/index.html`; the SPA calls the API on `:19557` (CORS). Package Center **Open** uses `adminport=19557`.

Auth: DSM session cookie, SynoToken, localhost, or RFC1918 peer. Admin-only tile (`grantPrivilege: admin`).

DB: `/var/packages/ThreatPrevention/var/tps.db`. Events from `eve.json`. Policy compile writes `var/rules/suricata.rules`; catalog source is `var/rules/catalog.rules` after `update-rules.sh`.

Still IDS-only (AF_PACKET). `setcap` after every install/upgrade: [spk-deploy-and-update.md](spk-deploy-and-update.md).
