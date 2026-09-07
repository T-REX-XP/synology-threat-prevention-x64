# Native Threat Prevention desktop app

**8.0.6-0017** restores the community UI as a webpack source tree. The Start Menu tile is a thin ExtJS `type: app` window (`threatprevention.js`) that iframes the SPA. Official `synoips.js` is no longer packed.

| Piece | Path |
| --- | --- |
| API contract | [api/SYNO.TPS.contract.md](api/SYNO.TPS.contract.md) |
| SQLite + ingest + compiler + tpsweb | `spk/src/threatprevention/python/` |
| SPA source (webpack) | `ui/src/` |
| Packed SPA + ExtJS shell | `spk/src/threatprevention/package/ui/` (`threatprevention.js`, `config`) |
| Start helpers | `spk/src/threatprevention/scripts/start-stop-status` |

Build the UI (also run automatically by `spk/pack-spk.sh`):

```sh
cd ui && npm ci && npm run build
```

Output is `ui/dist/{index.html,app.js,app.css}`. Local preview: `npm start` in `ui/` (proxies `/api` to tpsweb `:19557`).

`tpsweb` listens on **TCP 19557** and `var/tpsweb.sock`. The Start Menu tile launches `SYNO.SDS.ThreatPrevention.Application`. The SPA is also at `/webman/3rdparty/ThreatPrevention/index.html` and `http://<nas>:19557/`. HTTPS DSM should use the same-origin nginx location `/webman/3rdparty/ThreatPrevention/api` → `127.0.0.1:19557`.

Auth: DSM session cookie, SynoToken, localhost, or RFC1918 peer. Admin-only tile (`grantPrivilege: admin`).

DB: `/var/packages/ThreatPrevention/var/tps.db`. Events from `eve.json`. Policy compile writes `var/rules/suricata.rules`; catalog source is `var/rules/catalog.rules` after `update-rules.sh`. Auto-update is a tpsweb scheduler thread (the package user cannot write `/etc/crontab`).

Still IDS-only (AF_PACKET). `setcap` after every install/upgrade: [spk-deploy-and-update.md](spk-deploy-and-update.md).
