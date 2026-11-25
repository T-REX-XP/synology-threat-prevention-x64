# Google Maps in the official Threat Prevention UI

Research PoC notes. The ExtJS Statistics map is Synology’s, not something this package owns. There is **no demo or shared Maps key**.

## What the official app does

On window open (`preLoad` / `GoogleMapLoader.loadScript`) it injects:

```
https://maps.google.com/maps/api/js?libraries=places&callback=onGoogleMapLoaded
```

Defined as `SYNO.SDS.TPS.Utils.GoogleMapLoader.GMAP_API_URL` in `unpacked/package/ui/synoips.js`. There is **no Settings field** and no `key=` query. That used to work; Google now requires a Maps JavaScript API key.

Pins come from `SYNO.TPS.Event.Map.list` in the 7-day, 30-day, and all-logs buckets. The bridge waits for Google Maps before initializing the panel, proxies OpenStreetMap tiles through DSM, and fits the viewport to the visible markers.

This is **not** a `SYNO.TPS.*` WebAPI. The console noise happens even on Overview.

Map severity chips (`getSeverityIcons`) are HTML in a `syno_displayfield`. DSM 7 encodes them; `onSeverityAfterrender` then does `getElementById(…).onclick = …` on null and the spans show as raw markup. The inlined bridge turns off `htmlEncode` for official `syno-sds-ips-event-*` fragments.

## Console messages (ignore vs real)

| Message | Meaning |
| --- | --- |
| `Google Maps JavaScript API warning: NoApiKeys` | Official URL has no key. Expected. Map tiles stay blank or watermarked. |
| `GET …/mapsjs/gen_204?csp_test=true net::ERR_BLOCKED_BY_CLIENT` | Browser extension (uBlock, privacy/ad block) dropped Google’s telemetry/CSP probe. Not a DSM or tpsweb failure. |
| `d.first is not a function` in `gmapWarningHidden` | The official code treats native MutationObserver records as Ext collections. The current bridge disables that helper. |
| `img-src` CSP blocks `tile.openstreetmap.org` | The current bridge fetches the tiles via the same-origin `/webman/tps-api` endpoint. Check that the current package and DSM nginx configuration are installed. |
| `loaded directly without loading=async` | Google’s loader hint. Harmless. |
| Map loads with no event pins | Check the selected date range and configure one of the location sources below. |

`ERR_BLOCKED_BY_CLIENT` is the **browser**, not nginx or CSP. Allow `maps.googleapis.com` on the DSM host, or use a private window without blockers.

## There is no demo key

Google does not publish an unrestricted demo key. Do not paste a leaked or third-party key into the NAS (it will be billed to someone else and revoked).

## Using your own key

1. [Google Cloud Console](https://console.cloud.google.com/google/maps-apis) → project → enable **Maps JavaScript API**.
2. Credentials → API key. Restrict:
   - HTTP referrers: `https://zima.futurein.one/*` (and `https://<NAS-IP>:*/*` if you open DSM by IP).
   - API restriction: Maps JavaScript API only.
3. The Cloud project needs billing. There is a monthly free credit; it is not unlimited.

The official JS still has no place to enter the key. The bridge rewrites `GoogleMapLoader.GMAP_API_URL` when `/var/packages/ThreatPrevention/etc/gmaps.key` exists (one line, no spaces). The key stays **off git** and is **not** packed in the SPK. Reload the Threat Prevention window after dropping the file.

## Where event pins appear

- For public IPv4 locations, install a readable legacy IPv4 Country `GeoIP.dat` at `/var/packages/ThreatPrevention/etc/geoip/GeoIP.dat`, or use the DSM copy at `/usr/share/GeoIP/GeoIP.dat` if available. Country coordinates are approximate. Threat Prevention tries the source first and then the target so outbound alerts can show the remote location.
- For LAN alerts without a geolocatable peer, optionally create `/var/packages/ThreatPrevention/etc/map-site.json` with your site's coordinates in decimal degrees, for example `{"lat":48.85,"lng":2.35}`. These pins are labeled as the configured local site. The backend reads this file on each map request.
- Reload the Threat Prevention window after adding a location source to refresh the cached Statistics view.

## Related

- Country statistics use source IP GeoIP. See [backend-port-backlog.md](api/backend-port-backlog.md) T20–T21.
- Official contract: [official-app-surface.md](api/official-app-surface.md).
- Deploy console table: [spk-deploy-and-update.md](spk-deploy-and-update.md).
