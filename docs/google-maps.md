# Google Maps in the official Threat Prevention UI

Research PoC notes. The ExtJS Statistics map is Synology’s, not something this package owns. There is **no demo or shared Maps key**.

## What the official app does

On window open (`preLoad` / `GoogleMapLoader.loadScript`) it injects:

```
https://maps.google.com/maps/api/js?libraries=places&callback=onGoogleMapLoaded
```

Defined as `SYNO.SDS.TPS.Utils.GoogleMapLoader.GMAP_API_URL` in `unpacked/package/ui/synoips.js`. There is **no Settings field** and no `key=` query. That used to work; Google now requires a Maps JavaScript API key.

Default map center in `SYNO.SDS.TPS.Statistic.MapPanel` is Taipei (`25.050744`, `121.518979`). Pins come from `SYNO.TPS.Event.Map.list` → `location[]` (`lat`, `lng`, `country`, `ip_src`, …). Marker clusterer is `ui/synoips_no_check.js` (old googlecode image URLs).

This is **not** a `SYNO.TPS.*` WebAPI. The console noise happens even on Overview.

Map severity chips (`getSeverityIcons`) are HTML in a `syno_displayfield`. DSM 7 encodes them; `onSeverityAfterrender` then does `getElementById(…).onclick = …` on null and the spans show as raw markup. The inlined bridge turns off `htmlEncode` for official `syno-sds-ips-event-*` fragments (0027+).

## Console messages (ignore vs real)

| Message | Meaning |
| --- | --- |
| `Google Maps JavaScript API warning: NoApiKeys` | Official URL has no key. Expected. Map tiles stay blank or watermarked. |
| `GET …/mapsjs/gen_204?csp_test=true net::ERR_BLOCKED_BY_CLIENT` | Browser extension (uBlock, privacy/ad block) dropped Google’s telemetry/CSP probe. Not a DSM or tpsweb failure. |
| `loaded directly without loading=async` | Google’s loader hint. Harmless. |
| Empty map / no event pins | `Event.Map.list` `location[]` is empty until GeoIP (backlog T21). A key only buys tiles, not coordinates. |

`ERR_BLOCKED_BY_CLIENT` is the **browser**, not nginx or CSP. Allow `maps.googleapis.com` on the DSM host, or use a private window without blockers.

## There is no demo key

Google does not publish an unrestricted demo key. Do not paste a leaked or third-party key into the NAS (it will be billed to someone else and revoked).

## Using your own key

1. [Google Cloud Console](https://console.cloud.google.com/google/maps-apis) → project → enable **Maps JavaScript API**.
2. Credentials → API key. Restrict:
   - HTTP referrers: `https://zima.futurein.one/*` (and `https://<NAS-IP>:*/*` if you open DSM by IP).
   - API restriction: Maps JavaScript API only.
3. The Cloud project needs billing. There is a monthly free credit; it is not unlimited.

The official JS still has no place to enter the key. A PoC hook (not shipped yet) would be: keep the key **off git**, e.g. `/var/packages/ThreatPrevention/etc/gmaps.key`, and have `tps-bridge.js` rewrite `GoogleMapLoader.prototype.GMAP_API_URL` to append `&key=…`. Do not pack a key into the SPK.

## Related

- Pins / country pies: [backend-port-backlog.md](api/backend-port-backlog.md) T20–T21 (P2 GeoIP).
- Official contract: [official-app-surface.md](api/official-app-surface.md).
- Deploy console table: [spk-deploy-and-update.md](spk-deploy-and-update.md).
