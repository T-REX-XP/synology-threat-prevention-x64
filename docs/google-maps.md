# Statistics event map

From SPK `8.0.8-0071`, the DSM map uses bundled Leaflet and Natural Earth land polygons. It opens without internet access or a Maps API key. The date range and severity controls still use `SYNO.TPS.Event.Map.list`. Event groups at the same coordinates share a pin, and the popup lists the source, target, signature, severity and count for each group.

Older SPKs load the router UI's Google Maps renderer and can show a key error even when the background tiles load. Upgrade the SPK and reload the DSM desktop to replace the cached app script.

## Where event pins appear

- For public IPv4 locations, install a readable legacy IPv4 Country `GeoIP.dat` at `/var/packages/ThreatPrevention/etc/geoip/GeoIP.dat`, or use the DSM copy at `/usr/share/GeoIP/GeoIP.dat` if available. The map uses approximate country centers and tries the source IP before the target IP.
- For LAN alerts without a geolocated peer, create `/var/packages/ThreatPrevention/etc/map-site.json` with your site's coordinates in decimal degrees, for example `{"lat":48.85,"lng":2.35}`. The popup identifies the pin as the configured local site.
- Reopen the Threat Prevention window after adding a location source. This refreshes the cached date ranges. Alerts whose endpoints have no usable location stay in the Events list.

## Bundled map assets

- [Leaflet 1.9.4](https://github.com/Leaflet/Leaflet/tree/v1.9.4), BSD-2-Clause. The SPK includes the license. The bridge uses vector layers and omits the stylesheet URLs for bitmap marker and layer-control icons.
- [Natural Earth 1:110m land](https://www.naturalearthdata.com/downloads/110m-physical-vectors/110m-land/), version 4.1.0, [public domain](https://www.naturalearthdata.com/about/terms-of-use/). `land.json` contains the source shapefile's rings converted to GeoJSON and rounded to four decimal places.
