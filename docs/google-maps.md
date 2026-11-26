# Statistics event map

From SPK `8.0.8-0071`, the DSM map uses bundled Leaflet and Natural Earth land polygons. It opens without internet access or a Maps API key. The date range and severity controls still use `SYNO.TPS.Event.Map.list`. Event groups at the same coordinates share a pin, and the popup lists the source, target, signature, severity and count for each group.

Older SPKs load the router UI's Google Maps renderer and can show a key error even when the background tiles load. Upgrade the SPK and reload the DSM desktop to replace the cached app script.

## Original SRM map and DSM support

- In the RT6600ax Threat Prevention SPKs `1.3.3-0926` and `1.3.4-0927`, `ui/synoips.js` sets the Google Maps renderer to a custom `OSM` map type and requests tiles from `tile.openstreetmap.org`. The UI requests marker coordinates separately through `SYNO.TPS.Event.Map.list`.
- The `1.3.3-0926` event module calls `DBCache::getMapData`. The geolocation code in `libsynotps.so.1.3.3` reads SRM's model ID and `etc/display/map.conf`. The flags for the RT1900ac and MR2200ac select the legacy MaxMind `/var/db/geoip-database/GeoLiteCity.dat` path; the default branch uses `/var/db/geoip-database/GeoLite2-City.mmdb` via `libmaxminddb`. Both database paths are also present in `1.3.4-0927`. The SPKs contain neither database. This evidence is from static package inspection.
- Starting in SPK `8.0.8-0076`, Statistics → Map opens with **OpenStreetMap**. Its tiles show country and city names as you zoom. The layer selector also offers **Offline**, which draws land outlines and event pins and loads automatically if a tile fails. OpenStreetMap receives tile coordinates and the DSM origin through the same-origin proxy. The NAS looks up event IPs locally.
- To use MaxMind City coordinates, provide a current `GeoLite2-City.mmdb` in `/var/packages/ThreatPrevention/etc/geoip/` or use the system file at the SRM path above. The package includes the pure-Python MMDB reader and accepts GeoLite2 City and GeoIP2 City data. Update the file by atomic replacement and reopen Threat Prevention. MaxMind provides database downloads and update instructions. [MaxMind GeoLite documentation](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)

## Where event pins appear

- The map tries the event source IP before the target IP. For each public endpoint it uses MaxMind City coordinates when available, then a usable legacy IPv4 `GeoIP.dat` location, then the bundled DB-IP country locations for IPv4 and IPv6. City pins show the accuracy radius when the database supplies one.
- For LAN alerts without a geolocated peer, create `/var/packages/ThreatPrevention/etc/map-site.json` with your site's coordinates in decimal degrees, for example `{"lat":48.85,"lng":2.35}`. The popup identifies the pin as the configured local site.
- Reopen the Threat Prevention window after adding a location source. This refreshes the cached date ranges. Alerts whose endpoints have no usable location stay in the Events list.

## Bundled map assets

- [Leaflet 1.9.4](https://github.com/Leaflet/Leaflet/tree/v1.9.4), BSD-2-Clause. The SPK includes the license. The bridge uses vector layers and omits the stylesheet URLs for bitmap marker and layer-control icons.
- [Natural Earth 1:110m land](https://www.naturalearthdata.com/downloads/110m-physical-vectors/110m-land/), version 4.1.0, [public domain](https://www.naturalearthdata.com/about/terms-of-use/). `land.json` contains the source shapefile's rings converted to GeoJSON and rounded to four decimal places.
- Additional country pin coordinates use the `LABEL_X` and `LABEL_Y` fields of [Natural Earth 1:50m country data v5.1.2](https://github.com/nvkelso/natural-earth-vector/blob/v5.1.2/geojson/ne_50m_admin_0_countries.geojson).
- [IP Geolocation by DB-IP](https://db-ip.com/db/lite.php), November 2026 Country Lite, [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The package contains compact address range tables converted from the published IPv4 and IPv6 CSV. To refresh the snapshot, run `python3 spk/build-country-ranges.py <dbip-country-lite-YYYY-MM.csv.gz> spk/src/threatprevention/package/etc/geoip/dbip-country-ranges.gz` and update the accompanying notice.
- [MaxMind DB Reader 2.6.2](https://pypi.org/project/maxminddb/2.6.2/), Apache 2.0. The SPK contains the Python modules and license. The GeoLite2 dataset is provided by the operator or operating system.
