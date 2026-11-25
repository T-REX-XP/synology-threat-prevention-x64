"""Optional IPv4 GeoIP for Event.Map / country pies.

Looks for a legacy MaxMind GeoIP.dat (DSM often ships one) or a file the
admin dropped under the package. No demo MMDB is packed. Private addresses
do not get a pin.
"""
import ipaddress
import os
import time
from functools import lru_cache

from paths import PKGDEST, PKGETC

COUNTRY_BEGIN = 16776960

# Standard GeoIP Country edition ids (index 0 unused).
COUNTRY_CODES = (
    "", "AP", "EU", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "CW",
    "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AZ", "BA", "BB",
    "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BM", "BN", "BO",
    "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD",
    "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR",
    "CU", "CV", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO",
    "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ",
    "FK", "FM", "FO", "FR", "SX", "GA", "GB", "GD", "GE", "GF",
    "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT",
    "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID",
    "IE", "IL", "IN", "IO", "IQ", "IR", "IS", "IT", "JM", "JO",
    "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW",
    "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT",
    "LU", "LV", "LY", "MA", "MC", "MD", "MG", "MH", "MK", "ML",
    "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV",
    "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI",
    "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF",
    "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW",
    "PY", "QA", "RE", "RO", "RU", "RW", "SA", "SB", "SC", "SD",
    "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO",
    "SR", "ST", "SV", "SY", "SZ", "TC", "TD", "TF", "TG", "TH",
    "TJ", "TK", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ",
    "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG",
    "VI", "VN", "VU", "WF", "WS", "YE", "YT", "RS", "ZA", "ZM",
    "ME", "ZW", "A1", "A2", "O1", "AX", "GG", "IM", "JE", "BL",
    "MF", "BQ", "SS",
)

# Country centroids (lat, lng) for map pins when only a country DB exists.
CENTROIDS = {
    "AD": (42.5, 1.5), "AE": (24.0, 54.0), "AF": (33.0, 65.0), "AL": (41.0, 20.0),
    "AM": (40.0, 45.0), "AO": (-12.5, 18.5), "AR": (-34.0, -64.0), "AT": (47.3, 13.3),
    "AU": (-25.0, 133.0), "AZ": (40.5, 47.5), "BA": (44.0, 18.0), "BD": (24.0, 90.0),
    "BE": (50.8, 4.5), "BG": (43.0, 25.0), "BH": (26.0, 50.5), "BO": (-17.0, -65.0),
    "BR": (-10.0, -55.0), "BY": (53.0, 28.0), "CA": (56.0, -106.0), "CH": (47.0, 8.0),
    "CL": (-30.0, -71.0), "CN": (35.0, 105.0), "CO": (4.0, -72.0), "CR": (10.0, -84.0),
    "CU": (21.5, -80.0), "CY": (35.0, 33.0), "CZ": (49.8, 15.5), "DE": (51.2, 10.5),
    "DK": (56.0, 10.0), "DO": (19.0, -70.7), "DZ": (28.0, 3.0), "EC": (-2.0, -77.5),
    "EE": (59.0, 26.0), "EG": (27.0, 30.0), "ES": (40.0, -4.0), "ET": (8.0, 38.0),
    "FI": (64.0, 26.0), "FR": (46.0, 2.0), "GB": (54.0, -2.0), "GE": (42.0, 43.5),
    "GH": (8.0, -2.0), "GR": (39.0, 22.0), "GT": (15.5, -90.3), "HK": (22.3, 114.2),
    "HN": (15.0, -86.5), "HR": (45.2, 15.2), "HU": (47.0, 20.0), "ID": (-5.0, 120.0),
    "IE": (53.0, -8.0), "IL": (31.5, 34.8), "IN": (21.0, 78.0), "IQ": (33.0, 44.0),
    "IR": (32.0, 53.0), "IS": (65.0, -18.0), "IT": (42.8, 12.8), "JO": (31.0, 36.0),
    "JP": (36.0, 138.0), "KE": (1.0, 38.0), "KG": (41.0, 75.0), "KH": (13.0, 105.0),
    "KR": (36.5, 127.8), "KW": (29.3, 47.5), "KZ": (48.0, 68.0), "LA": (18.0, 105.0),
    "LB": (33.8, 35.8), "LK": (7.0, 81.0), "LT": (56.0, 24.0), "LU": (49.8, 6.1),
    "LV": (57.0, 25.0), "LY": (25.0, 17.0), "MA": (32.0, -5.0), "MD": (47.0, 29.0),
    "ME": (42.5, 19.3), "MK": (41.6, 21.7), "MM": (21.0, 96.0), "MN": (46.0, 105.0),
    "MO": (22.2, 113.5), "MX": (23.0, -102.0), "MY": (2.5, 112.5), "NG": (10.0, 8.0),
    "NL": (52.3, 5.3), "NO": (62.0, 10.0), "NP": (28.0, 84.0), "NZ": (-41.0, 174.0),
    "OM": (21.0, 57.0), "PA": (9.0, -80.0), "PE": (-10.0, -76.0), "PH": (13.0, 122.0),
    "PK": (30.0, 70.0), "PL": (52.0, 20.0), "PR": (18.2, -66.5), "PT": (39.5, -8.0),
    "PY": (-23.0, -58.0), "QA": (25.3, 51.2), "RO": (46.0, 25.0), "RS": (44.0, 21.0),
    "RU": (60.0, 100.0), "SA": (25.0, 45.0), "SE": (62.0, 15.0), "SG": (1.3, 103.8),
    "SI": (46.1, 14.8), "SK": (48.7, 19.7), "SN": (14.0, -14.0), "SV": (13.8, -88.9),
    "SY": (35.0, 38.0), "TH": (15.0, 100.0), "TJ": (39.0, 71.0), "TM": (40.0, 60.0),
    "TN": (34.0, 9.0), "TR": (39.0, 35.0), "TT": (11.0, -61.0), "TW": (23.5, 121.0),
    "TZ": (-6.0, 35.0), "UA": (49.0, 32.0), "UG": (1.0, 32.0), "US": (38.0, -97.0),
    "UY": (-33.0, -56.0), "UZ": (41.0, 64.0), "VE": (8.0, -66.0), "VN": (16.0, 106.0),
    "YE": (15.5, 47.5), "ZA": (-29.0, 24.0), "ZM": (-15.0, 30.0), "ZW": (-20.0, 30.0),
}

BOTNET_CLASSES = frozenset((
    "trojan-activity", "command-and-control", "trojan",
    "successful-admin", "successful-user",
))

def geoip_files():
    names = ("GeoIP.dat", "GeoLiteCountry.dat", "GeoIPCountry.dat")
    roots = (
        os.path.join(PKGETC, "geoip"),
        os.path.join(PKGDEST, "etc", "geoip"),
        "/usr/share/GeoIP",
        "/usr/share/geoip",
        "/var/lib/GeoIP",
    )
    out = []
    for root in roots:
        for name in names:
            path = os.path.join(root, name)
            if os.path.isfile(path):
                out.append(path)
    return out


def is_public_ipv4(text):
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return address.is_global and not (address.is_multicast or address.is_reserved)


class _CountryDat:
    def __init__(self, data):
        self.data = data

    def country(self, ipnum):
        offset = 0
        for depth in range(31, -1, -1):
            start = 6 * offset + (3 if ipnum & (1 << depth) else 0)
            if start + 3 > len(self.data):
                return ""
            offset = int.from_bytes(self.data[start:start + 3], "little")
            if offset >= COUNTRY_BEGIN:
                index = offset - COUNTRY_BEGIN
                return COUNTRY_CODES[index] if index < len(COUNTRY_CODES) else ""
        return ""


@lru_cache(maxsize=1)
def _read_dat(path, _mtime, _size):
    with open(path, "rb") as fh:
        return _CountryDat(fh.read())


@lru_cache(maxsize=1)
def _dat_at(_period):
    for path in geoip_files():
        try:
            stat = os.stat(path)
            if stat.st_size > 1000:
                return _read_dat(path, stat.st_mtime_ns, stat.st_size)
        except OSError:
            continue
    return None


def lookup(ip):
    """Return {country, lat, lng} or None."""
    ip = (ip or "").strip()
    if not is_public_ipv4(ip):
        return None
    db = _dat_at(int(time.monotonic()) // 5)
    return _lookup(db, ip) if db else None


@lru_cache(maxsize=8192)
def _lookup(db, ip):
    code = db.country(int(ipaddress.IPv4Address(ip)))
    if not code or code in ("A1", "A2", "O1"):
        return None
    lat, lng = CENTROIDS.get(code, (None, None))
    return {"country": code, "lat": lat, "lng": lng}


def available():
    return _dat_at(int(time.monotonic()) // 5) is not None
