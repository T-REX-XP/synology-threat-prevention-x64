"""Local country lookups for the event map and legacy GeoIP statistics."""
import gzip
import ipaddress
import os
import struct
import time
from functools import lru_cache

import maxminddb
from maxminddb.errors import InvalidDatabaseError

from paths import PKGDEST, PKGETC

COUNTRY_BEGIN = 16776960
MAP_COUNTRY_DB = os.path.join(PKGDEST, "etc", "geoip", "dbip-country-ranges.gz")
_HEADER = struct.Struct(">8sII")
_RANGE4 = struct.Struct(">4s4s2s")
_RANGE6 = struct.Struct(">16s16s2s")

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
    # Additional country label points from Natural Earth 1:50m (v5.1.2).
    "AG": (17.35, -61.79), "AI": (18.24, -63.03), "AQ": (-79.84, 35.89),
    "AS": (-14.33, -170.75), "AW": (12.52, -69.97), "AX": (60.16, 19.87),
    "BB": (13.16, -59.57), "BF": (12.67, -1.36), "BI": (-3.33, 29.92),
    "BJ": (10.32, 2.35), "BL": (17.9, -62.83), "BM": (32.3, -64.76),
    "BN": (4.45, 114.55), "BS": (26.4, -77.15), "BT": (27.54, 90.04),
    "BW": (-22.1, 24.18), "BZ": (17.2, -88.71), "CD": (-1.86, 23.46),
    "CF": (6.99, 20.91), "CG": (0.14, 15.9), "CI": (7.49, -5.57),
    "CK": (-21.22, -159.79), "CM": (4.59, 12.47), "CV": (15.07, -23.64),
    "CW": (12.15, -68.92), "DJ": (11.98, 42.5), "DM": (15.46, -61.34),
    "EH": (23.97, -12.63), "ER": (15.79, 38.29), "FJ": (-17.83, 177.98),
    "FK": (-51.61, -58.74), "FM": (6.89, 158.23), "FO": (62.19, -7.06),
    "GA": (-0.44, 11.84), "GD": (12.11, -61.68), "GG": (49.46, -2.56),
    "GL": (74.32, -39.34), "GM": (13.64, -15.0), "GN": (10.62, -10.02),
    "GQ": (2.33, 8.99), "GS": (-55.68, -31.06), "GU": (13.35, 144.7),
    "GW": (12.16, -14.52), "GY": (5.12, -58.94), "HM": (-53.1, 73.51),
    "HT": (19.26, -72.22), "IM": (54.22, -4.53), "IO": (-6.19, 71.35),
    "JE": (49.22, -2.09), "JM": (18.14, -77.32), "KI": (1.82, -157.38),
    "KM": (-11.73, 43.32), "KN": (17.34, -62.76), "KP": (39.89, 126.44),
    "KY": (19.32, -81.24), "LC": (13.89, -60.98), "LI": (47.11, 9.56),
    "LR": (6.45, -9.46), "LS": (-29.48, 28.25), "MC": (43.74, 7.4),
    "MF": (18.08, -63.05), "MG": (-18.63, 46.7), "MH": (7.08, 171.19),
    "ML": (18.69, -2.04), "MP": (15.19, 145.73), "MR": (19.59, -9.74),
    "MS": (16.74, -62.19), "MT": (35.89, 14.43), "MU": (-20.3, 57.57),
    "MV": (4.17, 73.51), "MW": (-13.39, 33.61), "MZ": (-13.94, 37.84),
    "NA": (-20.58, 17.11), "NC": (-21.06, 165.08), "NE": (17.45, 9.5),
    "NF": (-29.03, 167.95), "NI": (12.67, -85.07), "NR": (-0.52, 166.93),
    "NU": (-19.05, -169.86), "PF": (-17.63, -149.46), "PG": (-5.7, 143.91),
    "PM": (47.04, -56.33), "PN": (-24.36, -128.32), "PS": (32.05, 35.29),
    "PW": (7.52, 134.58), "RW": (-1.9, 30.1), "SB": (-8.03, 159.17),
    "SC": (-4.68, 55.48), "SD": (16.33, 29.26), "SH": (-15.95, -5.71),
    "SL": (8.62, -11.76), "SM": (43.93, 12.44), "SO": (3.57, 45.19),
    "SR": (4.14, -55.91), "SS": (7.23, 30.39), "ST": (0.97, 7.02),
    "SX": (18.04, -63.07), "SZ": (-26.53, 31.47), "TC": (21.82, -71.75),
    "TD": (15.14, 18.65), "TF": (-49.3, 69.12), "TG": (8.81, 1.06),
    "TL": (-8.8, 125.85), "TO": (-21.21, -175.16), "TV": (-8.51, 179.21),
    "VA": (41.9, 12.45), "VC": (13.09, -61.34), "VG": (18.43, -64.64),
    "VI": (17.75, -64.78), "VU": (-15.37, 166.91), "WF": (-14.29, -178.14),
    "WS": (-13.64, -172.44), "XK": (42.59, 20.86),
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


class _CountryRanges:
    def __init__(self, data):
        self.data = data
        if len(data) < _HEADER.size:
            raise ValueError("Missing country ranges header")
        magic, self.count4, self.count6 = _HEADER.unpack_from(data)
        self.start6 = _HEADER.size + self.count4 * _RANGE4.size
        if magic != b"TPSGEO1\0" or len(data) != self.start6 + self.count6 * _RANGE6.size:
            raise ValueError("Invalid country ranges")

    def country(self, address):
        if address.version == 4:
            table, start, upper = _RANGE4, _HEADER.size, self.count4
        else:
            table, start, upper = _RANGE6, self.start6, self.count6
        target = address.packed
        lower = 0
        while lower < upper:
            middle = (lower + upper) // 2
            first, last, code = table.unpack_from(self.data, start + middle * table.size)
            if target < first:
                upper = middle
            elif target > last:
                lower = middle + 1
            else:
                return code.decode("ascii")
        return ""


@lru_cache(maxsize=1)
def _read_ranges(path):
    try:
        with gzip.open(path, "rb") as fh:
            return _CountryRanges(fh.read())
    except (OSError, EOFError, ValueError):
        return None


@lru_cache(maxsize=8192)
def _ranges_location(db, address):
    code = db.country(address)
    point = CENTROIDS.get(code)
    return {"country": code, "lat": point[0], "lng": point[1]} if point else None


def city_paths():
    return (
        os.path.join(PKGETC, "geoip", "GeoLite2-City.mmdb"),
        "/var/db/geoip-database/GeoLite2-City.mmdb",
    )


@lru_cache(maxsize=2)
def _read_city(path, _mtime, _size):
    try:
        db = maxminddb.open_database(path, maxminddb.MODE_MMAP)
    except (OSError, InvalidDatabaseError, ValueError):
        return None
    if db.metadata().database_type in ("GeoLite2-City", "GeoIP2-City"):
        return db
    db.close()
    return None


@lru_cache(maxsize=1)
def _city_at(_period):
    for path in city_paths():
        try:
            stat = os.stat(path)
        except OSError:
            continue
        key = (path, stat.st_mtime_ns, stat.st_size)
        if _read_city(*key) is not None:
            return key
    return None


@lru_cache(maxsize=8192)
def _city_location(key, address):
    db = _read_city(*key)
    try:
        record = (db.get(address) or {}) if db else {}
    except (InvalidDatabaseError, ValueError):
        return None
    country = (record.get("country") or {}).get("iso_code")
    location = record.get("location") or {}
    lat, lng = location.get("latitude"), location.get("longitude")
    if not country or not isinstance(lat, (float, int)) or not isinstance(lng, (float, int)):
        return None
    if not (-90 <= lat <= 90 and -180 <= lng <= 180):
        return None
    result = {"country": country, "lat": lat, "lng": lng, "geo_provider": "maxmind"}
    radius = location.get("accuracy_radius")
    if isinstance(radius, int) and radius > 0:
        result["accuracy_radius_km"] = radius
    return result


def map_lookup(ip):
    """Prefer city coordinates, then fall back to legacy and bundled country data."""
    try:
        address = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    if not address.is_global or address.is_multicast or address.is_reserved:
        return None
    city = _city_at(int(time.monotonic()) // 5)
    if city:
        result = _city_location(city, address)
        if result:
            return result
    if address.version == 4:
        legacy = lookup(str(address))
        if legacy and legacy["lat"] is not None:
            return legacy
    db = _read_ranges(MAP_COUNTRY_DB)
    return _ranges_location(db, address) if db else None


def map_available():
    period = int(time.monotonic()) // 5
    return bool(_city_at(period) or _dat_at(period) or _read_ranges(MAP_COUNTRY_DB))
