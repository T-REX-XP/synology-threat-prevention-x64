"""Optional IPv4 GeoIP for Event.Map / country pies.

Looks for a legacy MaxMind GeoIP.dat (DSM often ships one) or a file the
admin dropped under the package. No demo MMDB is packed. Private addresses
do not get a pin.
"""
import os
import socket
import struct

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

_DAT = None
_CACHE = {}


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
            if os.path.isfile(path) and os.path.getsize(path) > 1000:
                out.append(path)
    return out


def is_public_ipv4(text):
    try:
        packed = socket.inet_aton(text)
    except (OSError, TypeError, ValueError):
        return False
    n = struct.unpack("!I", packed)[0]
    if n == 0 or n == 0xFFFFFFFF:
        return False
    if (n & 0xFF000000) == 0x00000000:
        return False
    if (n & 0xFF000000) == 0x7F000000:
        return False
    if (n & 0xFF000000) == 0x0A000000:
        return False
    if (n & 0xFFF00000) == 0xAC100000:
        return False
    if (n & 0xFFFF0000) == 0xC0A80000:
        return False
    if (n & 0xFFFF0000) == 0xA9FE0000:
        return False
    if (n & 0xFF000000) == 0xE0000000:
        return False
    return True


def ipv4_num(text):
    return struct.unpack("!I", socket.inet_aton(text))[0]


class _CountryDat(object):
    def __init__(self, path):
        self.path = path
        self.fh = open(path, "rb")

    def country(self, ipnum):
        offset = 0
        try:
            for depth in range(31, -1, -1):
                self.fh.seek(6 * offset)
                buf = self.fh.read(6)
                if len(buf) < 6:
                    return ""
                left = buf[0] | (buf[1] << 8) | (buf[2] << 16)
                right = buf[3] | (buf[4] << 8) | (buf[5] << 16)
                nxt = right if ipnum & (1 << depth) else left
                if nxt >= COUNTRY_BEGIN:
                    idx = nxt - COUNTRY_BEGIN
                    if 0 <= idx < len(COUNTRY_CODES):
                        return COUNTRY_CODES[idx]
                    return ""
                offset = nxt
        except OSError:
            return ""
        return ""


def _dat():
    global _DAT
    if _DAT is not None:
        return _DAT
    files = geoip_files()
    _DAT = _CountryDat(files[0]) if files else False
    return _DAT


def lookup(ip):
    """Return {country, lat, lng} or None."""
    ip = (ip or "").strip()
    if ip in _CACHE:
        return _CACHE[ip]
    if not is_public_ipv4(ip):
        _CACHE[ip] = None
        return None
    db = _dat()
    if not db:
        _CACHE[ip] = None
        return None
    try:
        code = db.country(ipv4_num(ip))
    except Exception:
        code = ""
    if not code or code in ("A1", "A2", "O1", "AP", "EU"):
        # Anonymous / satellite / continent — skip pin, keep country if useful.
        if code in ("AP", "EU"):
            rec = {"country": code, "lat": None, "lng": None}
            _CACHE[ip] = rec
            return rec
        _CACHE[ip] = None
        return None
    lat, lng = CENTROIDS.get(code, (None, None))
    rec = {"country": code, "lat": lat, "lng": lng}
    _CACHE[ip] = rec
    return rec


def available():
    return bool(geoip_files())
