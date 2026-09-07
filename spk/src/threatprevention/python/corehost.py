"""DSM-missing Core APIs the official ExtJS compounds with SYNO.TPS.*.

SRM Mesh (`SYNO.Core.Network.NSM.Device`) and SRM SystemDB are not on DSM 7.
USB volume listing exists on some DSM builds; we still implement the SRM-shaped
`devices[].partitions[]` the Log Storage tab walks, from live mounts.
"""
import glob
import os
import re
import socket
import subprocess


LEASE_FILES = (
    "/etc/dhcpd/dhcpd.leases",
    "/etc/dhcpd/dhcpd-leases.log",
    "/usr/syno/etc/dhcpd/dhcpd.leases",
    "/var/lib/dhcp/dhcpd.leases",
    "/etc/dhcpd/dhcpd.info",
    "/usr/syno/etc/dhcpd/dhcpd.info",
)
HOSTS_FILE = "/etc/hosts"
ARP_FILE = "/proc/net/arp"
SYNOINFO = "/etc/synoinfo.conf"


def _mac(raw):
    text = (raw or "").strip().lower().replace("-", ":")
    if len(text) == 12 and ":" not in text:
        text = ":".join(text[i:i + 2] for i in range(0, 12, 2))
    parts = text.split(":")
    if len(parts) != 6:
        return ""
    try:
        return ":".join("%02x" % int(p, 16) for p in parts)
    except ValueError:
        return ""


def iface_ipv4(name):
    if not name:
        return ""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "dev", name],
            stderr=subprocess.DEVNULL, timeout=3,
        ).decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return ""
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else ""


def server_name():
    if os.path.isfile(SYNOINFO):
        try:
            for line in open(SYNOINFO, encoding="utf-8", errors="replace"):
                if line.startswith("hostname="):
                    return line.split("=", 1)[1].strip().strip('"') or socket.gethostname()
        except OSError:
            pass
    try:
        return socket.gethostname() or ""
    except OSError:
        return ""


def _hosts_map():
    by_ip, by_mac = {}, {}
    if not os.path.isfile(HOSTS_FILE):
        return by_ip, by_mac
    try:
        fh = open(HOSTS_FILE, encoding="utf-8", errors="replace")
    except OSError:
        return by_ip, by_mac
    with fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip, name = parts[0], parts[1]
            if ip in ("127.0.0.1", "::1"):
                continue
            by_ip.setdefault(ip, name)
    return by_ip, by_mac


def _parse_isc_leases(text):
    """ISC dhcpd.leases → (mac, ip, hostname)."""
    rows = []
    for block in re.split(r"lease\s+", text):
        m_ip = re.match(r"(\d+\.\d+\.\d+\.\d+)\s*\{", block)
        if not m_ip:
            continue
        if re.search(r"binding state\s+free", block):
            continue
        mac = _mac((re.search(r"hardware ethernet\s+([0-9a-fA-F:]+)", block) or [None, ""])[1])
        host = ""
        m_host = re.search(r'client-hostname\s+"([^"]+)"', block)
        if m_host:
            host = m_host.group(1)
        if mac:
            rows.append((mac, m_ip.group(1), host))
    return rows


def _parse_syno_info(text):
    """Synology dhcpd.info style KEY=value blocks."""
    rows = []
    rec = {}
    for line in text.splitlines() + [""]:
        line = line.strip()
        if not line or line.startswith("["):
            mac = _mac(rec.get("MAC") or rec.get("mac") or rec.get("HWADDR") or "")
            ip = rec.get("IP") or rec.get("ip") or rec.get("ADDRESS") or ""
            host = rec.get("HOSTNAME") or rec.get("hostname") or rec.get("NAME") or ""
            if mac and re.match(r"\d+\.\d+\.\d+\.\d+$", ip):
                rows.append((mac, ip, host))
            rec = {}
            if line.startswith("["):
                continue
        if "=" in line:
            k, v = line.split("=", 1)
            rec[k.strip()] = v.strip().strip('"')
    return rows


def dhcp_leases():
    by_mac = {}
    for path in LEASE_FILES:
        if not os.path.isfile(path):
            continue
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        parsed = _parse_isc_leases(text) or _parse_syno_info(text)
        for mac, ip, host in parsed:
            prev = by_mac.get(mac) or {}
            by_mac[mac] = {
                "mac": mac,
                "ip": ip or prev.get("ip") or "",
                "hostname": host or prev.get("hostname") or "",
            }
    return by_mac


def list_neighbors():
    """Live L2/L3 neighbors: arp + ip neigh + DHCP + /etc/hosts."""
    hosts_ip, _unused = _hosts_map()
    leases = dhcp_leases()
    by_mac = {}

    def upsert(mac, ip="", hostname="", online=True, iface=""):
        mac = _mac(mac)
        if not mac or mac == "00:00:00:00:00:00":
            return
        cur = by_mac.get(mac) or {"mac": mac, "ip": "", "hostname": "", "is_online": False, "iface": ""}
        if ip:
            cur["ip"] = ip
        if hostname:
            cur["hostname"] = hostname
        if iface:
            cur["iface"] = iface
        cur["is_online"] = cur["is_online"] or bool(online)
        by_mac[mac] = cur

    if os.path.isfile(ARP_FILE):
        try:
            lines = open(ARP_FILE, encoding="utf-8", errors="replace").read().splitlines()[1:]
        except OSError:
            lines = []
        for line in lines:
            parts = line.split()
            if len(parts) < 6:
                continue
            flags = parts[2]
            online = flags not in ("0x0", "0x00")
            upsert(parts[3], ip=parts[0], online=online, iface=parts[5])

    try:
        neigh = subprocess.check_output(
            ["ip", "neigh", "show"], stderr=subprocess.DEVNULL, timeout=3,
        ).decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        neigh = ""
    for line in neigh.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        ip = parts[0]
        mac = ""
        iface = ""
        state = parts[-1].upper()
        if "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1]
        if "dev" in parts:
            iface = parts[parts.index("dev") + 1]
        online = state not in ("FAILED", "INCOMPLETE", "NONE")
        upsert(mac, ip=ip, online=online, iface=iface)

    for mac, rec in leases.items():
        upsert(mac, ip=rec.get("ip"), hostname=rec.get("hostname"), online=False)

    for rec in by_mac.values():
        if not rec.get("hostname"):
            rec["hostname"] = hosts_ip.get(rec.get("ip") or "") or ""
    kept = []
    for rec in by_mac.values():
        mac = rec.get("mac") or ""
        iface = rec.get("iface") or ""
        if mac.startswith("02:42:"):
            continue
        if iface.startswith(("docker", "br-", "veth", "virbr")):
            continue
        kept.append(rec)
    return sorted(kept, key=lambda r: r.get("ip") or r["mac"])


def nsm_device_list():
    """Shape SRM `SYNO.Core.Network.NSM.Device.get` v4 (`connecttype=all`)."""
    devices = []
    for rec in list_neighbors():
        devices.append({
            "mac": rec["mac"],
            "hostname": rec.get("hostname") or rec.get("ip") or rec["mac"],
            "name": rec.get("hostname") or rec.get("ip") or rec["mac"],
            "ip_addr": rec.get("ip") or "",
            "ip": rec.get("ip") or "",
            "is_online": bool(rec.get("is_online")),
            "online": bool(rec.get("is_online")),
            "connecttype": "lan",
            "mesh_re": False,
        })
    return {"devices": devices}


def usb_volume_rows():
    """Mounted USB/eSATA shares with capacity, SRM partition fields."""
    rows = []
    roots = []
    for pat in ("/volumeUSB*", "/volumeSATA*", "/volumeUSBshare*"):
        roots.extend(glob.glob(pat))
    for root in sorted(set(roots)):
        if not os.path.isdir(root):
            continue
        try:
            shares = os.listdir(root)
        except OSError:
            continue
        partitions = []
        for share in sorted(shares):
            if share.startswith(("@", "#", ".")):
                continue
            path = os.path.join(root, share)
            if not os.path.isdir(path):
                continue
            try:
                st = os.statvfs(path)
            except OSError:
                continue
            mb = int((st.f_frsize * st.f_blocks) / (1024.0 * 1024.0))
            partitions.append({
                "share_name": share,
                "path": path,
                "total_size_mb": mb,
                "status": "normal",
            })
        if not partitions:
            try:
                st = os.statvfs(root)
            except OSError:
                continue
            mb = int((st.f_frsize * st.f_blocks) / (1024.0 * 1024.0))
            partitions.append({
                "share_name": os.path.basename(root),
                "path": root,
                "total_size_mb": mb,
                "status": "normal",
            })
        rows.append({
            "id": os.path.basename(root),
            "dev_id": os.path.basename(root),
            "partitions": partitions,
        })
    return rows


def usb_list():
    """Shape `SYNO.Core.ExternalDevice.Storage.USB.list` additional=all."""
    return {"devices": usb_volume_rows()}


def systemdb_get():
    """SRM SystemDB: share name the event DB lives on (USB pick in Log Storage)."""
    shares = []
    for dev in usb_volume_rows():
        for part in dev.get("partitions") or []:
            if part.get("share_name"):
                shares.append(part["share_name"])
    return {"systemdb_shares": shares[0] if shares else ""}
