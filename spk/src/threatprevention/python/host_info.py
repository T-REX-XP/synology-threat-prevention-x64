#!/usr/bin/env python3
"""Resolve host details for observed LAN endpoints, or print them as JSON."""
import argparse
import ipaddress
import json
import re
import subprocess
import time
from functools import lru_cache

from corehost import _hosts_map, _mac, list_neighbors


LAN_NETWORKS = tuple(map(ipaddress.ip_network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "fc00::/7", "fe80::/10",
)))


def is_lan(address):
    return any(address in network for network in LAN_NETWORKS)


def alert_macs(event):
    ether = event.get("ether") or {}
    return (
        ether.get("src_mac") or event.get("src_mac") or "",
        ether.get("dest_mac") or event.get("dest_mac") or "",
    )


def _unicast_mac(raw):
    mac = _mac(raw)
    if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        if mac != "00:00:00:00:00:00" and not int(mac[:2], 16) & 1:
            return mac
    return ""


@lru_cache(maxsize=1)
def _local_records(_period):
    hosts, _ = _hosts_map()
    neighbors = {}
    for rec in list_neighbors():
        try:
            ip = str(ipaddress.ip_address(rec["ip"]))
        except ValueError:
            continue
        if ip not in neighbors or rec["is_online"]:
            neighbors[ip] = rec
    return hosts, neighbors


def _run(*command):
    try:
        return subprocess.check_output(
            command, stderr=subprocess.DEVNULL, timeout=1,
        ).decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return ""


@lru_cache(maxsize=1024)
def _lookup_name(ip, ipv4, _period):
    for line in _run("getent", "hosts", ip).splitlines():
        fields = line.split()
        if len(fields) >= 2:
            return "hostname", fields[1]
    if ipv4:
        for line in _run("nmblookup", "-A", ip).splitlines():
            match = re.match(r"^\s*(\S+)\s+<00>\s+(-|<ACTIVE>)", line)
            if match and "<GROUP>" not in line:
                return "netbios", match.group(1)
    return "", ""


def lookup_host(ip, captured_mac=""):
    """Use local inventory first, with bounded name lookups for LAN IPs."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if not is_lan(address):
        return {}
    ip = str(address)
    now = int(time.monotonic())
    hosts, neighbors = _local_records(now // 30)
    neighbor = neighbors.get(ip, {})
    mac = _unicast_mac(neighbor.get("mac"))
    name = hosts.get(ip) or neighbor.get("hostname")
    result = {}
    if mac:
        result["mac"] = mac
    else:
        mac = _unicast_mac(captured_mac)
        if mac:
            result["link_mac"] = mac
    if name:
        result["hostname"] = name
    else:
        kind, value = _lookup_name(ip, address.version == 4, now // 300)
        if kind:
            result[kind] = value
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ip", nargs="+", type=ipaddress.ip_address)
    args = parser.parse_args()
    print(json.dumps({str(ip): lookup_host(str(ip)) for ip in args.ip}, indent=2))
