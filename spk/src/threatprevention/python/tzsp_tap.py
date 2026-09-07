#!/usr/bin/env python3
"""Decapsulate MikroTik TZSP (UDP 37008) onto a TAP for Suricata AF_PACKET.

Linux gretap (OpenWrt) uses GRE ethertype 0x6558 (TEB). MikroTik EoIP is a
different GRE flavor and will not peer with tps0. RouterOS instead streams
copies with sniff-tzsp; this process writes the inner Ethernet frames to the
same tps0 TAP that Suricata already captures.
"""
import fcntl
import os
import select
import socket
import struct
import sys

from paths import MIRROR_CONF, PKGVAR

TZSP_PORT = 37008
TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
TZSP_TAG_PADDING = 0
TZSP_TAG_END = 1
TZSP_ENCAP_ETHERNET = 1


def _read_mirror():
    out = {"enabled": False, "router_ip": "", "ifname": "tps0", "encap": "gretap"}
    if not os.path.isfile(MIRROR_CONF):
        return out
    try:
        fh = open(MIRROR_CONF, encoding="utf-8", errors="replace")
    except OSError:
        return out
    with fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key, val = key.strip(), val.strip()
            if key == "enabled":
                out["enabled"] = str(val).lower() in ("1", "true", "yes", "on")
            elif key in ("router_ip", "ifname", "encap") and val:
                out[key] = val
    return out


def parse_tzsp(data):
    """Return the inner Ethernet frame, or None if the datagram is not TZSP Ethernet."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) < 5:
        return None
    version = data[0]
    encap = (data[2] << 8) | data[3]
    if version != 1 or encap != TZSP_ENCAP_ETHERNET:
        return None
    i = 4
    n = len(data)
    while i < n:
        tag = data[i]
        i += 1
        if tag == TZSP_TAG_END:
            break
        if tag == TZSP_TAG_PADDING:
            continue
        if i >= n:
            return None
        length = data[i]
        i += 1
        i += length
        if i > n:
            return None
    frame = bytes(data[i:])
    if len(frame) < 14:
        return None
    return frame


def open_tap(ifname):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", ifname.encode("ascii")[:15], IFF_TAP | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd


def serve(ifname="tps0", port=TZSP_PORT, allow_ip=""):
    fd = open_tap(ifname)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", int(port)))
    sock.setblocking(False)
    try:
        while True:
            ready, _, _ = select.select([sock], [], [], 1.0)
            if not ready:
                continue
            try:
                payload, addr = sock.recvfrom(65535)
            except socket.error:
                continue
            if allow_ip and addr and addr[0] != allow_ip:
                continue
            frame = parse_tzsp(payload)
            if not frame:
                continue
            try:
                os.write(fd, frame)
            except OSError:
                continue
    finally:
        try:
            sock.close()
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    cfg = _read_mirror()
    ifname = (argv[0] if argv else "") or cfg.get("ifname") or "tps0"
    allow = cfg.get("router_ip") or ""
    os.makedirs(os.path.join(PKGVAR, "log"), exist_ok=True)
    serve(ifname=ifname, allow_ip=allow)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
