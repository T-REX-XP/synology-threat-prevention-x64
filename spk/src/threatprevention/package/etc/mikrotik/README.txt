Router traffic copy (MikroTik RouterOS → NAS TAP)
=================================================

The NAS is not the gateway. Suricata on the NAS LAN NIC only sees traffic to
or from the NAS. To inspect LAN ↔ WAN client traffic, this router streams a
copy of FORWARD packets to the NAS with TZSP (UDP 37008). A helper on the NAS
writes those Ethernet frames onto local tps0. IDS only — packets are not dropped.

Why not GRE / EoIP?
  The OpenWrt path uses Linux gretap (GRE ethertype 0x6558, Transparent
  Ethernet Bridging). MikroTik EoIP is a different GRE flavor (tunnel-id) and
  will not peer with tps0. /interface gre is L3 only. sniff-tzsp is the
  RouterOS feature that matches this package.

This package never rewrites the router. Copy this folder from the NAS:

  /var/packages/ThreatPrevention/target/etc/mikrotik/

Example addresses (substitute yours):

  Router LAN  192.168.1.1
  NAS         192.168.1.130
  WAN if      ether1     (PPPoE: pppoe-out1, or your WAN name)
  LAN if      bridge     (or ether2 / vlan if you do not use a bridge)

Do this only on a trusted LAN. Do not allow TZSP from the WAN.


1. DSM Firewall (required, on the NAS)
--------------------------------------
Control Panel → Security → Firewall: allow UDP 37008 from the router LAN
IPv4 to this NAS. Without that, tps0 stays quiet.


2. Fasttrack (required on the router)
-------------------------------------
Fasttracked connections bypass mangle, so copies stay empty. Either disable
the fasttrack-connection filter rule, or do not fasttrack the traffic you
want inspected. This costs CPU; check load before leaving it off on a small
board.

  /ip firewall filter print where action=fasttrack-connection
  /ip firewall filter disable [find action=fasttrack-connection]


3. Apply (this folder, on the router)
-------------------------------------
Edit NasIp, WanIf, and LanIf at the top of apply-tps-mirror.rsc, upload the
file (Files / Winbox), then:

  /import file-name=apply-tps-mirror.rsc

Or paste the two mangle add lines from that file in a terminal.

Confirm:

  /ip firewall mangle print where comment~"tps-mirror"


4. Enable capture on the NAS
----------------------------
Threat Prevention → Settings → General → Capture source:
  Receive a traffic copy from the router
  MikroTik — TZSP stream (UDP 37008)
  Router LAN IPv4 = 192.168.1.1
  Apply, then restart the package so tps0 (TAP) and the TZSP listener start.

  /usr/bin/setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep \
    /var/packages/ThreatPrevention/target/bin/suricata
  synopkg restart ThreatPrevention


5. Verify
---------
NAS:
  ip link show tps0
  cat /var/packages/ThreatPrevention/etc/interface    # should be tps0
  grep -E "tzsp|tps0" /var/packages/ThreatPrevention/var/log/tzsp.log | tail
  grep -E "af-packet|tps0" /var/packages/ThreatPrevention/var/log/suricata.log | tail

Router:
  /ip firewall mangle print stats where comment~"tps-mirror"

Then browse the Internet from a LAN client. Events should cite that client,
not only the NAS.


6. Disable / remove
-------------------
NAS: Settings → Listen on NAS LAN interfaces → Apply → restart package.

Router:
  /ip firewall mangle remove [find comment~"tps-mirror"]
  /ip firewall filter enable [find action=fasttrack-connection]


Notes
-----
- Mangle is forward only. TZSP to the NAS is OUTPUT, so it is not re-copied.
- Every WAN byte is copied again on the LAN as UDP. Expect extra load.
- Switch-chip port mirroring to a spare NAS NIC is an alternative that does
  not use TZSP; this package still listens on one AF_PACKET iface (pin that
  NIC in Settings if you use hardware SPAN).
- Creating tps0 on the NAS needs CAP_NET_ADMIN; Package Center as the
  package user may skip tap create until synopkg restart after setcap.
