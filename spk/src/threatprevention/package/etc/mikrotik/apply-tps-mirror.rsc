# MikroTik RouterOS → NAS tps0 (TZSP)
#
# Linux gretap (OpenWrt) is Ethernet GRE, ethertype 0x6558. MikroTik EoIP is a
# different GRE flavor and will not peer with the NAS tap. Use sniff-tzsp instead.
#
# Copy this folder from the NAS:
#   /var/packages/ThreatPrevention/target/etc/mikrotik/
# Edit NasIp / WanIf / LanIf below, then on the router:
#   /import file-name=apply-tps-mirror.rsc
#
# Example: router 192.168.1.1, NAS 192.168.1.130, WAN ether1, LAN bridge.

:local NasIp "192.168.1.130"
:local WanIf "ether1"
:local LanIf "bridge"
:local TzspPort 37008

/ip firewall mangle remove [find comment~"tps-mirror"]

# FORWARD only (LAN↔WAN). TZSP to the NAS is OUTPUT, so it is not re-copied.
/ip firewall mangle add chain=forward action=sniff-tzsp sniff-target=$NasIp sniff-target-port=$TzspPort in-interface=$LanIf out-interface=$WanIf comment="tps-mirror-lan-wan"
/ip firewall mangle add chain=forward action=sniff-tzsp sniff-target=$NasIp sniff-target-port=$TzspPort in-interface=$WanIf out-interface=$LanIf comment="tps-mirror-wan-lan"

:put "tps-mirror: TZSP to NAS UDP 37008 (FORWARD LAN <-> WAN)"
:put "Disable fasttrack or copies stay empty. DSM Firewall: UDP 37008 from this router."
