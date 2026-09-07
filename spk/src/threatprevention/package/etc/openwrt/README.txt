Router traffic copy (OpenWrt → NAS gretap)
==========================================

The NAS is not the gateway. Suricata on the NAS LAN NIC only sees traffic to
or from the NAS. To inspect LAN ↔ WAN client traffic, this router duplicates
FORWARD frames into a gretap toward the NAS. Suricata listens on local tps0.
IDS only — packets are not dropped.

This package never rewrites the router. Copy this folder from the NAS:

  /var/packages/ThreatPrevention/target/etc/openwrt/

Example addresses (substitute yours):

  Router LAN  192.168.1.1
  NAS         192.168.1.130

Do this only on a trusted LAN. Do not allow GRE from the WAN.


1. DSM Firewall (required, on the NAS)
--------------------------------------
Control Panel → Security → Firewall: allow GRE (IP protocol 47) from the
router LAN IPv4 to this NAS. Without that, tps0 stays quiet.


2. Packages on this router
--------------------------
  opkg update
  opkg install kmod-gre gre


3. Apply (this folder, on the router)
-------------------------------------
  NAS_IP=192.168.1.130 sh apply-tps-mirror.sh

The script:

  - Detects LAN IPv4 (UCI network.lan.ipaddr) unless LAN_IP is set
  - Detects the WAN L3 device (ubus / UCI). For PPPoE this must be
    pppoe-wan (or the equivalent), not the underlying ethernet
  - Adds UCI interface tpsmirror (proto gretap, tunlink br-lan, mtu 1462)
  - Writes /etc/nftables.d/10-tps-mirror.nft (FORWARD br-lan ↔ WAN only)
  - Reloads firewall

If WAN detection is wrong, set it explicitly and rerun:

  WAN_IF=pppoe-wan NAS_IP=192.168.1.130 sh apply-tps-mirror.sh

Or edit the generated nft file and reload: /etc/init.d/firewall reload

Manual pieces (if you do not want the script):

  tps-mirror.network         append to /etc/config/network, then network reload
  tps-mirror.nft.template    copy to /etc/nftables.d/10-tps-mirror.nft and
                             replace __WAN_IF__ __NAS_IP__ __GRE_DEV__
                             (GRE_DEV is often gre-tpsmirror)


4. Enable capture on the NAS
----------------------------
Threat Prevention → Settings → General → Capture source:
  Receive a traffic copy from the router
  Router LAN IPv4 = 192.168.1.1
  Apply, then restart the package so tps0 is created.

  /usr/bin/setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep \
    /var/packages/ThreatPrevention/target/bin/suricata
  synopkg restart ThreatPrevention


5. Verify
---------
NAS:
  ip link show tps0
  cat /var/packages/ThreatPrevention/etc/interface    # should be tps0
  grep -E "af-packet|tps0|gretap" \
    /var/packages/ThreatPrevention/var/log/suricata.log | tail

Router:
  ip link show type gretap
  nft list chain inet fw4 tps_mirror

Then browse the Internet from a LAN client. Events should cite that client,
not only the NAS.


6. Disable / remove
-------------------
NAS: Settings → Listen on NAS LAN interfaces → Apply → restart package.

Router:
  rm -f /etc/nftables.d/10-tps-mirror.nft
  uci -q delete network.tpsmirror
  uci commit network
  /etc/init.d/network reload
  /etc/init.d/firewall reload


Notes
-----
- nft hook is forward only. GRE to the NAS is OUTPUT, so it is not
  re-mirrored. The include also returns "ip protocol gre".
- Every WAN byte is copied again on the LAN. Outer GRE can exceed 1500
  and fragment; inner frames on tps0 should stay intact.
- Creating tps0 on the NAS needs CAP_NET_ADMIN; Package Center as the
  package user may skip tunnel create until synopkg restart after setcap.
