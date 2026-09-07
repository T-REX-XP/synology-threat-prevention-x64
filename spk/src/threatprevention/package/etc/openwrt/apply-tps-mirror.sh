#!/bin/sh
# Run on the OpenWrt router. Installs gre, adds UCI gretap, writes nft LAN↔WAN dup.
# Does not commit from the NAS package — copy this script to the router and run it.
set -e

NAS_IP="${NAS_IP:-192.168.1.130}"
LAN_IP="${LAN_IP:-}"
GRE_NAME="${GRE_NAME:-tpsmirror}"

if [ -z "${LAN_IP}" ]; then
	LAN_IP="$(uci -q get network.lan.ipaddr || true)"
fi
[ -n "${LAN_IP}" ] || { echo "set LAN_IP" >&2; exit 1; }

detect_wan_if() {
	dev=""
	if command -v ubus >/dev/null 2>&1 && command -v jsonfilter >/dev/null 2>&1; then
		dev="$(ubus call network.interface.wan status 2>/dev/null | jsonfilter -e '@.l3_device' -e '@.device' 2>/dev/null | awk 'NF { print; exit }')"
	fi
	if [ -z "${dev}" ]; then
		dev="$(uci -q get network.wan.device || true)"
	fi
	if [ -z "${dev}" ]; then
		dev="$(uci -q get network.wan.ifname || true)"
	fi
	if [ -z "${dev}" ]; then
		dev="$(uci -q get network.wan.device || true)"
	fi
	# pppoe: l3_device is pppoe-wan
	echo "${dev}" | awk '{ print $1 }'
}

WAN_IF="$(detect_wan_if)"
[ -n "${WAN_IF}" ] || { echo "could not detect WAN ifname; set WAN_IF" >&2; exit 1; }

echo "LAN_IP=${LAN_IP} NAS_IP=${NAS_IP} WAN_IF=${WAN_IF} GRE=${GRE_NAME}"

if command -v opkg >/dev/null 2>&1; then
	opkg update >/dev/null 2>&1 || true
	opkg install kmod-gre gre 2>/dev/null || opkg install kmod-gre 2>/dev/null || true
fi

if ! uci -q get network.${GRE_NAME} >/dev/null 2>&1; then
	uci set network.${GRE_NAME}="interface"
	uci set network.${GRE_NAME}.proto="gretap"
	uci set network.${GRE_NAME}.ipaddr="${LAN_IP}"
	uci set network.${GRE_NAME}.peeraddr="${NAS_IP}"
	uci set network.${GRE_NAME}.tunlink="br-lan"
	uci set network.${GRE_NAME}.mtu="1462"
	uci set network.${GRE_NAME}.force_link="1"
	uci commit network
	if [ -x /etc/init.d/network ]; then
		/etc/init.d/network reload || true
	fi
fi

# Wait for the kernel tap; OpenWrt names it gre-<section> or the section name.
GRE_DEV=""
for candidate in "gre-${GRE_NAME}" "${GRE_NAME}" "gre4t-${GRE_NAME}"; do
	if [ -d "/sys/class/net/${candidate}" ]; then
		GRE_DEV="${candidate}"
		break
	fi
done
if [ -z "${GRE_DEV}" ]; then
	GRE_DEV="$(ip -o link show type gretap 2>/dev/null | awk -F': ' '{ print $2; exit }' | cut -d'@' -f1)"
fi
[ -n "${GRE_DEV}" ] || { echo "gretap device not up yet; reboot router or ifup ${GRE_NAME}" >&2; exit 1; }

NFT="/etc/nftables.d/10-tps-mirror.nft"
mkdir -p /etc/nftables.d
cat > "${NFT}" <<EOF
chain tps_mirror {
	type filter hook forward priority -5; policy accept;
	ip protocol gre return
	iifname "br-lan" oifname "${WAN_IF}" dup to ${NAS_IP} device "${GRE_DEV}"
	iifname "${WAN_IF}" oifname "br-lan" dup to ${NAS_IP} device "${GRE_DEV}"
}
EOF

if [ -x /etc/init.d/firewall ]; then
	/etc/init.d/firewall reload
fi

echo "mirror ready: ${GRE_DEV} ← FORWARD br-lan ↔ ${WAN_IF} (not INPUT/OUTPUT)"
echo "DSM must allow GRE (IP protocol 47) from ${LAN_IP} to ${NAS_IP}"
