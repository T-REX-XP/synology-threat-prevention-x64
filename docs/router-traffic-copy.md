# Router traffic copy (gretap / TZSP IDS)

The NAS is not the gateway. Suricata on `ovs_eth0` only sees packets to/from the NAS. To inspect **LAN ↔ WAN** client traffic, the LAN gateway sends a copy toward the NAS. Suricata listens on local `tps0`. This is IDS only (no NFQUEUE).

Two router families share the same NAS capture pin (`tps0`). They do **not** use the same wire format:

| Gateway | On the router | On the NAS | DSM Firewall |
| --- | --- | --- | --- |
| **OpenWrt** (nftables / fw4) | `gretap` + nft `dup` on **forward** | Linux `gretap` (`tps0`) | GRE, IP protocol **47**, from the router LAN IP |
| **MikroTik** RouterOS | mangle `sniff-tzsp` on **forward** | TAP `tps0` + `tzsp_tap.py` (UDP **37008**) | UDP **37008** from the router LAN IP |

MikroTik **EoIP** is a proprietary GRE flavor (tunnel-id). It will not peer with Linux gretap (ethertype 0x6558, Transparent Ethernet Bridging). `/interface gre` is L3 only. That is why this package uses TZSP for RouterOS.

![LAN clients exchange traffic with the WAN through the LAN gateway. OpenWrt copies it with nft dup over gretap (DSM Firewall GRE protocol 47). MikroTik copies it with sniff-tzsp on UDP 37008. The copy arrives on NAS tps0 and Suricata inspects it.](router-traffic-copy.svg)

Copies are originated on the router as **OUTPUT**. The copy hook is **forward** only, so the copy is not re-mirrored.

The SPK **never** rewrites the router. Copy snippets from the NAS and run them on the gateway.

Shipped with the package:

| Where | What |
| --- | --- |
| DSM Help → **Router traffic copy** | Operator steps inside Help Center / the app **?** button |
| `/var/packages/ThreatPrevention/target/etc/openwrt/` | `apply-tps-mirror.sh` and nft/UCI snippets |
| `/var/packages/ThreatPrevention/target/etc/mikrotik/` | `apply-tps-mirror.rsc` |
| [This file](router-traffic-copy.md) | Full operator reference |

Example addresses below: router `192.168.1.1`, NAS `192.168.1.130`. Substitute yours. Do this only on a trusted LAN; do not allow GRE or TZSP from the WAN.

---

## Prerequisites

1. OpenWrt (nftables / fw4) **or** MikroTik RouterOS as the LAN gateway.
2. This NAS on the same LAN, Threat Prevention installed, **`setcap`** on `bin/suricata`, package started. See [spk-deploy-and-update.md](spk-deploy-and-update.md).
3. Administrator access to DSM Firewall and SSH (OpenWrt) or Winbox/terminal (MikroTik).
4. OpenWrt GRE support: `opkg install kmod-gre gre`. MikroTik: disable **fasttrack** for the traffic you want copied (mangle never sees fasttracked flows).

Recommended order: **DSM Firewall → router script → Settings Apply → package restart → verify**.

---

## NAS

`/var/packages/ThreatPrevention/etc/mirror.conf` (shipped **disabled**). Choose the mode in **Settings → General → Capture source**:

- **Listen on NAS LAN interfaces** — Suricata sees only traffic to/from this NAS (`ovs_eth0`).
- **Receive a traffic copy from the router** — then pick **OpenWrt** (GRE tap) or **MikroTik** (TZSP). Enter the **router LAN IPv4**. Optional NAS IP is gretap-only (empty = auto).

Apply writes `enabled=1`, `router_kind`, `encap` (`gretap` or `tzsp`), and `ifname=tps0`. `start-stop-status` creates `tps0` on **start** (gretap or TAP + TZSP listener) and removes it on stop. Capture is pinned to `tps0` in `etc/interface` when the tap exists; otherwise it stays on `ovs_eth0`.

The tap needs **root** (or `CAP_NET_ADMIN`). Package Center start as the package user may skip create; `sudo synopkg restart ThreatPrevention` after `setcap` on `suricata` is the usual path. Apply does not create the tap by itself.

### DSM firewall (required)

Control Panel → **Security → Firewall**, from the **router LAN IP** only:

| Router | Allow |
| --- | --- |
| OpenWrt | **GRE** (IP protocol **47**) |
| MikroTik | **UDP 37008** |

Without that rule, `tps0` stays quiet. Do not allow GRE or TZSP from WAN or Any.

After install, confirm:

```sh
ip link show tps0
cat /var/packages/ThreatPrevention/etc/interface
getcap /var/packages/ThreatPrevention/target/bin/suricata
grep -E "af-packet|tps0|gretap|tzsp" /var/packages/ThreatPrevention/var/log/suricata.log /var/packages/ThreatPrevention/var/log/tzsp.log 2>/dev/null | tail
```

General → Monitored Interfaces should show **one** enabled capture device (`tps0`), not `tps0` plus LAN 1.

---

## OpenWrt

Copy from the NAS:

`/var/packages/ThreatPrevention/target/etc/openwrt/`

| File | Role |
| --- | --- |
| `README.txt` | Operator steps (this flow, for `cat` on the router) |
| `apply-tps-mirror.sh` | Detect WAN ifname (`ubus` / UCI), install `kmod-gre`+`gre`, UCI `gretap`, write nft include, `firewall reload` |
| `tps-mirror.network` | UCI snippet only |
| `tps-mirror.nft.template` | nft chain with `__WAN_IF__` / `__NAS_IP__` / `__GRE_DEV__` |

On the router:

```sh
NAS_IP=192.168.1.130 sh apply-tps-mirror.sh
```

Optional env:

| Variable | Default | Purpose |
| --- | --- | --- |
| `NAS_IP` | `192.168.1.130` | GRE peer (this NAS) |
| `LAN_IP` | UCI `network.lan.ipaddr` | Router LAN IPv4 (`gretap` local) |
| `WAN_IF` | autodetect | L3 WAN device |
| `GRE_NAME` | `tpsmirror` | UCI section name |

WAN must be the **L3** device (`pppoe-wan` when using PPPoE, not the underlying ethernet). If autodetection is wrong:

```sh
WAN_IF=pppoe-wan NAS_IP=192.168.1.130 sh apply-tps-mirror.sh
```

The nft include is **forward** only (`br-lan` ↔ WAN). GRE to the NAS is OUTPUT, so it is not re-mirrored. The include also returns `ip protocol gre`. fw4 includes `/etc/nftables.d/*.nft` inside `table inet fw4`.

### Manual (no script)

1. `opkg install kmod-gre gre`
2. Append `tps-mirror.network` to `/etc/config/network` (set `ipaddr` / `peeraddr`), then `/etc/init.d/network reload`
3. Copy `tps-mirror.nft.template` to `/etc/nftables.d/10-tps-mirror.nft` and replace `__WAN_IF__`, `__NAS_IP__`, `__GRE_DEV__` (often `gre-tpsmirror`)
4. `/etc/init.d/firewall reload`

Confirm:

```sh
ip link show type gretap
nft list chain inet fw4 tps_mirror
```

---

## MikroTik RouterOS

Copy from the NAS:

`/var/packages/ThreatPrevention/target/etc/mikrotik/`

| File | Role |
| --- | --- |
| `README.txt` | Operator steps (for `cat` on the router) |
| `apply-tps-mirror.rsc` | FORWARD `sniff-tzsp` to the NAS (UDP 37008) |

Edit `NasIp`, `WanIf`, and `LanIf` in the `.rsc`, upload it, then:

```
/import file-name=apply-tps-mirror.rsc
```

`WanIf` must be the **L3** WAN name (`pppoe-out1` when using PPPoE, not the underlying ethernet). `LanIf` is usually `bridge`.

**Fasttrack:** connections that hit `fasttrack-connection` never reach mangle, so the NAS sees nothing. Disable that filter rule (or stop fasttracking the flows you care about) and watch CPU.

Confirm:

```
/ip firewall mangle print stats where comment~"tps-mirror"
```

Hardware **switch-chip port mirroring** to a spare NAS NIC is an alternative that does not use TZSP. Pin that NIC as the capture source if you go that way; this package still listens on one AF_PACKET interface.

---

## Bandwidth and MTU

Every WAN byte is copied again on the LAN toward the NAS (GRE or TZSP). Outer GRE is larger than 1500; the kernel may fragment the outer packet. Inner frames on `tps0` should remain intact. Suricata `checksum-checks: no` on AF_PACKET because copies can fail offload checksums. TZSP on a small RouterBOARD can peg CPU once fasttrack is off.

---

## Disable

**NAS:** Settings → General → **Listen on NAS LAN interfaces**, Apply, then restart the package. Capture returns to `ovs_eth0`. Or set `enabled=0` in `mirror.conf` and restart. Stop removes `tps0`.

**OpenWrt:**

```sh
rm -f /etc/nftables.d/10-tps-mirror.nft
uci -q delete network.tpsmirror
uci commit network
/etc/init.d/network reload
/etc/init.d/firewall reload
```

**MikroTik:**

```
/ip firewall mangle remove [find comment~"tps-mirror"]
/ip firewall filter enable [find action=fasttrack-connection]
```

---

## Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `tps0` missing after Apply | Tap is created only at package start; `CAP_NET_ADMIN` missing | `setcap` on `suricata`, then `synopkg restart ThreatPrevention` |
| `tps0` UP but no LAN client alerts | DSM Firewall blocking GRE/TZSP; OpenWrt WAN ifname not L3; MikroTik fasttrack | Allow proto 47 (OpenWrt) or UDP 37008 (MikroTik) from the router LAN IP; set `WAN_IF` / `WanIf`; disable fasttrack |
| Loop or huge LAN load | Copy hooked on INPUT/OUTPUT, or GRE/TZSP allowed to bounce | Keep **forward**-only copy; do not allow GRE or UDP 37008 from WAN |
| MikroTik counters increment, NAS silent | TZSP listener not running, or wrong `encap` | Settings → **MikroTik**, Apply, restart package; check `var/log/tzsp.log` |
| Capture on `tps0` **and** LAN 1 | Dual pin | Monitored Interfaces should be `tps0` only; restart after Apply |
| `Operation not permitted` on capture | No file capabilities on the new ELF | Post-install `setcap` — [spk-deploy-and-update.md](spk-deploy-and-update.md) |
| nft chain missing | fw4 did not pick up `/etc/nftables.d/` | Confirm the file exists and `firewall reload`; WAN/LAN ifnames must match `iifname`/`oifname` |
