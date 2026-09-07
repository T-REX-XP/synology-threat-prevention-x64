# Router traffic copy (gretap IDS)

The NAS is not the gateway. Suricata on `ovs_eth0` only sees packets to/from the NAS. To inspect **LAN ↔ WAN** client traffic, OpenWrt duplicates those FORWARD frames into a **gretap** toward the NAS. Suricata listens on local `tps0`. This is IDS only (no NFQUEUE).

```
LAN clients ↔ br-lan ↔ wan
                 │
                 │ nft dup (FORWARD only)
                 ▼
            gretap (GRE proto 47)  →  NAS tps0  →  Suricata AF_PACKET
```

GRE is originated on the router (OUTPUT). The nft hook is **forward** only, so the copy is not re-mirrored. The include also `return`s `ip protocol gre`.

The SPK **never** rewrites the router. Copy snippets from the NAS and run them on OpenWrt.

Shipped with the package:

| Where | What |
| --- | --- |
| DSM Help → **Router traffic copy** | Operator steps inside Help Center / the app **?** button |
| `/var/packages/ThreatPrevention/target/etc/openwrt/README.txt` | Same steps on the NAS (copy this folder to the router) |
| This file | Full operator reference |

Example addresses below: router `192.168.1.1`, NAS `192.168.1.130`. Substitute yours. Do this only on a trusted LAN; do not allow GRE from the WAN.

---

## Prerequisites

1. OpenWrt as the LAN gateway (nftables / fw4).
2. This NAS on the same LAN, Threat Prevention installed, **`setcap`** on `bin/suricata`, package started. See [spk-deploy-and-update.md](spk-deploy-and-update.md).
3. Administrator access to DSM Firewall and SSH on both hosts.
4. GRE support on the router: `opkg install kmod-gre gre`.

Recommended order: **DSM Firewall → OpenWrt script → Settings Apply → package restart → verify**.

---

## NAS

`/var/packages/ThreatPrevention/etc/mirror.conf` (shipped **disabled**). Choose the mode in **Settings → General → Capture source**:

- **Listen on NAS LAN interfaces** — Suricata sees only traffic to/from this NAS (`ovs_eth0`).
- **Receive a traffic copy from the router** — OpenWrt GRE-copies LAN↔WAN onto local `tps0`. Enter the **router LAN IPv4**. Optional NAS IP (empty = auto).

Apply writes:

```
enabled=1
router_ip=192.168.1.1
local_ip=
ifname=tps0
```

Empty `local_ip` uses the IPv4 `ip route get` picks toward `router_ip`. `start-stop-status` creates `tps0` (`type gretap`) on **start** when `enabled=1` and removes it on stop. Capture is pinned to `tps0` in `etc/interface` when the tap exists; otherwise it stays on `ovs_eth0`.

`gretap` needs **root** (or `CAP_NET_ADMIN`). Package Center start as the package user may skip tunnel create; `sudo synopkg restart ThreatPrevention` after `setcap` on `suricata` is the usual path. Apply does not create the tap by itself.

### DSM firewall (required)

Control Panel → **Security → Firewall**: allow **GRE** (IP protocol **47**) **from the router LAN IP** (`192.168.1.1`) to this NAS. Without that, `tps0` stays quiet.

Do not add a generic “allow GRE from WAN” or from Any.

After install, confirm:

```sh
ip link show tps0
cat /var/packages/ThreatPrevention/etc/interface
getcap /var/packages/ThreatPrevention/target/bin/suricata
grep -E "af-packet|tps0|gretap" /var/packages/ThreatPrevention/var/log/suricata.log | tail
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

## Bandwidth and MTU

Every WAN byte is copied again as GRE on the LAN toward the NAS. Outer GRE is larger than 1500; the kernel may fragment the outer packet. Inner frames on `tps0` should remain intact. Suricata `checksum-checks: no` on AF_PACKET because copies can fail offload checksums.

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

---

## Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `tps0` missing after Apply | Tap is created only at package start; `CAP_NET_ADMIN` missing | `setcap` on `suricata`, then `synopkg restart ThreatPrevention` |
| `tps0` UP but no LAN client alerts | DSM Firewall blocking GRE, or OpenWrt WAN ifname is not the L3 device | Allow proto 47 from the router LAN IP; set `WAN_IF` and rerun the script |
| Capture on `tps0` **and** LAN 1 | Dual pin | Monitored Interfaces should be `tps0` only; restart after Apply |
| `Operation not permitted` on capture | No file capabilities on the new ELF | Post-install `setcap` — [spk-deploy-and-update.md](spk-deploy-and-update.md) |
| nft chain missing | fw4 did not pick up `/etc/nftables.d/` | Confirm the file exists and `firewall reload`; WAN/LAN ifnames must match `iifname`/`oifname` |
| Loop or huge LAN load | Copy hooked on INPUT/OUTPUT, or GRE allowed to bounce | Keep the **forward**-only include; do not mirror GRE; do not allow GRE from WAN |
