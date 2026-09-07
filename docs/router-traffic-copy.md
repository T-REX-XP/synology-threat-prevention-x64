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

Empty `local_ip` uses the IPv4 `ip route get` picks toward `router_ip`. `start-stop-status` creates `tps0` (`type gretap`) on start when `enabled=1` and removes it on stop. Capture is pinned to `tps0` in `etc/interface` when the tap exists; otherwise it stays on `ovs_eth0`.

`gretap` needs **root** (or `CAP_NET_ADMIN`). Package Center start as the package user may skip tunnel create; `sudo synopkg restart ThreatPrevention` after `setcap` on `suricata` is the usual path.

### DSM firewall (required)

Control Panel → **Security → Firewall**: allow **GRE** (IP protocol **47**) **from the router LAN IP** (`192.168.1.1`) to this NAS. Without that, `tps0` stays quiet.

Do not add a generic “allow GRE from WAN”.

After install, confirm:

```sh
ip link show tps0
grep . /var/packages/ThreatPrevention/etc/interface
getcap /var/packages/ThreatPrevention/target/bin/suricata
grep -E "af-packet|tps0|gretap" /var/packages/ThreatPrevention/var/log/suricata.log | tail
```

General → Monitored Interfaces should show **one** enabled capture device (`tps0`), not `tps0` plus LAN 1.

## OpenWrt

Do **not** let the SPK rewrite the router. Copy from the NAS:

`/var/packages/ThreatPrevention/target/etc/openwrt/`

| File | Role |
| --- | --- |
| `apply-tps-mirror.sh` | Detect WAN ifname (`ubus` / UCI `network.wan.device` / `ifname`), install `kmod-gre`+`gre`, UCI `gretap`, write nft include, `firewall reload` |
| `tps-mirror.network` | UCI snippet only |
| `tps-mirror.nft.template` | nft chain with `__WAN_IF__` / `__NAS_IP__` / `__GRE_DEV__` |

On the router:

```sh
NAS_IP=192.168.1.130 sh apply-tps-mirror.sh
```

WAN must be the **L3** device (`pppoe-wan` when using PPPoE, not the underlying ethernet).

## Bandwidth and MTU

Every WAN byte is copied again as GRE on the LAN toward the NAS. Outer GRE is larger than 1500; the kernel may fragment the outer packet. Inner frames on `tps0` should remain intact. Suricata `checksum-checks: no` on AF_PACKET because copies can fail offload checksums.

## Disable

Settings → General → **Listen on NAS LAN interfaces**, Apply. Capture returns to `ovs_eth0`. Or set `enabled=0` in `mirror.conf` and restart the package. On OpenWrt remove `/etc/nftables.d/10-tps-mirror.nft` and the `network.tpsmirror` UCI section.
