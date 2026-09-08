# Hardware acceleration (Intel)

This x86_64 Suricata 8 build can use **Intel Hyperscan** for signature matching. **DPDK** and **NIC flow offload** are documented here but are **not wired** — capture stays AF_PACKET (IDS).

Default policy: **Hyperscan on** when `suricata --build-info` reports Hyperscan support.

On an installed NAS: Settings → General → **Hardware acceleration**, and DSM Help → **This NAS (Suricata IDS)**.

```
packet → AF_PACKET (ovs_eth0 | tps0)
              │
              ▼
     detect mpm/spm  →  Hyperscan (hs)  or  ac / bmh
              │
              ▼
         eve.json alerts
```

## Intel Hyperscan (wired)

High-performance multi-pattern and regex matching using SIMD (AVX2 / AVX-512). Suricata uses it as:

- `mpm-algo: hs` — Multi-Pattern Matching
- `spm-algo: hs` — Single-Pattern Matching

This is the default. Confirm the binary:

```sh
/var/packages/ThreatPrevention/target/bin/suricata --build-info | grep -i hyperscan
# Hyperscan support: yes
```

### Settings

Settings → General → **Hardware acceleration** → **Intel Hyperscan (MPM / SPM)**. Apply rewrites `detect.mpm-algo` / `detect.spm-algo` and restarts Suricata.

Shipped files:

| Path | Role |
| --- | --- |
| `/var/packages/ThreatPrevention/etc/accel.conf` | `hyperscan=1` (default) |
| `target/etc/suricata/suricata.yaml` | `detect.mpm-algo` / `spm-algo` |
| `start-stop-status` | `--set detect.mpm-algo=…` on every start |

If Hyperscan is missing from the binary, the engine falls back to `ac` / `bmh` so it still starts.

To turn it off: uncheck the box, Apply. Matching uses Aho-Corasick / Boyer-Moore.

## Intel DPDK (not wired)

Userspace packet I/O that bypasses the Linux kernel (Intel X710, E810, …). Suricata can use DPDK, but this package does **not**: DSM OVS, unsigned-package privileges, hugepages, and VFIO are out of scope. Capture remains AF_PACKET. The Settings checkbox stays disabled.

## NIC hardware flow offload (not wired)

`rte_flow` / SR-IOV prefilter on the NIC (skip TLS or trusted flows before Suricata). Not implemented. Do not enable hardware bypass of IDS inspection on this package.

## Verify

```sh
grep -E "mpm-algo|spm-algo" /var/packages/ThreatPrevention/target/etc/suricata/suricata.yaml
grep hyperscan /var/packages/ThreatPrevention/etc/accel.conf
grep -E "Hyperscan|mpm" /var/packages/ThreatPrevention/var/log/suricata.log | tail
```

Engine start logs the chosen MPM when log level allows it. After Apply, `accel.conf` should show `hyperscan=1` and yaml `mpm-algo: hs`.
