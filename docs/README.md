# Documentation

Operator and research notes for the community DSM 7 Threat Prevention PoC (vanilla Suricata 8 + official ExtJS UI). Not a product.

## Operator

| Doc | When to read it |
| --- | --- |
| [spk-deploy-and-update.md](spk-deploy-and-update.md) | Install, `setcap`, upgrade, uninstall, capture pin |
| [router-traffic-copy.md](router-traffic-copy.md) | OpenWrt GRE or MikroTik TZSP copy of LAN↔WAN onto NAS `tps0` (IDS) |
| [hw-acceleration.md](hw-acceleration.md) | Intel Hyperscan default; DPDK / NIC offload not wired |
| [google-maps.md](google-maps.md) | Overview map / GeoIP (optional) |

On an installed NAS, the same router steps ship in:

- DSM Help → **This NAS (Suricata IDS)** (setcap, capture source, Hyperscan) and **Router traffic copy**
- `/var/packages/ThreatPrevention/target/etc/openwrt/README.txt` (OpenWrt)
- `/var/packages/ThreatPrevention/target/etc/mikrotik/README.txt` (MikroTik)

## Internals

| Doc | Topic |
| --- | --- |
| [dsm-extjs-sdk.md](dsm-extjs-sdk.md) | DSM 7 ExtJS load path, `ui/config`, Help indexer |
| [backend-replaceability.md](backend-replaceability.md) | What is official vs community |
| [ootb-ui-compat-review.md](ootb-ui-compat-review.md) | Shim layers on `synoips.js` |
| [api/SYNO.TPS.contract.md](api/SYNO.TPS.contract.md) | `SYNO.TPS.*` envelopes |
| [api/official-app-surface.md](api/official-app-surface.md) | What the official app calls |
| [api/backend-port-backlog.md](api/backend-port-backlog.md) | Remaining API gaps |
| [native-app-plan.md](native-app-plan.md) | Pack layout / Start Menu app |
| [spk-repack-evaluation.md](spk-repack-evaluation.md) | SPK packaging notes |
| [x64-dsm-migration-plan.md](x64-dsm-migration-plan.md) | aarch64 SRM → x86_64 DSM |

## Official SRM package (research only)

| Doc | Topic |
| --- | --- |
| [ThreatPrevention-1.3.3-0926-package-review.md](ThreatPrevention-1.3.3-0926-package-review.md) | Unpacked official SPK |
| [ThreatPrevention-bundled-signatures.md](ThreatPrevention-bundled-signatures.md) | Bundled ET dump |
| [rules/README.md](rules/README.md) | Rule extracts |

Do not publish official `synoips.js`, texts, or help as a community product. The extra DSM Help pages in this repo (`threatprevention_dsm.html`, `threatprevention_router.html`) are community-written.
