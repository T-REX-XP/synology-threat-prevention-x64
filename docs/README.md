# Documentation

Operator and internals for this DSM 7 Threat Prevention PoC. Start with the [root README](../README.md).

## Operator

| Doc | When to read it |
| --- | --- |
| [spk-deploy-and-update.md](spk-deploy-and-update.md) | Install, `setcap`, upgrade, uninstall |
| [hw-acceleration.md](hw-acceleration.md) | Intel Hyperscan default; DPDK / NIC offload not wired |
| [google-maps.md](google-maps.md) | Overview map / GeoIP (optional) |

On an installed NAS: DSM Help → **This NAS (Suricata IDS)**.

## Internals

| Doc | Topic |
| --- | --- |
| [backend-replaceability.md](backend-replaceability.md) | Official vs community backend |
| [ootb-ui-compat-review.md](ootb-ui-compat-review.md) | Bridge / shim on `synoips.js` |
| [dsm-extjs-sdk.md](dsm-extjs-sdk.md) | DSM 7 ExtJS load path, Help indexer |
| [api/SYNO.TPS.contract.md](api/SYNO.TPS.contract.md) | `SYNO.TPS.*` envelopes |
| [api/official-app-surface.md](api/official-app-surface.md) | What the official app calls |
| [api/backend-port-backlog.md](api/backend-port-backlog.md) | Remaining API gaps |
| [native-app-plan.md](native-app-plan.md) | Pack layout / Start Menu app |
| [spk-repack-evaluation.md](spk-repack-evaluation.md) | SPK packaging notes |
| [x64-dsm-migration-plan.md](x64-dsm-migration-plan.md) | aarch64 SRM → x86_64 DSM |

## Research (official SRM SPK)

Notes on the original `ThreatPrevention-1.3.3-0926` tree. That tree is **not** in git.

| Doc | Topic |
| --- | --- |
| [ThreatPrevention-1.3.3-0926-package-review.md](ThreatPrevention-1.3.3-0926-package-review.md) | Unpacked official SPK |
| [ThreatPrevention-bundled-signatures.md](ThreatPrevention-bundled-signatures.md) | Bundled ET dump |
| [rules/README.md](rules/README.md) | Rule extracts |

Do not publish official `synoips.js`, texts, or help. The extra DSM Help page (`threatprevention_dsm.html`) is community-written.
