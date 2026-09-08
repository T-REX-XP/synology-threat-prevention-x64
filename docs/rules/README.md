# Signature catalogs

Generated locally by `extract_rules.py` from the official Threat Prevention
ET Open tarball (`build/official/` or `unpacked/` after `./build.sh`).
**Not stored in git.**

```sh
python3 docs/rules/extract_rules.py
```

| File (gitignored) | Rows | Use |
| --- | --- | --- |
| `alerts-active.csv` | ~23k | Enabled signatures |
| `alerts-all.csv` | ~34k | Includes commented and deleted SIDs |
| `alerts-active.json` | ~23k | Compact JSON |
| `summary.json` | — | Aggregates (small; kept in git) |

Narrative review: [`../ThreatPrevention-bundled-signatures.md`](../ThreatPrevention-bundled-signatures.md).
