# Local inputs (not in git)

Packing (`./spk/pack-spk.sh`) needs a copy of the **official** Threat Prevention SPK
unpacked here. Synology copyright — do not commit this directory.

Expected layout:

```
unpacked/
  package/ui/synoips.js
  package/etc/rules/emerging.rules.tar.gz
  package/etc/rules/signature.conf
  package/etc/suricata/threshold.config
  spk/PACKAGE_ICON.PNG
  spk/PACKAGE_ICON_256.PNG
```

Place the tree yourself after clone. The community sources under `spk/src/` do not
include the official UI.
