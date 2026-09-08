# Official inputs (not in git)

`./build.sh` downloads the public SRM Threat Prevention SPK and extracts
the files packing needs into **`build/official/`**. You do not need to
populate this directory.

If you already unpacked an official SPK here (`package/ui/synoips.js`,
`package/etc/rules/`, `spk/PACKAGE_ICON.PNG`), `pack-spk.sh` will still
accept it as a fallback when `build/official/` is missing.

Synology copyright — do not commit `unpacked/package/` or `unpacked/spk/`.
