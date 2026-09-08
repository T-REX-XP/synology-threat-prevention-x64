"""Intel Hyperscan / acceleration policy. DPDK and NIC offload are not wired."""
import os
import re
import subprocess

from paths import ACCEL_CONF, PKGDEST, PKGETC, SURICATA_BIN, YAML_PATH

_HS_CACHE = None

_DETECT_BLOCK = (
    "detect:\n"
    "  profile: medium\n"
    "  mpm-algo: %s\n"
    "  spm-algo: %s\n"
)


def _truth(v, default=False):
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def ensure_accel_conf():
    os.makedirs(PKGETC, exist_ok=True)
    if os.path.isfile(ACCEL_CONF):
        return
    src = os.path.join(PKGDEST, "etc", "accel.conf")
    if os.path.isfile(src):
        try:
            with open(src, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            with open(ACCEL_CONF, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.chmod(ACCEL_CONF, 0o644)
        except OSError:
            pass


def read_accel_conf():
    ensure_accel_conf()
    out = {"hyperscan": True, "dpdk": False, "nic_offload": False}
    if not os.path.isfile(ACCEL_CONF):
        return out
    try:
        lines = open(ACCEL_CONF, encoding="utf-8", errors="replace")
    except OSError:
        return out
    with lines as fh:
        for line in fh:
            if "=" not in line or line.strip().startswith("#"):
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            if k == "hyperscan":
                out["hyperscan"] = _truth(v, True)
            elif k == "dpdk":
                out["dpdk"] = False
            elif k == "nic_offload":
                out["nic_offload"] = False
    return out


def write_accel_conf(data):
    os.makedirs(PKGETC, exist_ok=True)
    hs = _truth((data or {}).get("hyperscan"), True)
    lines = [
        "# Intel Hyperscan MPM/SPM. DPDK and NIC offload are not wired.",
        "hyperscan=%s" % ("1" if hs else "0"),
        "dpdk=0",
        "nic_offload=0",
    ]
    with open(ACCEL_CONF, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    try:
        os.chmod(ACCEL_CONF, 0o644)
    except OSError:
        pass
    return hs


def hyperscan_available(force=False):
    global _HS_CACHE
    if _HS_CACHE is not None and not force:
        return _HS_CACHE
    if not os.path.isfile(SURICATA_BIN):
        _HS_CACHE = False
        return False
    try:
        out = subprocess.check_output(
            [SURICATA_BIN, "--build-info"],
            stderr=subprocess.STDOUT,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        _HS_CACHE = False
        return False
    text = out.decode("utf-8", "replace")
    found = False
    for line in text.splitlines():
        if "hyperscan" not in line.lower():
            continue
        found = True
        low = line.lower()
        _HS_CACHE = "yes" in low and "no" not in low.split(":", 1)[-1]
        return _HS_CACHE
    _HS_CACHE = found
    return _HS_CACHE


def effective_algos(conf=None):
    """Return (mpm, spm, hyperscan_active). Fall back to ac/bmh if hs is missing."""
    conf = conf or read_accel_conf()
    want = bool(conf.get("hyperscan"))
    avail = hyperscan_available()
    active = bool(want and avail)
    if active:
        return "hs", "hs", True
    return "ac", "bmh", False


def apply_detect_algos(text, mpm, spm):
    text = text or ""
    mpm = mpm or "ac"
    spm = spm or "bmh"

    def replace_key(blob, key, value):
        pat = re.compile(r"^([ \t]*)" + re.escape(key) + r":[^\n]*$", re.M)
        if pat.search(blob):
            return pat.sub(r"\1%s: %s" % (key, value), blob, count=1)
        return blob

    text = replace_key(text, "mpm-algo", mpm)
    text = replace_key(text, "spm-algo", spm)
    if re.search(r"^([ \t]*)mpm-algo:", text, re.M) and not re.search(r"^([ \t]*)spm-algo:", text, re.M):
        text = re.sub(
            r"^([ \t]*)mpm-algo:[^\n]*$",
            lambda m: m.group(0) + "\n" + m.group(1) + "spm-algo: %s" % spm,
            text, count=1, flags=re.M,
        )
    if re.search(r"^([ \t]*)mpm-algo:", text, re.M) and re.search(r"^([ \t]*)spm-algo:", text, re.M):
        return text
    block = _DETECT_BLOCK % (mpm, spm)
    if re.search(r"^detect:\s*$", text, re.M):
        return re.sub(r"^detect:\s*$", block.rstrip(), text, count=1, flags=re.M)
    return text.rstrip() + "\n\n" + block


def apply_accel_yaml(mpm=None, spm=None):
    if mpm is None or spm is None:
        mpm, spm, _active = effective_algos()
    path = YAML_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        text = open(path, encoding="utf-8", errors="replace").read() if os.path.isfile(path) else ""
    except OSError:
        text = ""
    new = apply_detect_algos(text, mpm, spm)
    if new == text and os.path.isfile(path):
        return mpm, spm
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new)
    return mpm, spm


def accel_cli_sets():
    mpm, spm, _active = effective_algos()
    return ["--set", "detect.mpm-algo=" + mpm, "--set", "detect.spm-algo=" + spm]


def accel_status():
    conf = read_accel_conf()
    mpm, spm, active = effective_algos(conf)
    avail = hyperscan_available()
    return {
        "hyperscan": bool(conf.get("hyperscan")),
        "hyperscan_available": avail,
        "hyperscan_active": active,
        "mpm_algo": mpm,
        "spm_algo": spm,
        "dpdk": False,
        "dpdk_available": False,
        "nic_offload": False,
        "nic_offload_available": False,
    }
