"""Local diagnostics for update and capture operations."""
import os
import re
import sys
import time

from paths import PKGVAR


OPERATIONS_LOG = os.path.join(PKGVAR, "log", "operations.log")


def log_operation(component, message):
    # Rule validators and feed tools can include a private URL in an error.
    detail = re.sub(r"https?://[^\s\x22<>]+", "[URL]", str(message), flags=re.I)
    detail = " | ".join(line.strip() for line in detail.splitlines() if line.strip())[-8192:]
    line = "%s [%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), component, detail)
    try:
        os.makedirs(os.path.dirname(OPERATIONS_LOG), exist_ok=True)
        with open(OPERATIONS_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        sys.stderr.write(line)


def log_tail(path, limit=3072):
    try:
        with open(path, "rb") as fh:
            size = fh.seek(0, os.SEEK_END)
            fh.seek(max(0, size - limit))
            return fh.read(limit).decode("utf-8", "replace").strip()
    except OSError:
        return ""
