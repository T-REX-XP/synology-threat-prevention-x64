"""Commands for the packaged Suricata 8 socket client."""
import json
import subprocess

from paths import SURICATA_SOCKET, SURICATASC


def command_ok(command, timeout=60):
    try:
        response = subprocess.run(
            [SURICATASC, "-c", command, SURICATA_SOCKET],
            capture_output=True, timeout=timeout, check=True,
        )
        return json.loads(response.stdout).get("return") == "OK"
    except (OSError, subprocess.SubprocessError, ValueError, AttributeError):
        return False
