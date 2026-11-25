"""Commands for the packaged Suricata 8 socket client."""
import json
import subprocess

from paths import SURICATA_SOCKET, SURICATASC


def command_result(command, timeout=60):
    """Return success and Suricata's reply or a diagnostic."""
    try:
        response = subprocess.run(
            [SURICATASC, "-c", command, SURICATA_SOCKET],
            capture_output=True, timeout=timeout,
        )
        if response.returncode:
            detail = response.stderr.decode("utf-8", "replace").strip()
            return False, detail or "socket client exit %d" % response.returncode
        data = json.loads(response.stdout)
        if isinstance(data, dict) and data.get("return") in ("OK", "NOK"):
            return data["return"] == "OK", data.get("message")
    except subprocess.TimeoutExpired:
        return False, "socket command timed out after %s seconds" % timeout
    except OSError as exc:
        return False, str(exc)
    except ValueError:
        pass
    return False, "invalid response from the Suricata socket client"


def command_ok(command, timeout=60):
    return command_result(command, timeout)[0]
