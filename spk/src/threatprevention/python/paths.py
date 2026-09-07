"""Package paths. Override with env for local tests."""
import os

PKGDEST = os.environ.get("TPS_PKGDEST", "/var/packages/ThreatPrevention/target")
PKGVAR = os.environ.get("TPS_PKGVAR", "/var/packages/ThreatPrevention/var")
PKGETC = os.environ.get("TPS_PKGETC", "/var/packages/ThreatPrevention/etc")
DB_PATH = os.path.join(PKGVAR, "tps.db")
EVE_PATH = os.path.join(PKGVAR, "log", "eve.json")
RULES_OUT = os.path.join(PKGVAR, "rules", "suricata.rules")
SOCK_PATH = os.path.join(PKGVAR, "tpsweb.sock")
INGEST_PID = os.path.join(PKGVAR, "ingest.pid")
TPSWEB_PID = os.path.join(PKGVAR, "tpsweb.pid")
SURICATA_PID = os.path.join(PKGVAR, "suricata.pid")
SENSOR_CONF = os.path.join(PKGETC, "sensor.conf")
IFACE_FILE = os.path.join(PKGETC, "interface")
SIGNATURE_CONF = os.path.join(PKGDEST, "etc", "rules", "signature.conf")
CLASSIFICATION = os.path.join(PKGDEST, "etc", "rules", "classification.config")
YAML_PATH = os.path.join(PKGDEST, "etc", "suricata", "suricata.yaml")
UPDATE_SCRIPT = os.path.join(PKGDEST, "scripts", "update-rules.sh")
if not os.path.isfile(UPDATE_SCRIPT):
    UPDATE_SCRIPT = "/var/packages/ThreatPrevention/scripts/update-rules.sh"
SURICATASC = os.path.join(PKGDEST, "bin", "suricatasc")
SURICATA_SOCKET = os.path.join(PKGVAR, "suricata.socket")
TPSWEB_PORT = int(os.environ.get("TPS_PORT", "19557"))
EXPORT_DIR = os.path.join(PKGVAR, "export")
