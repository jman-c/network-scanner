# Networks to scan (CIDR). Example: scan your /24
SCAN_CIDRS = ["192.168.0.0/24"]
SCAN_IFACE = "Realtek USB GbE Family Controller #3"

# Known/allowed devices by MAC (lowercase, colon-separated)
# Map MAC -> friendly name
KNOWN_DEVICES = {}

# How often to rescan (seconds) when running continuous scans
SCAN_INTERVAL_SEC = 60

# If using local OUI file, path to file (download step below)
LOCAL_OUI_PATH = "oui.txt"

# Monitoring
ALERT_ON_NEW_DEVICE = True
ALERT_WEBHOOK_URL = ""  # optional, e.g. Discord/Slack webhook

