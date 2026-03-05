# Networks to scan (CIDR). Example: scan your /24
SCAN_CIDRS = ["192.168.0.0/24"]
SCAN_IFACE = "Realtek USB GbE Family Controller #3"

# Known/allowed devices by MAC (lowercase, colon-separated)
# Map MAC -> friendly name
KNOWN_DEVICES = {
    "aa:bb:cc:dd:ee:ff": "Core Switch",
    "11:22:33:44:55:66": "NAS",
}

# How often to rescan (seconds) when running continuous scans
SCAN_INTERVAL_SEC = 60

# Vendor lookup: choose "local" (OUI file) or "remote" (API)
VENDOR_LOOKUP_MODE = "remote"  # "remote" also supported

# If using local OUI file, path to file (download step below)
LOCAL_OUI_PATH = "oui.txt"

