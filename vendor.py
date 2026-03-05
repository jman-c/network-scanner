import re
import time
from typing import Dict
import requests

OUI_LINE_RE = re.compile(
    r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$"
)


def _normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def oui_of(mac: str) -> str:
    """
    Return the first 3 bytes of a MAC address as an OUI (aa:bb:cc).
    """
    mac = _normalize_mac(mac)
    parts = mac.split(":")
    if len(parts) < 3:
        return ""
    return ":".join(parts[:3])


def load_oui_file(path: str) -> Dict[str, str]:
    """
    Parses IEEE oui.txt format lines like:
      FC-34-97   (hex)        Cisco Systems, Inc
    Returns mapping "fc:34:97" -> "Cisco Systems, Inc"
    """
    mapping: Dict[str, str] = {}

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = OUI_LINE_RE.match(line.strip())
                if m:
                    oui_dash = m.group(1).lower()
                    vendor = m.group(2).strip()
                    mapping[oui_dash.replace("-", ":")] = vendor
    except FileNotFoundError:
        pass

    return mapping


def vendor_lookup_local(mac: str, oui_map: Dict[str, str]) -> str:
    return oui_map.get(oui_of(mac), "Unknown")


# ---------------------------------------------------
# Remote lookup system
# ---------------------------------------------------

# Cache results by OUI to prevent API spam
_OUI_VENDOR_CACHE: Dict[str, str] = {}

# Cooldown tracking if API rate limits us
_OUI_COOLDOWN_UNTIL: Dict[str, float] = {}


def vendor_lookup_remote(mac: str) -> str:
    """
    Vendor lookup using macvendors.com
    with caching + cooldown to avoid rate limits.
    """

    mac = _normalize_mac(mac)
    o = oui_of(mac)

    if not o:
        return "Unknown"

    # Return cached result if available
    if o in _OUI_VENDOR_CACHE:
        return _OUI_VENDOR_CACHE[o]

    # Respect cooldown if previously rate-limited
    now = time.time()
    if _OUI_COOLDOWN_UNTIL.get(o, 0) > now:
        return "Unknown"

    probe_mac = f"{o}:00:00:00"

    try:
        r = requests.get(
            f"https://api.macvendors.com/{probe_mac}",
            timeout=5
        )

        text = (r.text or "").strip()

        # macvendors returns JSON error when rate limited
        if "Please slow down your requests" in text or "Too Many" in text:
            _OUI_COOLDOWN_UNTIL[o] = now + 600  # 10 minute cooldown
            return "Unknown"

        if r.status_code == 200 and text:

            # If response looks like JSON error
            if text.startswith("{") and text.endswith("}"):
                vendor = "Unknown"
            else:
                vendor = text

            _OUI_VENDOR_CACHE[o] = vendor
            return vendor

    except Exception:
        pass

    _OUI_VENDOR_CACHE[o] = "Unknown"
    return "Unknown"


def is_locally_administered(mac: str) -> bool:
    """
    Detect locally administered MAC addresses
    (often randomized for privacy).
    """
    try:
        first_octet = int(_normalize_mac(mac).split(":")[0], 16)
        return (first_octet & 0b00000010) != 0
    except Exception:
        return False


def vendor_lookup(mac: str) -> str:
    """
    Best-effort vendor lookup.

    Steps:
    1. Check OUI cache
    2. Remote lookup
    3. If unknown + locally administered -> label randomized
    """

    vendor = vendor_lookup_remote(mac)

    if vendor == "Unknown" and is_locally_administered(mac):
        return "Randomized / Locally administered"

    return vendor