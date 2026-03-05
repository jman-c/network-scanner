import re
from functools import lru_cache
from typing import Dict, Optional
import requests

OUI_LINE_RE = re.compile(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$")

def _normalize_oui(mac: str) -> str:
    mac = mac.lower().replace("-", ":")
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
        # If file missing, caller can still run but vendor will be "Unknown"
        pass
    return mapping

@lru_cache(maxsize=1)
def _remote_vendor_cache():
    return {}

def vendor_lookup_local(mac: str, oui_map: Dict[str, str]) -> str:
    oui = _normalize_oui(mac)
    return oui_map.get(oui, "Unknown")

def vendor_lookup_remote(mac: str) -> str:
    """
    Remote vendor lookup using macvendors.com (simple and popular).
    Note: depends on external service availability.
    """
    mac = mac.lower()
    cache = _remote_vendor_cache()
    if mac in cache:
        return cache[mac]
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if r.status_code == 200 and r.text.strip():
            cache[mac] = r.text.strip()
        else:
            cache[mac] = "Unknown"
    except Exception:
        cache[mac] = "Unknown"
    return cache[mac]