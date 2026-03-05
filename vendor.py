import json
import os
import re
import time
from typing import Dict, Optional

import requests

# ---------------------------
# Persistent vendor cache
# ---------------------------

CACHE_PATH = "vendor_cache.json"

def _load_persistent_cache() -> Dict[str, str]:
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    # normalize keys to lowercase
                    return {k.lower(): str(v) for k, v in data.items()}
        except Exception:
            pass
    return {}

def _save_persistent_cache(cache: Dict[str, str]) -> None:
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, sort_keys=True)
    except Exception:
        pass

_PERSIST_CACHE: Dict[str, str] = _load_persistent_cache()

# ---------------------------
# Local OUI file support (optional)
# ---------------------------

OUI_LINE_RE = re.compile(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$")

def _normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")

def oui_of(mac: str) -> str:
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

# ---------------------------
# Remote lookup (rate-limit safe)
# ---------------------------

# In-memory OUI cache to avoid repeated lookups within a run
_OUI_VENDOR_CACHE: Dict[str, str] = {}

# Cooldown if we get rate-limited (per OUI)
_OUI_COOLDOWN_UNTIL: Dict[str, float] = {}

def _vendor_lookup_remote_macvendors(probe_mac: str) -> str:
    """
    Uses macvendors.com. Note: it can rate-limit aggressively.
    It may return HTTP 200 with a JSON error body, so we detect that.
    """
    try:
        r = requests.get(f"https://api.macvendors.com/{probe_mac}", timeout=5)
        text = (r.text or "").strip()

        # Rate limit / error message (often JSON text)
        if "Please slow down your requests" in text or "Too Many" in text:
            return "RATE_LIMIT"

        if r.status_code == 200 and text:
            # If it looks like JSON, treat as unknown/error
            if text.startswith("{") and text.endswith("}"):
                return "Unknown"
            return text
    except Exception:
        pass

    return "Unknown"

def is_locally_administered(mac: str) -> bool:
    """
    Locally administered MAC = second least significant bit of first octet is 1.
    Often indicates randomized/private MAC (phones/laptops on Wi-Fi).
    """
    try:
        first_octet = int(_normalize_mac(mac).split(":")[0], 16)
        return (first_octet & 0b00000010) != 0
    except Exception:
        return False

def vendor_lookup(
    mac: str,
    local_oui_map: Optional[Dict[str, str]] = None,
    use_remote: bool = True,
) -> str:
    """
    Best-effort vendor lookup:
      1) Persistent cache (OUI -> vendor)
      2) Local OUI file (if provided)
      3) Remote lookup (rate-limit safe) once per OUI (cached)
      4) If still Unknown and locally administered -> label randomized

    Pass local_oui_map if you have one; otherwise it will skip local lookup.
    """
    mac = _normalize_mac(mac)
    o = oui_of(mac)
    if not o:
        return "Unknown"

    # 1) Persistent cache
    if o in _PERSIST_CACHE and _PERSIST_CACHE[o]:
        return _PERSIST_CACHE[o]

    # 2) Local OUI map (optional)
    if local_oui_map:
        v_local = local_oui_map.get(o, "Unknown")
        if v_local != "Unknown":
            _PERSIST_CACHE[o] = v_local
            _save_persistent_cache(_PERSIST_CACHE)
            return v_local

    # 3) Remote (optional)
    if use_remote:
        # In-memory cache
        if o in _OUI_VENDOR_CACHE:
            v = _OUI_VENDOR_CACHE[o]
        else:
            now = time.time()
            if _OUI_COOLDOWN_UNTIL.get(o, 0) > now:
                v = "Unknown"
            else:
                probe_mac = f"{o}:00:00:00"
                v = _vendor_lookup_remote_macvendors(probe_mac)

                if v == "RATE_LIMIT":
                    # cooldown for 10 minutes to stop hammering
                    _OUI_COOLDOWN_UNTIL[o] = now + 600
                    v = "Unknown"

            _OUI_VENDOR_CACHE[o] = v

        if v != "Unknown":
            _PERSIST_CACHE[o] = v
            _save_persistent_cache(_PERSIST_CACHE)
            return v

    # 4) Randomized label
    if is_locally_administered(mac):
        return "Randomized / Locally administered"

    return "Unknown"