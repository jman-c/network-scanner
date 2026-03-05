from dataclasses import dataclass, asdict
from datetime import datetime
from threading import Lock
from typing import Dict, Optional, List, Any

@dataclass
class Device:
    ip: str
    mac: str
    vendor: str
    hostname: Optional[str]
    friendly_name: Optional[str]
    first_seen: str
    last_seen: str
    known: bool

class DeviceStore:
    def __init__(self):
        self._lock = Lock()
        self._devices: Dict[str, Device] = {}  # key by MAC

    def has(self, mac: str) -> bool:
        mac = mac.lower()
        with self._lock:
            return mac in self._devices

    def get(self, mac: str) -> Optional[Dict[str, Any]]:
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            return None if d is None else asdict(d)

    def upsert(
        self,
        ip: str,
        mac: str,
        vendor: Optional[str],
        known: bool,
        friendly_name: Optional[str],
        hostname: Optional[str],
    ):
        """
        Upsert by MAC. If vendor/hostname is None, keep existing value.
        """
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        mac = mac.lower()

        with self._lock:
            if mac in self._devices:
                d = self._devices[mac]
                d.ip = ip
                d.last_seen = now
                d.known = known

                if vendor is not None:
                    d.vendor = vendor

                if hostname is not None and hostname != "":
                    d.hostname = hostname

                if friendly_name is not None and friendly_name != "":
                    d.friendly_name = friendly_name
            else:
                self._devices[mac] = Device(
                    ip=ip,
                    mac=mac,
                    vendor=vendor or "Unknown",
                    hostname=hostname,
                    friendly_name=friendly_name,
                    first_seen=now,
                    last_seen=now,
                    known=known,
                )

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [asdict(d) for d in self._devices.values()]

    def summary(self) -> Dict[str, int]:
        rows = self.all()
        total = len(rows)
        unknown = sum(1 for r in rows if not r["known"])
        known = total - unknown
        return {"total": total, "known": known, "unknown": unknown}