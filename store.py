from dataclasses import dataclass, asdict
from datetime import datetime
from threading import Lock
from typing import Dict, Optional

@dataclass
class Device:
    ip: str
    mac: str
    vendor: str
    first_seen: str
    last_seen: str
    known: bool
    name: Optional[str] = None

class DeviceStore:
    def __init__(self):
        self._lock = Lock()
        self._devices: Dict[str, Device] = {}  # key by MAC

    def upsert(self, ip: str, mac: str, vendor: str, known: bool, name: Optional[str]):
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        mac = mac.lower()
        with self._lock:
            if mac in self._devices:
                d = self._devices[mac]
                d.ip = ip
                d.vendor = vendor
                d.last_seen = now
                d.known = known
                d.name = name
            else:
                self._devices[mac] = Device(
                    ip=ip,
                    mac=mac,
                    vendor=vendor,
                    first_seen=now,
                    last_seen=now,
                    known=known,
                    name=name,
                )

    def all(self):
        with self._lock:
            return [asdict(d) for d in self._devices.values()]

    def summary(self):
        rows = self.all()
        total = len(rows)
        unknown = sum(1 for r in rows if not r["known"])
        known = total - unknown
        return {"total": total, "known": known, "unknown": unknown}