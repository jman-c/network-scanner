from dataclasses import dataclass, asdict
from datetime import datetime
from threading import Lock
from typing import Dict, Optional

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

    def upsert(
        self,
        ip: str,
        mac: str,
        vendor: str,
        known: bool,
        friendly_name: Optional[str],
        hostname: Optional[str],
    ):
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        mac = mac.lower()

        with self._lock:
            if mac in self._devices:
                d = self._devices[mac]
                d.ip = ip
                d.vendor = vendor
                d.last_seen = now
                d.known = known
                d.friendly_name = friendly_name
                # Only update hostname if we got a non-empty value
                if hostname:
                    d.hostname = hostname
            else:
                self._devices[mac] = Device(
                    ip=ip,
                    mac=mac,
                    vendor=vendor,
                    hostname=hostname,
                    friendly_name=friendly_name,
                    first_seen=now,
                    last_seen=now,
                    known=known,
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