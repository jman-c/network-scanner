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
        self._alerts: List[Dict[str, Any]] = []
        self._max_alerts = 200

    def has(self, mac: str) -> bool:
        mac = mac.lower()
        with self._lock:
            return mac in self._devices

    def add_alert(self, alert: Dict[str, Any]) -> None:
        with self._lock:
            self._alerts.insert(0, alert)
            if len(self._alerts) > self._max_alerts:
                self._alerts = self._alerts[: self._max_alerts]

    def alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._alerts[:limit])

    def dismiss_alert(self, alert_id: str) -> None:
        with self._lock:
            self._alerts = [a for a in self._alerts if a.get("id") != alert_id]

    def clear_alerts(self) -> None:
        with self._lock:
            self._alerts = []

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