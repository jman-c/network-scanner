from datetime import datetime
from threading import Lock
from typing import Optional, List, Dict, Any

import config
from db import get_conn


class DeviceStore:
    def __init__(self, db_path: str = "net_scanner.db"):
        self._lock = Lock()
        self.db_path = db_path

    def has(self, mac: str) -> bool:
        mac = mac.lower()
        with self._lock, get_conn(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM devices WHERE mac = ? LIMIT 1",
                (mac,),
            ).fetchone()
            return row is not None

    def add_alert(self, alert: Dict[str, Any]) -> None:
        with self._lock, get_conn(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO alerts (
                    id, type, time, ip, mac, vendor, hostname, known, friendly_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.get("id"),
                alert.get("type"),
                alert.get("time"),
                alert.get("ip"),
                alert.get("mac"),
                alert.get("vendor"),
                alert.get("hostname"),
                1 if alert.get("known") else 0,
                alert.get("friendly_name"),
            ))

            conn.execute("""
                DELETE FROM alerts
                WHERE id NOT IN (
                    SELECT id FROM alerts
                    ORDER BY time DESC
                    LIMIT 200
                )
            """)

    def alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock, get_conn(self.db_path) as conn:
            rows = conn.execute("""
                SELECT id, type, time, ip, mac, vendor, hostname, known, friendly_name
                FROM alerts
                ORDER BY time DESC
                LIMIT ?
            """, (limit,)).fetchall()

            return [
                {
                    "id": r["id"],
                    "type": r["type"],
                    "time": r["time"],
                    "ip": r["ip"],
                    "mac": r["mac"],
                    "vendor": r["vendor"],
                    "hostname": r["hostname"],
                    "known": bool(r["known"]),
                    "friendly_name": r["friendly_name"],
                }
                for r in rows
            ]

    def dismiss_alert(self, alert_id: str) -> None:
        with self._lock, get_conn(self.db_path) as conn:
            conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))

    def clear_alerts(self) -> None:
        with self._lock, get_conn(self.db_path) as conn:
            conn.execute("DELETE FROM alerts")

    def upsert(
        self,
        ip: str,
        mac: str,
        vendor: Optional[str],
        known: bool,
        friendly_name: Optional[str],
        hostname: Optional[str],
    ) -> None:
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        mac = mac.lower()

        with self._lock, get_conn(self.db_path) as conn:
            existing = conn.execute("""
                SELECT vendor, hostname, friendly_name, first_seen
                FROM devices
                WHERE mac = ?
            """, (mac,)).fetchone()

            if existing:
                new_vendor = vendor if vendor is not None else existing["vendor"]
                new_hostname = hostname if hostname not in (None, "") else existing["hostname"]
                new_friendly = friendly_name if friendly_name not in (None, "") else existing["friendly_name"]

                conn.execute("""
                    UPDATE devices
                    SET ip = ?, vendor = ?, hostname = ?, friendly_name = ?, last_seen = ?, known = ?
                    WHERE mac = ?
                """, (
                    ip,
                    new_vendor or "Unknown",
                    new_hostname,
                    new_friendly,
                    now,
                    1 if known else 0,
                    mac,
                ))
            else:
                conn.execute("""
                    INSERT INTO devices (
                        mac, ip, vendor, hostname, friendly_name, first_seen, last_seen, known
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    mac,
                    ip,
                    vendor or "Unknown",
                    hostname,
                    friendly_name,
                    now,
                    now,
                    1 if known else 0,
                ))

    def all(self) -> List[Dict[str, Any]]:
        with self._lock, get_conn(self.db_path) as conn:
            rows = conn.execute("""
                SELECT ip, mac, vendor, hostname, friendly_name, first_seen, last_seen, known
                FROM devices
                ORDER BY last_seen DESC, mac ASC
            """).fetchall()

            devices = []
            now = datetime.utcnow()
            offline_threshold = config.SCAN_INTERVAL_SEC * 2

            for r in rows:
                last_seen = r["last_seen"]
                status = "unknown"

                if last_seen:
                    try:
                        last = datetime.fromisoformat(last_seen.replace("Z", ""))
                        delta = (now - last).total_seconds()
                        status = "online" if delta <= offline_threshold else "offline"
                    except Exception:
                        status = "unknown"

                devices.append({
                    "ip": r["ip"],
                    "mac": r["mac"],
                    "vendor": r["vendor"],
                    "hostname": r["hostname"],
                    "friendly_name": r["friendly_name"],
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                    "known": bool(r["known"]),
                    "status": status,
                })

            return devices

    def summary(self) -> Dict[str, int]:
        with self._lock, get_conn(self.db_path) as conn:
            row = conn.execute("""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN known = 1 THEN 1 ELSE 0 END) AS known,
                    SUM(CASE WHEN known = 0 THEN 1 ELSE 0 END) AS unknown
                FROM devices
            """).fetchone()

            return {
                "total": int(row["total"] or 0),
                "known": int(row["known"] or 0),
                "unknown": int(row["unknown"] or 0),
            }