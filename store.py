from datetime import datetime
from threading import Lock
from typing import Optional, List, Dict, Any

import config
from db import get_conn


def _parse_utc(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", ""))
    except Exception:
        return None


def _utc_now_str() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))

    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)

    if days > 0:
        return f"{days}d {hours}h"
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


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

    def add_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        ts = _utc_now_str()

        with self._lock, get_conn(self.db_path) as conn:
            conn.execute("""
                INSERT INTO device_events (
                    mac, event_type, event_time, ip, vendor, hostname, known, friendly_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                (payload.get("mac") or "").lower(),
                event_type,
                ts,
                payload.get("ip"),
                payload.get("vendor"),
                payload.get("hostname"),
                1 if payload.get("known") else 0,
                payload.get("friendly_name"),
            ))

    def get_device_events(self, mac: str, limit: int = 50) -> List[Dict[str, Any]]:
        mac = mac.lower()

        with self._lock, get_conn(self.db_path) as conn:
            rows = conn.execute("""
                SELECT id, mac, event_type, event_time, ip, vendor, hostname, known, friendly_name
                FROM device_events
                WHERE mac = ?
                ORDER BY event_time DESC, id DESC
                LIMIT ?
            """, (mac, limit)).fetchall()

            return [
                {
                    "id": r["id"],
                    "mac": r["mac"],
                    "event_type": r["event_type"],
                    "event_time": r["event_time"],
                    "ip": r["ip"],
                    "vendor": r["vendor"],
                    "hostname": r["hostname"],
                    "known": bool(r["known"]),
                    "friendly_name": r["friendly_name"],
                }
                for r in rows
            ]

    def start_session(self, payload: Dict[str, Any], started_at: Optional[str] = None) -> None:
        started_at = started_at or _utc_now_str()
        mac = (payload.get("mac") or "").lower()
        if not mac:
            return

        with self._lock, get_conn(self.db_path) as conn:
            active = conn.execute("""
                SELECT id FROM device_sessions
                WHERE mac = ? AND is_active = 1
                ORDER BY id DESC
                LIMIT 1
            """, (mac,)).fetchone()

            if active:
                return

            conn.execute("""
                INSERT INTO device_sessions (
                    mac, started_at, ended_at, duration_sec, start_ip, end_ip,
                    vendor, hostname, known, friendly_name, is_active
                ) VALUES (?, ?, NULL, NULL, ?, NULL, ?, ?, ?, ?, 1)
            """, (
                mac,
                started_at,
                payload.get("ip"),
                payload.get("vendor"),
                payload.get("hostname"),
                1 if payload.get("known") else 0,
                payload.get("friendly_name"),
            ))

    def end_session(self, payload: Dict[str, Any], ended_at: Optional[str] = None) -> None:
        ended_at = ended_at or _utc_now_str()
        mac = (payload.get("mac") or "").lower()
        if not mac:
            return

        with self._lock, get_conn(self.db_path) as conn:
            active = conn.execute("""
                SELECT id, started_at
                FROM device_sessions
                WHERE mac = ? AND is_active = 1
                ORDER BY id DESC
                LIMIT 1
            """, (mac,)).fetchone()

            if not active:
                return

            started = _parse_utc(active["started_at"])
            ended = _parse_utc(ended_at)
            duration_sec = None
            if started and ended:
                duration_sec = max(0, int((ended - started).total_seconds()))

            conn.execute("""
                UPDATE device_sessions
                SET ended_at = ?, duration_sec = ?, end_ip = ?, is_active = 0
                WHERE id = ?
            """, (
                ended_at,
                duration_sec,
                payload.get("ip"),
                active["id"],
            ))

    def get_device_sessions(self, mac: str, limit: int = 50) -> List[Dict[str, Any]]:
        mac = mac.lower()

        with self._lock, get_conn(self.db_path) as conn:
            rows = conn.execute("""
                SELECT
                    id, mac, started_at, ended_at, duration_sec,
                    start_ip, end_ip, vendor, hostname, known, friendly_name, is_active
                FROM device_sessions
                WHERE mac = ?
                ORDER BY started_at DESC, id DESC
                LIMIT ?
            """, (mac, limit)).fetchall()

            sessions = []
            now = datetime.utcnow()

            for r in rows:
                duration_sec = r["duration_sec"]
                if r["is_active"]:
                    started = _parse_utc(r["started_at"])
                    if started:
                        duration_sec = max(0, int((now - started).total_seconds()))

                sessions.append({
                    "id": r["id"],
                    "mac": r["mac"],
                    "started_at": r["started_at"],
                    "ended_at": r["ended_at"],
                    "duration_sec": duration_sec,
                    "duration_human": _format_duration(duration_sec or 0) if duration_sec is not None else "",
                    "start_ip": r["start_ip"],
                    "end_ip": r["end_ip"],
                    "vendor": r["vendor"],
                    "hostname": r["hostname"],
                    "known": bool(r["known"]),
                    "friendly_name": r["friendly_name"],
                    "is_active": bool(r["is_active"]),
                })

            return sessions

    def get_device_session_stats(self, mac: str) -> Dict[str, Any]:
        mac = mac.lower()

        with self._lock, get_conn(self.db_path) as conn:
            rows = conn.execute("""
                SELECT started_at, ended_at, duration_sec, is_active
                FROM device_sessions
                WHERE mac = ?
                ORDER BY started_at DESC
            """, (mac,)).fetchall()

            now = datetime.utcnow()
            total_sessions = len(rows)
            completed_sessions = 0
            total_uptime_sec = 0
            longest_session_sec = 0
            active_session_started_at = None

            for r in rows:
                if r["is_active"]:
                    active_session_started_at = r["started_at"]
                    started = _parse_utc(r["started_at"])
                    if started:
                        dur = max(0, int((now - started).total_seconds()))
                    else:
                        dur = 0
                else:
                    completed_sessions += 1
                    dur = int(r["duration_sec"] or 0)

                total_uptime_sec += dur
                longest_session_sec = max(longest_session_sec, dur)

            avg_session_sec = int(total_uptime_sec / total_sessions) if total_sessions > 0 else 0

            return {
                "total_sessions": total_sessions,
                "completed_sessions": completed_sessions,
                "total_uptime_sec": total_uptime_sec,
                "total_uptime_human": _format_duration(total_uptime_sec) if total_uptime_sec > 0 else "",
                "avg_session_sec": avg_session_sec,
                "avg_session_human": _format_duration(avg_session_sec) if avg_session_sec > 0 else "",
                "longest_session_sec": longest_session_sec,
                "longest_session_human": _format_duration(longest_session_sec) if longest_session_sec > 0 else "",
                "active_session_started_at": active_session_started_at,
            }

    def upsert(
        self,
        ip: str,
        mac: str,
        vendor: Optional[str],
        known: bool,
        friendly_name: Optional[str],
        hostname: Optional[str],
    ) -> None:
        now = _utc_now_str()
        mac = mac.lower()

        event_to_add: Optional[Dict[str, Any]] = None
        session_to_start: Optional[Dict[str, Any]] = None

        with self._lock, get_conn(self.db_path) as conn:
            existing = conn.execute("""
                SELECT vendor, hostname, friendly_name, status, online_since
                FROM devices
                WHERE mac = ?
            """, (mac,)).fetchone()

            if existing:
                new_vendor = vendor if vendor is not None else existing["vendor"]
                new_hostname = hostname if hostname not in (None, "") else existing["hostname"]
                new_friendly = friendly_name if friendly_name not in (None, "") else existing["friendly_name"]

                previous_status = (existing["status"] or "unknown").lower()
                if previous_status == "online" and existing["online_since"]:
                    online_since = existing["online_since"]
                else:
                    online_since = now

                conn.execute("""
                    UPDATE devices
                    SET ip = ?, vendor = ?, hostname = ?, friendly_name = ?, last_seen = ?, known = ?, status = ?, online_since = ?
                    WHERE mac = ?
                """, (
                    ip,
                    new_vendor or "Unknown",
                    new_hostname,
                    new_friendly,
                    now,
                    1 if known else 0,
                    "online",
                    online_since,
                    mac,
                ))

                if previous_status == "offline":
                    payload = {
                        "mac": mac,
                        "ip": ip,
                        "vendor": new_vendor or "Unknown",
                        "hostname": new_hostname,
                        "known": known,
                        "friendly_name": new_friendly,
                    }
                    event_to_add = {
                        **payload,
                        "event_type": "device_online",
                    }
                    session_to_start = payload

            else:
                conn.execute("""
                    INSERT INTO devices (
                        mac, ip, vendor, hostname, friendly_name, first_seen, last_seen, known, status, online_since
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    mac,
                    ip,
                    vendor or "Unknown",
                    hostname,
                    friendly_name,
                    now,
                    now,
                    1 if known else 0,
                    "online",
                    now,
                ))

                payload = {
                    "mac": mac,
                    "ip": ip,
                    "vendor": vendor or "Unknown",
                    "hostname": hostname,
                    "known": known,
                    "friendly_name": friendly_name,
                }
                event_to_add = {
                    **payload,
                    "event_type": "new_device",
                }
                session_to_start = payload

        if event_to_add:
            self.add_event(event_to_add["event_type"], event_to_add)

        if session_to_start:
            self.start_session(session_to_start, started_at=now)

    def mark_offline_devices(self) -> List[Dict[str, Any]]:
        now = datetime.utcnow()
        now_str = _utc_now_str()
        offline_threshold = config.SCAN_INTERVAL_SEC * 2

        newly_offline = []
        events_to_add: List[Dict[str, Any]] = []
        sessions_to_end: List[Dict[str, Any]] = []

        with self._lock, get_conn(self.db_path) as conn:
            rows = conn.execute("""
                SELECT ip, mac, vendor, hostname, friendly_name, known, last_seen, status, online_since
                FROM devices
            """).fetchall()

            for r in rows:
                last = _parse_utc(r["last_seen"])
                if not last:
                    continue

                delta = (now - last).total_seconds()
                should_be_offline = delta > offline_threshold
                current_status = (r["status"] or "unknown").lower()

                if should_be_offline and current_status != "offline":
                    conn.execute("""
                        UPDATE devices
                        SET status = ?
                        WHERE mac = ?
                    """, ("offline", r["mac"]))

                    payload = {
                        "ip": r["ip"],
                        "mac": r["mac"],
                        "vendor": r["vendor"],
                        "hostname": r["hostname"],
                        "known": bool(r["known"]),
                        "friendly_name": r["friendly_name"],
                    }

                    newly_offline.append(payload)
                    events_to_add.append({
                        **payload,
                        "event_type": "device_offline",
                    })
                    sessions_to_end.append(payload)

        for event in events_to_add:
            self.add_event(event["event_type"], event)

        for payload in sessions_to_end:
            self.end_session(payload, ended_at=now_str)

        return newly_offline

    def all(self) -> List[Dict[str, Any]]:
        with self._lock, get_conn(self.db_path) as conn:
            rows = conn.execute("""
                SELECT ip, mac, vendor, hostname, friendly_name, first_seen, last_seen, known, status, online_since
                FROM devices
                ORDER BY last_seen DESC, mac ASC
            """).fetchall()

            now = datetime.utcnow()
            devices = []

            for r in rows:
                status = (r["status"] or "unknown").lower()
                online_since = r["online_since"]
                uptime = ""

                if status == "online":
                    start = _parse_utc(online_since)
                    if start:
                        uptime = _format_duration((now - start).total_seconds())

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
                    "online_since": online_since,
                    "uptime": uptime,
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