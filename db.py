import sqlite3
from contextlib import contextmanager

DB_PATH = "net_scanner.db"


def init_db(db_path: str = DB_PATH) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                vendor TEXT NOT NULL DEFAULT 'Unknown',
                hostname TEXT,
                friendly_name TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                known INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'unknown',
                online_since TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                time TEXT NOT NULL,
                ip TEXT,
                mac TEXT,
                vendor TEXT,
                hostname TEXT,
                known INTEGER,
                friendly_name TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS vendor_cache (
                oui_prefix TEXT PRIMARY KEY,
                vendor_name TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_time TEXT NOT NULL,
                ip TEXT,
                vendor TEXT,
                hostname TEXT,
                known INTEGER,
                friendly_name TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                duration_sec INTEGER,
                start_ip TEXT,
                end_ip TEXT,
                vendor TEXT,
                hostname TEXT,
                known INTEGER,
                friendly_name TEXT,
                is_active INTEGER NOT NULL DEFAULT 1
            )
        """)

        cols = [row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()]

        if "status" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN status TEXT NOT NULL DEFAULT 'unknown'")

        if "online_since" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN online_since TEXT")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(time DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_device_events_mac_time ON device_events(mac, event_time DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_device_sessions_mac_start ON device_sessions(mac, started_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_device_sessions_active ON device_sessions(mac, is_active)")

        conn.commit()
    finally:
        conn.close()


@contextmanager
def get_conn(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()