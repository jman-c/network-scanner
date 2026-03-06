import json
import os
import threading
import time
from datetime import datetime
from typing import Dict, Any, Set

import requests
from flask import Flask, jsonify, render_template, request

import config
from scanner import scan_many
from store import DeviceStore
from vendor import load_oui_file, vendor_lookup
from hostname import reverse_dns

app = Flask(__name__)
store = DeviceStore()

SEEN_MACS_PATH = "seen_macs.json"


def load_seen_macs(path: str) -> Set[str]:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return {str(x).lower() for x in data}
        except Exception:
            pass
    return set()


def save_seen_macs(path: str, seen: Set[str]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sorted(list(seen)), f, indent=2)
    except Exception:
        pass


# Load persisted “seen” set (prevents startup alert spam)
SEEN_MACS: Set[str] = load_seen_macs(SEEN_MACS_PATH)

# Optional: load local OUI mapping if present (safe if missing)
LOCAL_OUI_MAP = {}
try:
    local_path = getattr(config, "LOCAL_OUI_PATH", "oui.txt")
    LOCAL_OUI_MAP = load_oui_file(local_path)
    if LOCAL_OUI_MAP:
        print(f"[vendor] loaded {len(LOCAL_OUI_MAP)} OUIs from {local_path}")
except Exception:
    LOCAL_OUI_MAP = {}


def is_known(mac: str):
    mac = mac.lower()
    if mac in config.KNOWN_DEVICES:
        return True, config.KNOWN_DEVICES[mac]
    return False, None


def make_alert(alert_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    # stable-ish unique id (good enough for UI): time + mac
    mac = payload.get("mac", "")
    alert_id = f"{ts}:{mac}"
    out = {"id": alert_id, "type": alert_type, "time": ts}
    out.update(payload)
    return out


def scan_loop():
    backoff = config.SCAN_INTERVAL_SEC
    last_seen_save = 0.0

    while True:
        try:
            iface = getattr(config, "SCAN_IFACE", None)
            rows = scan_many(config.SCAN_CIDRS, iface=iface)

            print(f"[scan_loop] iface={iface} cidrs={config.SCAN_CIDRS} -> found {len(rows)} devices")

            for r in rows:
                mac = r["mac"].lower()
                ip = r["ip"]

                known, friendly_name = is_known(mac)
                is_new_in_memory = not store.has(mac)

                if is_new_in_memory:
                    # Enrich only NEW devices (fast)
                    hostname = reverse_dns(ip)
                    vendor = vendor_lookup(mac, local_oui_map=LOCAL_OUI_MAP, use_remote=True)

                    # Optional fallback: if no friendly name configured, use hostname
                    if not friendly_name and hostname:
                        friendly_name = hostname

                    store.upsert(
                        ip=ip,
                        mac=mac,
                        vendor=vendor,
                        known=known,
                        friendly_name=friendly_name,
                        hostname=hostname,
                    )

                    # Alert only if this MAC has never been seen across restarts
                    if getattr(config, "ALERT_ON_NEW_DEVICE", True) and (mac not in SEEN_MACS):
                        alert = make_alert(
                            "new_device",
                            {
                                "ip": ip,
                                "mac": mac,
                                "vendor": vendor,
                                "hostname": hostname,
                                "known": known,
                                "friendly_name": friendly_name,
                            },
                        )
                        store.add_alert(alert)
                        print(f"[ALERT] New device: ip={ip} mac={mac} vendor={vendor} host={hostname} known={known}")

                        webhook = getattr(config, "ALERT_WEBHOOK_URL", "").strip()
                        if webhook:
                            try:
                                requests.post(webhook, json=alert, timeout=4)
                            except Exception:
                                pass

                    # Mark as seen (persisted)
                    SEEN_MACS.add(mac)

                else:
                    # Existing device: skip hostname/vendor lookup
                    store.upsert(
                        ip=ip,
                        mac=mac,
                        vendor=None,
                        known=known,
                        friendly_name=friendly_name,  # allow configured names to update
                        hostname=None,
                    )

            # Save seen MACs occasionally (every ~30s max) to reduce disk writes
            now = time.time()
            if now - last_seen_save > 30:
                save_seen_macs(SEEN_MACS_PATH, SEEN_MACS)
                last_seen_save = now

            backoff = config.SCAN_INTERVAL_SEC

        except Exception as e:
            msg = str(e)
            print(f"[scan_loop] error: {msg}")
            backoff = min(backoff * 2, 300)

        time.sleep(backoff)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/devices")
def api_devices():
    return jsonify({"devices": store.all(), "summary": store.summary()})


@app.route("/api/alerts")
def api_alerts():
    return jsonify({"alerts": store.alerts(50)})


@app.route("/api/alerts/<alert_id>", methods=["DELETE"])
def api_alert_delete(alert_id: str):
    store.dismiss_alert(alert_id)
    return jsonify({"ok": True})


@app.route("/api/alerts/clear", methods=["POST"])
def api_alerts_clear():
    store.clear_alerts()
    return jsonify({"ok": True})


def start_background_scanner():
    t = threading.Thread(target=scan_loop, daemon=True)
    t.start()


if __name__ == "__main__":
    start_background_scanner()
    app.run(host="0.0.0.0", port=5000, debug=True)