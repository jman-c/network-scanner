import threading
import time
from datetime import datetime
from typing import Dict, Any

import requests
from flask import Flask, jsonify, render_template

import config
from db import init_db
from scanner import scan_many
from store import DeviceStore
from vendor import load_oui_file, vendor_lookup
from hostname import reverse_dns

app = Flask(__name__)

DB_PATH = getattr(config, "DB_PATH", "net_scanner.db")
init_db(DB_PATH)
store = DeviceStore(DB_PATH)

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
    mac = payload.get("mac", "")
    alert_id = f"{alert_type}:{ts}:{mac}"
    out = {"id": alert_id, "type": alert_type, "time": ts}
    out.update(payload)
    return out


def send_webhook(alert: Dict[str, Any]) -> None:
    webhook = getattr(config, "ALERT_WEBHOOK_URL", "").strip()
    if webhook:
        try:
            requests.post(webhook, json=alert, timeout=4)
        except Exception:
            pass


def scan_loop():
    backoff = config.SCAN_INTERVAL_SEC

    while True:
        try:
            iface = getattr(config, "SCAN_IFACE", None)
            rows = scan_many(config.SCAN_CIDRS, iface=iface)

            print(f"[scan_loop] iface={iface} cidrs={config.SCAN_CIDRS} -> found {len(rows)} devices")

            for r in rows:
                mac = r["mac"].lower()
                ip = r["ip"]

                known, friendly_name = is_known(mac)
                is_new_device = not store.has(mac)

                if is_new_device:
                    hostname = reverse_dns(ip)
                    vendor = vendor_lookup(mac, local_oui_map=LOCAL_OUI_MAP, use_remote=True)

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

                    if getattr(config, "ALERT_ON_NEW_DEVICE", True):
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
                        send_webhook(alert)

                else:
                    store.upsert(
                        ip=ip,
                        mac=mac,
                        vendor=None,
                        known=known,
                        friendly_name=friendly_name,
                        hostname=None,
                    )

            newly_offline = store.mark_offline_devices()
            for device in newly_offline:
                alert = make_alert("offline_device", device)
                store.add_alert(alert)
                print(f"[ALERT] Device offline: ip={device['ip']} mac={device['mac']} vendor={device['vendor']}")
                send_webhook(alert)

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


@app.route("/api/devices/<path:mac>/events")
def api_device_events(mac: str):
    return jsonify({"mac": mac.lower(), "events": store.get_device_events(mac, limit=50)})


@app.route("/api/devices/<path:mac>/sessions")
def api_device_sessions(mac: str):
    return jsonify({
        "mac": mac.lower(),
        "stats": store.get_device_session_stats(mac),
        "sessions": store.get_device_sessions(mac, limit=50),
    })


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