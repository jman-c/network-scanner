import threading
import time
from flask import Flask, jsonify, render_template

import config
from scanner import scan_many
from store import DeviceStore
from vendor import vendor_lookup
from hostname import reverse_dns

app = Flask(__name__)
store = DeviceStore()


def is_known(mac: str):
    mac = mac.lower()
    if mac in config.KNOWN_DEVICES:
        return True, config.KNOWN_DEVICES[mac]
    return False, None


def resolve_vendor(mac: str) -> str:
    return vendor_lookup(mac)


def scan_loop():
    backoff = config.SCAN_INTERVAL_SEC

    while True:
        try:
            iface = getattr(config, "SCAN_IFACE", None)
            rows = scan_many(config.SCAN_CIDRS, iface=iface)

            print(f"[scan_loop] iface={iface} cidrs={config.SCAN_CIDRS} -> found {len(rows)} devices")

            for r in rows:
                mac = r["mac"]
                ip = r["ip"]

                # Check if device is known
                known, friendly_name = is_known(mac)

                # Vendor lookup
                vendor = resolve_vendor(mac)

                # Hostname detection
                hostname = reverse_dns(ip)

                # Optional fallback: use hostname as friendly name
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

            backoff = config.SCAN_INTERVAL_SEC  # reset on success

        except Exception as e:
            msg = str(e)
            print(f"[scan_loop] error: {msg}")
            backoff = min(backoff * 2, 300)  # exponential backoff up to 5 minutes

        time.sleep(backoff)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/devices")
def api_devices():
    return jsonify({"devices": store.all(), "summary": store.summary()})


def start_background_scanner():
    t = threading.Thread(target=scan_loop, daemon=True)
    t.start()


if __name__ == "__main__":
    start_background_scanner()
    app.run(host="0.0.0.0", port=5000, debug=True)