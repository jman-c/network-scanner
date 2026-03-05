import threading
import time
from flask import Flask, jsonify, render_template

import config
from scanner import scan_many
from store import DeviceStore
from vendor import load_oui_file, vendor_lookup
from hostname import reverse_dns

app = Flask(__name__)
store = DeviceStore()

# Optional: load local OUI mapping if you have oui.txt.
# If you don't have the file, it just loads empty and continues.
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

                # Only enrich NEW devices (fast + fewer network calls)
                if not store.has(mac):
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


def start_background_scanner():
    t = threading.Thread(target=scan_loop, daemon=True)
    t.start()


if __name__ == "__main__":
    start_background_scanner()
    app.run(host="0.0.0.0", port=5000, debug=True)