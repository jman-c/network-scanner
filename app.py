import threading
import time
from flask import Flask, jsonify, render_template

import config
from scanner import scan_many
from store import DeviceStore
from vendor import load_oui_file, vendor_lookup

from driver_check import npcap_installed, install_npcap

app = Flask(__name__)
store = DeviceStore()

# Load OUI mapping once (if using local)
OUI_MAP = load_oui_file(config.LOCAL_OUI_PATH)


def resolve_vendor(mac: str) -> str:
    return vendor_lookup(mac)

def is_known(mac: str):
    mac = mac.lower()
    if mac in config.KNOWN_DEVICES:
        return True, config.KNOWN_DEVICES[mac]
    return False, None

def scan_loop():
    while True:
        try:
            rows = scan_many(config.SCAN_CIDRS, iface=getattr(config, "SCAN_IFACE", None))
            print(f"[scan_loop] iface={getattr(config, 'SCAN_IFACE', None)} cidrs={config.SCAN_CIDRS} -> {len(rows)} devices")
            for r in rows:
                mac = r["mac"]
                known, name = is_known(mac)
                vendor = resolve_vendor(mac)
                store.upsert(ip=r["ip"], mac=mac, vendor=vendor, known=known, name=name)
        except Exception as e:
            # In production, log this properly
            print(f"[scan_loop] error: {e}")
        time.sleep(config.SCAN_INTERVAL_SEC)

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
    if not npcap_installed():
        print("Npcap not found.")

        choice = input("Install Npcap now? (y/n): ")

        if choice.lower() == "y":
            install_npcap()
            print("Please restart the program after installation.")
            exit()
        else:
            print("Scanner will not function without Npcap.")
            exit()
    start_background_scanner()
    # For LAN use; in production use gunicorn and bind appropriately
    app.run(host="0.0.0.0", port=5000, debug=True)