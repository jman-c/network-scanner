# Network Device Scanner

A lightweight network discovery and monitoring tool built with **Python,
Scapy, and Flask**.

The scanner discovers devices on a local network, identifies them using
**MAC address vendor lookup**, resolves **hostnames**, and presents the
results on a **web dashboard**.

It also includes a **monitoring system that alerts when new devices
appear on the network**.

------------------------------------------------------------------------

# Features

Current capabilities of the scanner:

-   Network discovery using **ARP scanning**
-   Cross‑platform support (**Windows, Linux, macOS**)
-   Vendor identification using **MAC OUI lookup**
-   Persistent **vendor cache** to avoid repeated API calls
-   Hostname detection using **reverse DNS**
-   Device dashboard built with **Flask**
-   Device status classification (**Known / Unknown**)
-   Persistent baseline tracking of previously seen devices
-   **New device detection alerts**
-   Dashboard alert system
-   Ability to **dismiss individual alerts**
-   Ability to **clear all alerts**
-   Device summary statistics (total / known / unknown)
-   Device first‑seen and last‑seen timestamps
-   Optional webhook integration for alerts
-   Test framework support for cache testing

------------------------------------------------------------------------

# Architecture

    ARP Scan (Scapy)
          ↓
    Device Discovery
          ↓
    Hostname Detection
          ↓
    Vendor Lookup
          ↓
    Device Store
          ↓
    Alerts + Dashboard

------------------------------------------------------------------------

# Requirements

Python version:

    Python 3.10+

Python packages:

    flask>=3.0.0
    scapy>=2.5.0
    requests>=2.31.0

------------------------------------------------------------------------

# Installation

Clone the repository:

    git clone https://github.com/YOUR_USERNAME/net-scanner.git
    cd net-scanner

Create a virtual environment:

    python -m venv .venv

Activate the environment.

### Windows

    .venv\Scripts\activate

### Linux / macOS

    source .venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

------------------------------------------------------------------------

# Running the Scanner

Run inside the virtual environment:

    python app.py

The dashboard will be available at:

    http://localhost:5000

------------------------------------------------------------------------

# Configuration

Edit `config.py`.

Example:

``` python
SCAN_CIDRS = ["192.168.0.0/24"]
SCAN_IFACE = "Realtek USB GbE Family Controller #3"

KNOWN_DEVICES = {}

SCAN_INTERVAL_SEC = 60

ALERT_ON_NEW_DEVICE = True
ALERT_WEBHOOK_URL = ""
```

------------------------------------------------------------------------

# Platform Setup

## Windows

Windows requires a packet capture driver for Scapy.

Install **Npcap**:

https://npcap.com/

During installation enable:

    WinPcap Compatible Mode

------------------------------------------------------------------------

## Linux

Install libpcap.

### Debian / Ubuntu

    sudo apt install libpcap0.8 libpcap-dev tcpdump

### Fedora

    sudo dnf install libpcap libpcap-devel tcpdump

Run the scanner:

    sudo python app.py

Optional (run without sudo):

    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

------------------------------------------------------------------------

## macOS

macOS uses built‑in **BPF packet capture**.

Usually the only requirement is running with elevated privileges:

    sudo python app.py

List interfaces:

    python -c "from scapy.all import show_interfaces; show_interfaces()"

------------------------------------------------------------------------

# Runtime Files

The scanner generates runtime cache files which should **not be
committed to Git**.

    vendor_cache.json
    seen_macs.json

## vendor_cache.json

Stores MAC OUI → vendor mappings.

Example:

``` json
{
  "e4:54:e8": "Dell Inc.",
  "2c:cf:67": "Raspberry Pi (Trading) Ltd"
}
```

This prevents repeated vendor API calls.

------------------------------------------------------------------------

## seen_macs.json

Stores devices that have already been discovered.

Example:

``` json
[
  "e4:54:e8:12:34:56",
  "98:fa:9b:25:56:67"
]
```

This prevents **alert spam when the application restarts**.

------------------------------------------------------------------------

# Alerts

When a new device appears on the network an alert is generated.

Example:

    NEW DEVICE DETECTED

    IP: 192.168.0.88
    MAC: 2c:cf:67:aa:bb:cc
    Vendor: Raspberry Pi
    Hostname: raspberrypi

Alerts can be:

-   dismissed individually
-   cleared entirely from the dashboard

------------------------------------------------------------------------

# Tests

Tests should be run from the project root. (for now these are for me)

Example:

    python -m tests.test_cache

------------------------------------------------------------------------

# Security Notes

This scanner performs **ARP discovery**, which means it only detects
devices on the **local broadcast network**.

It does not scan beyond the local subnet.

------------------------------------------------------------------------

# Planned Improvements

Possible future improvements:

-   Device type classification
-   Offline device alerts
-   Historical device tracking
-   Network topology mapping
-   Device approval workflow
-   Database-backed storage
-   Containerized deployment (Docker)
-   API authentication

------------------------------------------------------------------------

# License

MIT License

------------------------------------------------------------------------

# Contributions

Contributions are welcome.

Open an issue or submit a pull request if you have improvements or bug
fixes.
