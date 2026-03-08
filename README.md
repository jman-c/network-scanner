# Network Device Scanner

A lightweight network discovery and monitoring tool built with **Python, Scapy, Flask, and SQLite**.

The scanner discovers devices on a local network, identifies them using **MAC address vendor lookup**, resolves **hostnames**, and presents the results on a **live web dashboard**.

It also includes a **monitoring system that detects when devices appear or disappear from the network**, tracks **device uptime**, and stores information in a **persistent SQLite database**.

---

# Screenshots

## Dashboard

![Dashboard](docs/images/dashboard.png) (coming soon)

The dashboard displays all discovered devices in real time along with:

* device status (online/offline)
* device uptime
* hostname and vendor information
* alerts when devices join or leave the network

## Alerts Panel

![Alerts](docs/images/alerts.png) (coming soon)

The alert system notifies when:

* new devices appear
* known devices go offline

Alerts can be dismissed individually or cleared entirely.

---

# Features

### Network Discovery

* Network discovery using **ARP scanning**
* Cross-platform support (**Windows, Linux, macOS**)
* Configurable scan intervals
* Detection of devices on the **local subnet**

### Device Identification

* Vendor identification using **MAC OUI lookup**
* Persistent **vendor cache stored in SQLite**
* Hostname detection using **reverse DNS**
* Optional friendly name assignment

### Monitoring

* **New device detection alerts**
* **Offline device detection alerts**
* Real-time **device status tracking (Online / Offline)**
* **Device uptime tracking**
* Automatic detection of devices reconnecting to the network

### Dashboard

* Web dashboard built with **Flask**
* Live updating device table
* Device summary statistics:

  * total devices
  * known devices
  * unknown devices
* Device status indicators
* Device uptime display

### Alerts System

* Dashboard alert notifications
* Ability to **dismiss individual alerts**
* Ability to **clear all alerts**
* Optional **webhook integration** for external notifications

### Persistence

* Device data stored in **SQLite database**
* Vendor lookup cache stored in database
* Alerts stored persistently
* Historical data ready for future expansion

---

# Architecture

The scanner follows a modular pipeline:

```
ARP Scan (Scapy)
      ↓
Device Discovery
      ↓
Hostname Detection
      ↓
Vendor Lookup
      ↓
SQLite Device Store
      ↓
Monitoring Logic
      ↓
Alerts + Dashboard
```

### Data Storage

```
SQLite Database
│
├── devices
│     Current device state
│
├── alerts
│     Monitoring alerts
│
└── vendor_cache
      Cached vendor lookups
```

---

# Requirements

Python version:

```
Python 3.10+
```

Python packages:

```
flask>=3.0.0
scapy>=2.5.0
requests>=2.31.0
```

---

# Installation

Clone the repository:

```
git clone https://github.com/YOUR_USERNAME/net-scanner.git
cd net-scanner
```

Create a virtual environment:

```
python -m venv .venv
```

Activate the environment.

### Windows

```
.venv\Scripts\activate
```

### Linux / macOS

```
source .venv/bin/activate
```

Install dependencies:

```
pip install -r requirements.txt
```

---

# Running the Scanner

Run inside the virtual environment:

```
python app.py
```

The dashboard will be available at:

```
http://localhost:5000
```

---

# Configuration

Edit `config.py`.

Example:

```python
SCAN_CIDRS = ["192.168.0.0/24"]

SCAN_IFACE = "Realtek USB GbE Family Controller #3"

KNOWN_DEVICES = {}

SCAN_INTERVAL_SEC = 30

ALERT_ON_NEW_DEVICE = True

ALERT_WEBHOOK_URL = ""
```

### Configuration Options

| Setting               | Description                          |
| --------------------- | ------------------------------------ |
| `SCAN_CIDRS`          | Network ranges to scan               |
| `SCAN_IFACE`          | Network interface used for scanning  |
| `KNOWN_DEVICES`       | Dictionary of trusted MAC addresses  |
| `SCAN_INTERVAL_SEC`   | How often the scanner runs           |
| `ALERT_ON_NEW_DEVICE` | Enable/disable new device alerts     |
| `ALERT_WEBHOOK_URL`   | Optional webhook endpoint for alerts |

---

# Platform Setup

## Windows

Windows requires a packet capture driver for Scapy.

Install **Npcap**:

https://npcap.com/

During installation enable:

```
WinPcap Compatible Mode
```

---

## Linux (not been tested)

Install libpcap.

### Debian / Ubuntu (not been tested)

```
sudo apt install libpcap0.8 libpcap-dev tcpdump
```

### Fedora (not been tested)

```
sudo dnf install libpcap libpcap-devel tcpdump
```

Run the scanner:

```
sudo python app.py
```

Optional (run without sudo):

```
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

---

## macOS (not been tested)

macOS uses built-in **BPF packet capture**.

Usually the only requirement is running with elevated privileges:

```
sudo python app.py
```

List interfaces:

```
python -c "from scapy.all import show_interfaces; show_interfaces()"
```

---

# Database

The application stores runtime data in a **SQLite database**.

File created automatically:

```
net_scanner.db
```

### Tables

**devices**

Stores the current state of all discovered devices.

Includes:

* MAC address
* IP address
* vendor
* hostname
* friendly name
* first seen
* last seen
* device status
* uptime start time

---

**alerts**

Stores alert notifications generated by the scanner.

Example events:

* new device detected
* device went offline

---

**vendor_cache**

Stores cached MAC OUI → vendor mappings to prevent repeated API calls.

---

# Device Status

Devices are classified dynamically as:

| Status  | Description                                         |
| ------- | --------------------------------------------------- |
| Online  | Device detected during recent scans                 |
| Offline | Device previously detected but no longer responding |
| Unknown | Status not yet determined                           |

Offline detection occurs when a device has not been seen for:

```
2 × SCAN_INTERVAL_SEC
```

---

# Device Uptime

The scanner tracks **continuous device uptime**.

When a device is detected:

```
online_since = current time
```

If the device disconnects and reconnects, uptime resets.

Examples:

```
12m
1h 23m
4d 6h
```

---

# Alerts

### New Device Alert

Triggered when a previously unseen MAC address appears.

### Offline Device Alert

Triggered when a previously online device disappears from the network.

Alerts can be:

* dismissed individually
* cleared entirely from the dashboard

---

# Feature Roadmap

Planned improvements for future releases:

### Device History

Track device connect and disconnect events over time.

### Device Detail Page

Allow clicking a device to view full information and history.

### Network Topology

Visualize device relationships and network structure.

### Device Type Detection

Automatically classify devices (router, phone, printer, IoT).

### Authentication

Add login support for dashboard access.

### Docker Deployment

Containerized deployment for easy setup.

### Multi-Network Support

Scan multiple subnets or VLANs.

---

# Security Notes

This scanner performs **ARP discovery**, which means it only detects devices on the **local broadcast network**.

It does not scan beyond the local subnet.

The scanner does **not perform vulnerability scanning or port scanning**.

---

# License

MIT License

---

# Contributions

Contributions are welcome.

Open an issue or submit a pull request if you have improvements or bug fixes.
