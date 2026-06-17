# 🌐 Complete Network Monitoring System - Usage Guide

## 📦 What You Just Got

Three powerful tools to monitor your entire network:

1. **Network Scanner** (`network_scanner.py`) - Discover all devices
2. **Live Monitor** (`live_monitor.py`) - Real-time traffic analysis
3. **Web Dashboard** (`web_dashboard.py`) - Beautiful web interface

---

## 🚀 Quick Start Guide

### Step 1: Copy Files to Your Project

Copy these 3 new files to your `code` folder:
- `network_scanner.py`
- `live_monitor.py`  
- `web_dashboard.py`

Your folder structure should look like:
```
E:\network-analyzer-project\
├── code\
│   ├── network_analyzer.py      ← Original analyzer
│   ├── network_scanner.py       ← NEW: Device scanner
│   ├── live_monitor.py          ← NEW: Live monitor
│   ├── web_dashboard.py         ← NEW: Web dashboard
│   ├── train_models.py
│   ├── test.py
│   └── generate_threats.py
├── data\
└── ...
```

---

## 🔍 Tool 1: Network Scanner

**What it does:** Finds all devices connected to your network

### How to Use:

**IMPORTANT: Must run as Administrator!**

1. **Close VS Code**
2. **Right-click** VS Code icon → **Run as administrator**
3. **Open** your project folder
4. **Activate** virtual environment:
   ```bash
   venv\Scripts\activate
   ```

5. **Run the scanner:**
   ```bash
   python code\network_scanner.py
   ```

### What You'll See:

```
🔍 Scanning Network: 192.168.1.0/24
📍 Your IP: 192.168.1.100
================================================

Please wait, this may take 10-30 seconds...

================================================
✅ Found 5 device(s) on the network
================================================

#    IP Address        MAC Address          Hostname                  Vendor
---- ----------------- -------------------- ------------------------- ---------------
👉 1  192.168.1.100     AA:BB:CC:DD:EE:FF    DESKTOP-PC                Intel
   2  192.168.1.1       11:22:33:44:55:66    router.local              TP-Link
   3  192.168.1.101     77:88:99:AA:BB:CC    laptop                    Apple
   4  192.168.1.102     DD:EE:FF:00:11:22    android-phone             Samsung
   5  192.168.1.103     33:44:55:66:77:88    smart-tv                  Unknown

👉 = Your device
================================================

💾 Device list saved to: network_devices.json
```

### Output File:

The scanner creates `network_devices.json` with detailed device information.

---

## 📡 Tool 2: Live Network Monitor

**What it does:** Monitors ALL traffic in real-time and tracks per-device statistics

### How to Use:

**IMPORTANT: Must run as Administrator!**

1. **Make sure VS Code is running as Administrator**

2. **Activate** virtual environment:
   ```bash
   venv\Scripts\activate
   ```

3. **Run the live monitor:**
   ```bash
   python code\live_monitor.py
   ```

   Or specify network interface:
   ```bash
   python code\live_monitor.py Ethernet
   # or
   python code\live_monitor.py Wi-Fi
   ```

### What You'll See:

```
🚀 Starting live network monitoring...
📡 Interface: Default
Press Ctrl+C to stop

2026-02-13 22:00:15 - INFO - 📊 Processed 100 packets (45.23 pkt/s)
2026-02-13 22:00:20 - INFO - 📊 Processed 200 packets (48.67 pkt/s)

====================================================
📊 LIVE NETWORK STATISTICS - 22:00:30
====================================================

⏱️  Runtime: 30s | Total Packets: 450 | Rate: 15.00 pkt/s

📡 Protocol Distribution:
   TCP: 320 (71.1%)
   UDP: 100 (22.2%)
   ICMP: 30 (6.7%)

🔝 Top Active Devices:
   192.168.1.100: 250 sent, 180 received
   192.168.1.101: 120 sent, 90 received
   192.168.1.1: 80 sent, 180 received

🚨 Recent Alerts: 1
   [HIGH] PORT_SCAN: Device 192.168.1.101 accessed 25 different ports
====================================================
```

### Features:

- ✅ Real-time packet capture
- ✅ Per-device statistics
- ✅ Automatic threat detection
- ✅ Protocol analysis
- ✅ Top talkers identification
- ✅ Alert generation

### Stop Monitoring:

Press **Ctrl+C** to stop. It will show final summary and save to `live_monitor_stats.json`

---

## 🖥️ Tool 3: Web Dashboard

**What it does:** Beautiful web interface to view all monitoring data

### How to Use:

1. **Activate** virtual environment:
   ```bash
   venv\Scripts\activate
   ```

2. **Run the web server:**
   ```bash
   python code\web_dashboard.py
   ```

### What You'll See:

```
╔═══════════════════════════════════════════════════════════╗
║          Network Analyzer Web Dashboard                  ║
║        Access from: http://localhost:5000                 ║
╚═══════════════════════════════════════════════════════════╝

📡 Starting web server...
🌐 Open your browser and go to: http://localhost:5000
📱 Or from another device: http://YOUR_IP:5000

Press Ctrl+C to stop
```

3. **Open your web browser** and go to:
   - From same computer: `http://localhost:5000`
   - From phone/tablet: `http://192.168.1.100:5000` (use your PC's IP)

### Dashboard Features:

✅ **Summary Cards**
- Total alerts
- Total devices
- Packets analyzed
- Monitoring status

✅ **Alerts Table**
- Real-time security alerts
- Severity levels
- Timestamps
- Source IPs

✅ **Devices Table**
- All discovered devices
- IP addresses
- MAC addresses
- Hostnames
- Vendors

✅ **Auto-refresh**
- Updates every 10 seconds
- Manual refresh button

---

## 🎯 Complete Workflow

Here's how to use all three tools together:

### Day 1: Initial Setup

**Step 1: Discover Devices**
```bash
# Run as Administrator
python code\network_scanner.py
```
Output: `network_devices.json` with 5 devices

**Step 2: Start Web Dashboard**
```bash
python code\web_dashboard.py
```
Open browser: `http://localhost:5000`

**Step 3: Start Live Monitoring** (in another terminal)
```bash
# Run as Administrator
python code\live_monitor.py
```

Now you have:
- ✅ Complete device inventory
- ✅ Real-time monitoring active
- ✅ Web dashboard showing everything

---

### Day 2: Check for Threats

**Option A: Analyze Saved Traffic**
```bash
python code\network_analyzer.py pcap data\pcaps\malicious_traffic.pcap
```

**Option B: View Live Data**
Open browser: `http://localhost:5000`

**Option C: Check Logs**
```bash
type alerts.json
type live_monitor_stats.json
type network_devices.json
```

---

## 📊 Understanding the Output Files

### 1. `alerts.json`
Created by: `network_analyzer.py` and `live_monitor.py`

Contains: Security alerts

Example:
```json
[
  {
    "timestamp": "2026-02-13T22:00:00",
    "alert_type": "PORT_SCAN",
    "severity": "HIGH",
    "message": "Port scan detected from 192.168.1.50",
    "source_ip": "192.168.1.50",
    "destination_ip": "192.168.1.100"
  }
]
```

### 2. `network_devices.json`
Created by: `network_scanner.py`

Contains: All discovered devices

Example:
```json
{
  "scan_time": "2026-02-13T21:30:00",
  "network_range": "192.168.1.0/24",
  "devices": [
    {
      "ip": "192.168.1.100",
      "mac": "AA:BB:CC:DD:EE:FF",
      "hostname": "DESKTOP-PC",
      "vendor": "Intel",
      "is_local": true
    }
  ]
}
```

### 3. `live_monitor_stats.json`
Created by: `live_monitor.py`

Contains: Traffic statistics per device

Example:
```json
{
  "total_packets": 1500,
  "duration": 120,
  "device_stats": {
    "192.168.1.100": {
      "packets_sent": 500,
      "packets_received": 300,
      "protocols": {"TCP": 400, "UDP": 100},
      "ports_accessed": [80, 443, 8080]
    }
  },
  "alerts": [...]
}
```

---

## 🔧 Troubleshooting

### Issue 1: "Permission denied" or "Access is denied"

**Solution:**
- Close VS Code
- Right-click VS Code icon → **Run as administrator**
- Try again

### Issue 2: "No devices found" in network scanner

**Solution:**
- Make sure you're connected to a network (Wi-Fi or Ethernet)
- Check Windows Firewall isn't blocking Scapy
- Try running: `python -c "from scapy.all import *; print(get_if_list())"`

### Issue 3: Live monitor not capturing packets

**Solution:**
- Run as Administrator
- Specify interface manually:
  ```bash
  # First, find your interface
  ipconfig
  
  # Then use it
  python code\live_monitor.py Ethernet
  # or
  python code\live_monitor.py Wi-Fi
  ```

### Issue 4: Web dashboard shows "No data"

**Solution:**
- Run the scanner first: `python code\network_scanner.py`
- Or run the analyzer: `python code\network_analyzer.py pcap data\pcaps\malicious_traffic.pcap`
- The dashboard displays data from JSON files, so you need to generate them first

### Issue 5: Can't access dashboard from phone

**Solution:**
1. Find your PC's IP address:
   ```bash
   ipconfig
   ```
   Look for "IPv4 Address" (e.g., 192.168.1.100)

2. Make sure your phone is on the same Wi-Fi network

3. Open browser on phone and go to:
   ```
   http://192.168.1.100:5000
   ```
   (Replace 192.168.1.100 with your actual IP)

4. If still not working, check Windows Firewall:
   - Allow Python through firewall
   - Or temporarily disable firewall for testing

---

## 🎓 For Your Graduation Project

### What to Include in Your Report:

**Chapter 1: Network Discovery**
- Explain how ARP scanning works
- Show screenshots of discovered devices
- Discuss MAC address vendor identification

**Chapter 2: Traffic Analysis**
- Explain packet capture techniques
- Show per-device statistics
- Discuss protocol distribution

**Chapter 3: Threat Detection**
- Show detected port scans
- Show detected DDoS attempts
- Explain detection algorithms

**Chapter 4: Visualization**
- Show web dashboard screenshots
- Explain real-time updates
- Discuss user interface design

### Screenshots to Take:

1. Network scanner output showing all devices
2. Live monitor showing real-time statistics
3. Web dashboard main page
4. Alerts table with detected threats
5. Devices table
6. Terminal showing commands

---

## 💡 Advanced Usage

### Run Multiple Tools Simultaneously

**Terminal 1: Web Dashboard**
```bash
venv\Scripts\activate
python code\web_dashboard.py
```

**Terminal 2: Live Monitor**
```bash
venv\Scripts\activate
python code\live_monitor.py
```

**Browser: View Dashboard**
```
http://localhost:5000
```

Now you're monitoring your network in real-time with a live dashboard!

### Schedule Regular Scans

Create a batch file `scan_network.bat`:
```batch
@echo off
cd E:\network-analyzer-project
call venv\Scripts\activate
python code\network_scanner.py
pause
```

Run this every day to track new devices joining your network.

---

## 📋 Quick Reference

| Task | Command |
|------|---------|
| Scan for devices | `python code\network_scanner.py` |
| Monitor live traffic | `python code\live_monitor.py` |
| Start web dashboard | `python code\web_dashboard.py` |
| Analyze PCAP file | `python code\network_analyzer.py pcap file.pcap` |
| View alerts | `type alerts.json` |
| View devices | `type network_devices.json` |
| View stats | `type live_monitor_stats.json` |

**Remember:** Network scanner and live monitor need Administrator privileges!

---

## 🎯 Next Steps

1. **Test each tool individually** first
2. **Generate some test traffic** with `generate_threats.py`
3. **Run all tools together** to see the complete system
4. **Take screenshots** for your project documentation
5. **Customize detection thresholds** in the code
6. **Add your own features** (e.g., email alerts, mobile app)

---

**Your network monitoring system is ready! 🎉**

Any questions? Just ask! 🚀
