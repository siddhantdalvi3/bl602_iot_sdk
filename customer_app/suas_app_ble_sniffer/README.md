# BLE Sniffer for BL602 - Enhanced v3.0

A comprehensive BLE packet sniffer for the BL602 platform with real-time Wireshark integration, multi-format exports, device tracking, and manufacturer identification.

## 🌟 Features

### Firmware Features

- **100% Duty Cycle Scanning**: Continuous capture with `window == interval`
- **Active Scanning**: Captures SCAN_RSP for additional device information
- **Full AD Parsing**: Extracts name, services, TX power, manufacturer data, appearance
- **Large Buffer**: 200 packet buffer for high-traffic environments
- **Statistics**: Real-time capture rate and overflow monitoring

### Python Sniffer Features

- **📡 Real-time Wireshark Integration**: Live packet viewing via FIFO pipe
- **📊 JSON Export**: Complete packet and device data for analysis
- **📋 CSV Export**: Spreadsheet-ready device list
- **📄 HTML Report**: Beautiful visual report with charts
- **🏭 OUI Database**: Auto-identifies 100+ manufacturers (Apple, Samsung, Xiaomi, ESP32, etc.)
- **🔧 Service UUID Decoding**: Heart Rate, Battery, Fitness Machine, etc.
- **📱 Device Database**: Tracks all devices with RSSI history
- **🎨 Colored Terminal Output**: Visual distinction for packet types
- **🔍 Flexible Filtering**: By MAC, name, or RSSI threshold

## 📋 Output Formats

### 1. PCAP (Wireshark)

Standard packet capture format for protocol analysis.

### 2. JSON Export

```json
{
  "capture_info": {
    "start_time": "2025-11-30T15:00:00",
    "duration_seconds": 300,
    "total_packets": 15420
  },
  "devices": [
    {
      "mac": "AA:BB:CC:DD:EE:FF",
      "name": "iPhone",
      "manufacturer": "Apple",
      "rssi_avg": -65.2,
      "services": ["Heart Rate", "Battery"],
      "packet_count": 142
    }
  ],
  "packets": [...]
}
```

### 3. CSV Export

| MAC Address       | Name   | Manufacturer | RSSI (Avg) | Services            | Packets |
| ----------------- | ------ | ------------ | ---------- | ------------------- | ------- |
| AA:BB:CC:DD:EE:FF | iPhone | Apple        | -65.2      | Heart Rate; Battery | 142     |

### 4. HTML Report

Interactive visual report with:

- Capture statistics dashboard
- Device table with sorting
- Packet type distribution
- RSSI color coding (good/medium/poor)

## 🚀 Quick Start

### 1. Flash the Firmware

```bash
cd customer_app/suas_app_ble_sniffer
make clean && make
# Flash using your preferred method
```

### 2. Install Python Dependencies

```bash
pip3 install pyserial
```

### 3. Run the Sniffer

**Basic capture:**

```bash
python3 ble_sniffer_py/sniffer.py -p /dev/tty.usbserial-110
```

**With all exports:**

```bash
python3 ble_sniffer_py/sniffer.py -p /dev/tty.usbserial-110 \
    --json capture.json \
    --csv devices.csv \
    --html report.html
```

**Real-time Wireshark:**

```bash
# Terminal 1
python3 ble_sniffer_py/sniffer.py -p /dev/tty.usbserial-110 --fifo

# Terminal 2
wireshark -k -i capture.pcap
```

## 📖 Command Line Options

### Basic Options

| Option          | Description                      | Default      |
| --------------- | -------------------------------- | ------------ |
| `-p, --port`    | Serial port (required)           | -            |
| `-b, --baud`    | Baud rate                        | 115200       |
| `-o, --output`  | Output PCAP file                 | capture.pcap |
| `--fifo`        | Use FIFO for real-time Wireshark | false        |
| `-v, --verbose` | Show decoded packet details      | false        |
| `-q, --quiet`   | Suppress progress dots           | false        |
| `--no-color`    | Disable colored output           | false        |

### Filtering Options

| Option          | Description                       | Example                          |
| --------------- | --------------------------------- | -------------------------------- |
| `--filter-mac`  | Filter by MAC address             | `--filter-mac AA:BB:CC:DD:EE:FF` |
| `--filter-name` | Filter by device name (substring) | `--filter-name "iPhone"`         |
| `--min-rssi`    | Minimum RSSI threshold            | `--min-rssi -60`                 |

### Export Options

| Option        | Description               |
| ------------- | ------------------------- |
| `--json FILE` | Export full data to JSON  |
| `--csv FILE`  | Export device list to CSV |
| `--html FILE` | Generate HTML report      |

## 🔬 Usage Examples

### Track a Specific Device

```bash
python3 sniffer.py -p /dev/tty.usbserial-110 \
    --filter-mac AA:BB:CC:DD:EE:FF \
    --verbose
```

### Find All iPhones

```bash
python3 sniffer.py -p /dev/tty.usbserial-110 \
    --filter-name "iphone" \
    --csv iphones.csv
```

### Capture Only Strong Signals

```bash
python3 sniffer.py -p /dev/tty.usbserial-110 \
    --min-rssi -50 \
    --html nearby_devices.html
```

### Long-running Survey

```bash
python3 sniffer.py -p /dev/tty.usbserial-110 \
    --json survey_$(date +%Y%m%d).json \
    --html survey_$(date +%Y%m%d).html \
    -q
```

## 📊 Decoded Information

### BLE Advertisement Types

| Type | Name            | Description            |
| ---- | --------------- | ---------------------- |
| 0x00 | ADV_IND         | Connectable undirected |
| 0x01 | ADV_DIRECT_IND  | Connectable directed   |
| 0x02 | ADV_SCAN_IND    | Scannable undirected   |
| 0x03 | ADV_NONCONN_IND | Non-connectable        |
| 0x04 | SCAN_RSP        | Scan response          |

### Decoded AD Types

- **Flags** (0x01): Discoverability mode
- **Complete/Short Name** (0x08/0x09): Device name
- **TX Power** (0x0A): Transmission power level
- **Service UUIDs** (0x02/0x03): 16-bit service identifiers
- **Appearance** (0x19): Device category (phone, watch, etc.)
- **Manufacturer Data** (0xFF): Vendor-specific data

### Manufacturer Identification

The sniffer identifies devices from 100+ manufacturers including:

- Apple, Samsung, Google, Microsoft, Amazon
- Xiaomi, Huawei, OnePlus
- Espressif (ESP32), Nordic, Texas Instruments
- Fitbit, Tile, Garmin, Polar

### Service UUID Decoding

Recognizes common BLE services:

- Heart Rate (0x180D)
- Battery (0x180F)
- Device Information (0x180A)
- Fitness Machine (0x1826)
- Environmental Sensing (0x181A)
- And 40+ more...

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BL602 Firmware                           │
├─────────────────────────────────────────────────────────────┤
│  scanner.c          │  sniffer.c         │  main.c          │
│  - Active scanning  │  - AD parsing      │  - Task init     │
│  - 100% duty cycle  │  - Ring buffer     │  - LED control   │
│  - All channels     │  - Stats tracking  │                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ UART (btsnoop format)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Python Sniffer (sniffer.py)        │
├─────────────────────────────────────────────────────────────┤
│  Serial Parser  →  Packet Decoder  →  Device Database       │
│        │                  │                  │              │
│        ▼                  ▼                  ▼              │
│     PCAP File         Statistics         Exports            │
│     (Wireshark)       Dashboard       (JSON/CSV/HTML)       │
└─────────────────────────────────────────────────────────────┘
```

## 📁 File Structure

```
customer_app/suas_app_ble_sniffer/
├── suas_app_ble_sniffer/
│   ├── main.c           # Application entry point
│   ├── scanner.c        # BLE scanning with active mode
│   ├── scanner.h        # Scanner interface
│   ├── sniffer.c        # Packet buffering and AD parsing
│   ├── sniffer.h        # Sniffer data structures
│   ├── bouffalo.mk      # Build configuration
│   └── Makefile         # Component makefile
├── Makefile             # Project makefile
├── proj_config.mk       # Project configuration
└── README.md            # This file

ble_sniffer_py/
├── sniffer.py  # Python Sniffer script
└── requirements.txt     # Python dependencies
```

## 🔧 Technical Details

### HCI Packet Format (btsnoop)

```
[btsnoop]:pkt_type =[0x<type>],len =[0x<len>],data=[<hex_string>]
```

| pkt_type | Description         |
| -------- | ------------------- |
| 0x01     | HCI Command         |
| 0x02     | ACL Data            |
| 0x04     | HCI Event (LE Meta) |
| 0x05     | HCI Event (General) |

### Scan Parameters (Firmware)

```c
scan_param.type = BT_LE_SCAN_TYPE_ACTIVE;  // Get SCAN_RSP
scan_param.filter_dup = 0;                  // Capture all
scan_param.interval = 0x30;                 // 30ms
scan_param.window = 0x30;                   // 30ms (100% duty)
```

### Buffer Configuration

- Buffer Size: 200 packets
- Task Priority: 12 (high)
- Stack Size: 1536 words

## 🐛 Troubleshooting

### No packets captured

1. Check serial port: `ls /dev/tty.usb*`
2. Verify baud rate matches (115200)
3. Reset the BL602 board

### Parse errors

- Update to latest sniffer.py
- Check for firmware/Python version mismatch

### Buffer overflow on device

- Increase `SNIFFER_BUFFER_SIZE` in sniffer.c
- Reduce scan window for lower traffic

### Wireshark not connecting (FIFO mode)

- Ensure FIFO is created: `ls -la capture.pcap`
- Start Wireshark after the script is running

## 📜 License

Part of the BL602 IoT SDK. See LICENSE file for details.

## 🙏 Acknowledgments

- Bouffalo Lab for the BL602 SDK
- Wireshark team for packet analysis tools
- IEEE for OUI database
