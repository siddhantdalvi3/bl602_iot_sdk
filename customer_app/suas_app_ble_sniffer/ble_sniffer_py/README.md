# BLE Sniffer Python Tools

Python utilities for capturing and analyzing BLE packets from BL602.

## Files

| File               | Description                        |
| ------------------ | ---------------------------------- |
| `sniffer.py`       | Full-featured sniffer with exports |
| `requirements.txt` | Python dependencies                |

## Installation

### Python Dependencies

```bash
pip install -r requirements.txt
```

### Wireshark (Optional - for real-time packet viewing)

**macOS:**

```bash
brew install --cask wireshark
```

**Ubuntu/Debian:**

```bash
sudo apt update
sudo apt install wireshark
# Allow non-root users to capture packets
sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER
# Log out and back in for group changes to take effect
```

**Fedora:**

```bash
sudo dnf install wireshark
sudo usermod -a -G wireshark $USER
```

**Windows:**

Download the installer from [wireshark.org/download](https://www.wireshark.org/download.html)

## Quick Start

```bash
# Basic capture
python sniffer.py -p /dev/tty.usbserial-110

# With all exports
python sniffer.py -p /dev/tty.usbserial-110 \
    --json data.json --csv devices.csv --html report.html

# Real-time Wireshark
python sniffer.py -p /dev/tty.usbserial-110 --fifo -v
```

## Enhanced Sniffer Features

### 📊 Multiple Export Formats

#### JSON (`--json FILE`)

Complete capture data including:

- Capture metadata (time, duration, packet count)
- Full device database with RSSI history
- All decoded packets (last 10,000)

#### CSV (`--csv FILE`)

Spreadsheet-ready device list with:

- MAC, Name, Manufacturer
- RSSI statistics (min, max, avg)
- Services, TX Power, Appearance
- First/last seen timestamps

#### HTML (`--html FILE`)

Visual report featuring:

- Statistics dashboard
- Sortable device table
- RSSI color coding
- Packet type distribution

### 🏭 Manufacturer Identification

Automatically identifies 100+ manufacturers from MAC OUI:

| Vendor            | Example MACs                 |
| ----------------- | ---------------------------- |
| Apple             | 00:1C:B3, 28:CF:DA, 3C:07:54 |
| Samsung           | 50:01:BB, 8C:77:12, BC:20:A4 |
| Google            | 3C:5A:B4, 54:60:09, F8:8F:CA |
| Xiaomi            | 04:CF:8C, 58:44:98, C4:6A:B7 |
| Espressif         | 24:0A:C4, 30:AE:A4, A4:CF:12 |
| Nordic            | C0:A5:E3, F0:5C:D5           |
| Texas Instruments | 34:03:DE, 78:C5:E5           |

### 🔧 Service UUID Decoding

Recognizes standard BLE services:

| UUID   | Service                     |
| ------ | --------------------------- |
| 0x180D | Heart Rate                  |
| 0x180F | Battery                     |
| 0x180A | Device Information          |
| 0x1826 | Fitness Machine             |
| 0x181A | Environmental Sensing       |
| 0x1812 | Human Interface Device      |
| 0xFEAA | Google Eddystone            |
| 0xFD6F | Apple Exposure Notification |

### 📱 Device Tracking

For each discovered device, tracks:

- MAC address and type (public/random)
- Device name (from ADV or SCAN_RSP)
- Manufacturer (from OUI database)
- RSSI history (min, max, average)
- TX Power level
- Appearance category
- Service UUIDs
- Company ID from manufacturer data
- Advertisement types seen
- Packet count
- First/last seen timestamps

## Command Reference

### Basic Options

```
-p, --port PORT      Serial port (required)
-b, --baud RATE      Baud rate (default: 115200)
-o, --output FILE    Output PCAP file (default: capture.pcap)
--fifo               Use FIFO for real-time Wireshark
-v, --verbose        Show decoded packet details
-q, --quiet          Suppress progress dots
--no-color           Disable colored output
```

### Filtering

```
--filter-mac MAC     Only capture packets from this MAC
--filter-name NAME   Filter by device name (substring match)
--min-rssi RSSI      Only capture if RSSI >= threshold
```

### Export

```
--json FILE          Export full data to JSON
--csv FILE           Export device list to CSV
--html FILE          Generate HTML report
```

## Examples

### Capture Everything

```bash
python sniffer.py -p /dev/tty.usbserial-110 -o full_capture.pcap
```

### Monitor Specific Device

```bash
python sniffer.py -p /dev/tty.usbserial-110 \
    --filter-mac AA:BB:CC:DD:EE:FF \
    --verbose
```

### Find Apple Devices

```bash
python sniffer.py -p /dev/tty.usbserial-110 \
    --filter-name "" \
    --csv apple_devices.csv \
    -v 2>&1 | grep -i apple
```

### Survey Strong Nearby Devices

```bash
python sniffer.py -p /dev/tty.usbserial-110 \
    --min-rssi -50 \
    --html nearby.html \
    --json nearby.json
```

### Long-Running Capture

```bash
python sniffer.py -p /dev/tty.usbserial-110 \
    -o capture_$(date +%Y%m%d_%H%M).pcap \
    --json survey_$(date +%Y%m%d_%H%M).json \
    --html survey_$(date +%Y%m%d_%H%M).html \
    -q
```

## Output Examples

### Terminal Output (Verbose Mode)

```
╔══════════════════════════════════════════════════════════╗
║         BL602 BLE Sniffer - Enhanced v3.0                ║
╚══════════════════════════════════════════════════════════╝

Connected to /dev/tty.usbserial-110 @ 115200 baud
Capturing... (Ctrl+C to stop)

  EVT LE Advertising Report [AA:BB:CC:DD:EE:FF "iPhone" -62dBm svc:2]
  EVT LE Advertising Report [11:22:33:44:55:66 "Mi Band" -78dBm]
  CMD LE Controller OCF=0x00B
  EVT Command Complete

═══════════════════════════════════════════════════════════════════
📊 BLE Sniffer Statistics (running 60s)
═══════════════════════════════════════════════════════════════════
  Packets:  1,234 (20.6/sec)
  Data:     45,678 bytes (44.6 KB)
  Devices:  23 unique
  Errors:   0

  Packet Types:
    HCI_EVT: 1150 (93.2%)
    HCI_CMD: 84 (6.8%)

  Top Devices:
    AA:BB:CC:DD:EE:FF "iPhone" [Apple]
      RSSI: -62dBm (min:-68, max:-55), Pkts: 142
═══════════════════════════════════════════════════════════════════
```

### JSON Export Structure

```json
{
	"capture_info": {
		"start_time": "2025-11-30T15:00:00",
		"end_time": "2025-11-30T15:05:00",
		"duration_seconds": 300,
		"total_packets": 6420,
		"bytes_captured": 256840,
		"errors": 0
	},
	"statistics": {
		"packet_types": { "HCI_EVT": 6200, "HCI_CMD": 220 },
		"packets_per_second": 21.4
	},
	"devices": [
		{
			"mac": "AA:BB:CC:DD:EE:FF",
			"name": "iPhone",
			"manufacturer": "Apple",
			"addr_type": "random",
			"rssi_min": -72,
			"rssi_max": -55,
			"rssi_avg": -63.5,
			"tx_power": 4,
			"appearance": "Generic Phone",
			"services": ["Generic Access", "Battery"],
			"company_id": "0x004C",
			"company_name": "Apple",
			"first_seen": "2025-11-30T15:00:01",
			"last_seen": "2025-11-30T15:04:58",
			"packet_count": 342,
			"adv_types": ["ADV_IND", "SCAN_RSP"]
		}
	],
	"packets": [
		{
			"timestamp": 1732975200.123,
			"timestamp_iso": "2025-11-30T15:00:00.123",
			"packet_type": "HCI_EVT",
			"raw_hex": "043e1b0201...",
			"mac": "AA:BB:CC:DD:EE:FF",
			"rssi": -62,
			"name": "iPhone",
			"event_code": 62,
			"subevent": 2
		}
	]
}
```

## Troubleshooting

### Serial Port Issues

**Find port:**

```bash
# macOS
ls /dev/tty.usb*

# Linux
ls /dev/ttyUSB* /dev/ttyACM*
```

**Permission denied:**

```bash
# Linux
sudo usermod -a -G dialout $USER
# Then logout and login
```

### Parse Errors

If you see "Failed to parse" messages:

1. Ensure firmware is up to date
2. Check baud rate matches (115200)
3. Try resetting the BL602

### No Packets

1. Verify BLE devices are nearby
2. Check if firmware is running (`[SCANNER] BLE scan started`)
3. Try lowering `--min-rssi` threshold

### Wireshark FIFO Issues

1. Ensure script is running before starting Wireshark
2. Use correct path: `wireshark -k -i capture.pcap`
3. Check FIFO exists: `ls -la capture.pcap`

## License

Part of the BL602 IoT SDK project.
