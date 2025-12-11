# BLE Sniffer Python Tools

Python utilities for capturing and analyzing BLE packets from BL602 with GATT service discovery, battery level tracking, and manufacturer identification.

**Latest Updates (Phase 2.5):**
- ✅ GATT service UUID detection (Battery, Device Info, Heart Rate, etc.)
- ✅ Battery level extraction from manufacturer data
- ✅ Robust error handling for malformed packets
- ✅ Enhanced CSV with GATT fields (9 new columns)
- ✅ HTML report with battery indicators and service badges
- ✅ Memory optimized firmware (80-packet buffer, 127-byte payload)

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
# Basic capture and export all formats
python sniffer.py -p /dev/tty.usbserial-110 \
    --json data.json --csv devices.csv --html report.html

# Verbose capture (see packet details and GATT parsing)
python sniffer.py -p /dev/tty.usbserial-110 -v

# Monitor specific device with GATT data
python sniffer.py -p /dev/tty.usbserial-110 \
    --filter-mac AA:BB:CC:DD:EE:FF --verbose

# Long-running survey (all formats with timestamped outputs)
python sniffer.py -p /dev/tty.usbserial-110 \
    --json survey_$(date +%s).json \
    --csv devices_$(date +%s).csv \
    --html report_$(date +%s).html
```

## 🆕 Phase 2.5: GATT Service Parsing

### 🔋 Battery Level Tracking

Automatically extracts battery levels from manufacturer data:

- **Samsung (0x0075)**: Reads battery percentage from manufacturer data
- **Other vendors**: Framework ready for expansion
- **CSV Column**: "Battery Level (%)" - shows percentage or blank if unavailable
- **HTML Display**: Color-coded battery bar (red <20%, yellow 20-50%, green >50%)

### 🛍️ GATT Service Detection

Identifies advertised GATT services in real-time:

| Service UUID | Name           | Badge | Tracking |
| ------------ | -------------- | ----- | --------- |
| 0x180F       | Battery        | 🔋    | has_battery_service |
| 0x180A       | Device Info    | ℹ️    | has_device_info_service |
| 0x180D       | Heart Rate     | ❤️    | has_heart_rate_service |
| 0x1802       | Immediate Alert| ⚠️    | Detected in GATT |
| 0x1803       | Link Loss      | 🔗    | Detected in GATT |
| 0x1804       | TX Power       | 📡    | Detected in GATT |
| 0x1826       | Fitness Machine| 💪    | Detected in GATT |
| 0x181A       | Environmental  | 🌡️    | Detected in GATT |
| 0x1812       | HID            | 🖱️    | Detected in GATT |

### 📊 Multiple Export Formats

#### JSON (`--json FILE`)

Complete capture data with **GATT extensions**:

- Capture metadata (time, duration, packet count)
- Full device database with RSSI history and **battery levels**
- **services_detected**: GATT service detection flags (battery, device_info, heart_rate)
- **GATT fields**: manufacturer_name, model_number, firmware_revision
- All decoded packets (last 10,000)

#### CSV (`--csv FILE`)

Spreadsheet-ready device list with **9 new GATT columns**:

- MAC, Name, Manufacturer, Address Type
- RSSI statistics (min, max, avg)
- **Battery Level (%)** - extracted from manufacturer data
- **Manufacturer Name** - from GATT Device Info
- **Model Number** - from GATT Device Info
- **Firmware Revision** - from GATT Device Info
- **Has Battery Service** (Yes/No)
- **Has Device Info Service** (Yes/No)
- **Has Heart Rate Service** (Yes/No)
- First/last seen timestamps, Packet count

#### HTML (`--html FILE`)

Interactive visual report with **GATT enhancements**:

- Statistics dashboard with device count and errors
- **Sortable device table** with battery column
- **Color-coded battery bars**: Red (<20%), Yellow (20-50%), Green (>50%)
- **GATT Service badges**: Visual indicators for detected services
- **Device Info section**: Displays manufacturer, model, firmware revision
- RSSI heat map (color gradient: green strong → red weak)
- Packet type distribution chart

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
- Manufacturer (from OUI database and company ID)
- RSSI history (min, max, average)
- TX Power level
- Appearance category
- Service UUIDs advertised
- **Company ID from manufacturer data**
- **Battery Level** (when available)
- **GATT Service flags**: Battery, Device Info, Heart Rate
- **Device Information**: Manufacturer name, Model number, Firmware revision
- Advertisement types seen
- Packet count
- First/last seen timestamps

### 🛡️ Robust Error Handling

- **Malformed packet detection**: Gracefully handles invalid HCI packets
- **Parse error recovery**: Continues capturing even if individual packets fail to parse
- **Silent skipping**: Unparseable packets are logged but don't crash the sniffer
- **Real-world validation**: Successfully processes 2,000+ packets with mixed device types

### ⚙️ Hardware Optimizations

**Memory-optimized firmware (Phase 2.5)**:
- Buffer size: 80 packets (reduced from 200)
- Payload size: 127 bytes (reduced from 255)
- Manufacturer data: 48 bytes (reduced from 64)
- **Result**: Successfully compiles on BL602 with tight RAM constraints (~160KB)

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

### Capture with Full GATT Analysis

```bash
python sniffer.py -p /dev/tty.usbserial-110 \
    --csv devices.csv --json data.json --html report.html -v
```
**Outputs:**
- `devices.csv`: All 9 GATT columns (battery, manufacturer_name, services)
- `data.json`: GATT data in services_detected object
- `report.html`: Battery bars and service badges
- Console: GATT parsing details for each device

### Monitor Specific Device with GATT Tracking

```bash
python sniffer.py -p /dev/tty.usbserial-110 \
    --filter-mac AA:BB:CC:DD:EE:FF \
    --csv single_device.csv --verbose
```
**Tracks**: RSSI, battery level, service advertisements for that device

### Find Devices Advertising Battery Service

```bash
python sniffer.py -p /dev/tty.usbserial-110 \
    --csv devices.csv --json data.json -q
# Then inspect CSV for "Has Battery Service = Yes"
```

### Survey Strong Nearby Devices with GATT

```bash
python sniffer.py -p /dev/tty.usbserial-110 \
    --min-rssi -50 \
    --html nearby.html --csv nearby.csv --json nearby.json
```
**Results**: Only devices with strong signal (-50dBm or better), with GATT data

### Long-Running Background Capture

```bash
# Capture continuously for analysis
python sniffer.py -p /dev/tty.usbserial-110 \
    --json survey_$(date +%Y%m%d_%H%M%S).json \
    --csv devices_$(date +%Y%m%d_%H%M%S).csv \
    --html report_$(date +%Y%m%d_%H%M%S).html \
    --quiet  # No console output
```

### Test Battery Level Extraction (Samsung Devices)

```bash
python sniffer.py -p /dev/tty.usbserial-110 \
    --csv samsung_devices.csv -v 2>&1 | grep -i battery
```
**Note**: Battery levels appear in CSV when Samsung devices advertise manufacturer data

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

### JSON Export Structure (Phase 2.5 Enhanced)

```json
{
	"capture_info": {
		"start_time": "2025-12-11T15:00:00",
		"end_time": "2025-12-11T15:05:00",
		"duration_seconds": 300,
		"total_packets": 2076,
		"bytes_captured": 320450,
		"errors": 1
	},
	"statistics": {
		"packet_types": { "HCI_EVT": 2046, "HCI_CMD": 30 },
		"packets_per_second": 39.3
	},
	"devices": [
		{
			"mac": "5B:14:F7:CC:A7:89",
			"name": "",
			"manufacturer": "Apple",
			"addr_type": "random",
			"rssi_min": -89,
			"rssi_max": -62,
			"rssi_avg": -72.5,
			"tx_power": 0,
			"appearance": "",
			"battery_level": null,
			"manufacturer_name": "",
			"model_number": "",
			"firmware_rev": "",
			"services_detected": {
				"battery": false,
				"device_info": false,
				"heart_rate": false
			},
			"company_id": "0x004C",
			"company_name": "Apple",
			"mfg_data_hex": "0c0e00bb408f0ca4c78d63c7",
			"first_seen": "2025-12-11T15:00:01",
			"last_seen": "2025-12-11T15:04:58",
			"packet_count": 342,
			"adv_types": ["ADV_IND"]
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

### Parse Errors (Phase 2.5 Improved)

**New behavior**: Malformed packets are skipped silently (no crashes)

If you see occasional "Parse error" messages:

1. This is **normal** for ~1 error per 2,000 packets
2. Sniffer automatically continues capturing
3. Check battery level extraction with: `grep 'battery' devices.csv`
4. Verify GATT service detection in: `cat devices.json | grep services_detected`

If GATT data is empty (battery_level=null, services=false):

1. **This is expected** - most consumer devices don't advertise services in passive mode
2. Test with smartwatch or fitness tracker (e.g., Samsung, Xiaomi, Fitbit)
3. Verify manufacturer data parsing: `grep 'mfg_data' devices.json`

### Firmware Issues

1. Ensure firmware is up to date (Phase 2.5 or later)
2. Check compilation: `make clean && make`
3. Verify baud rate: 115200
4. Reset BL602: Power cycle or `make flash`

### No Packets

1. Verify BLE devices are nearby and advertising
2. Check if firmware is running (`[SCANNER] BLE scan started`)
3. Try lowering `--min-rssi` threshold (e.g., -90)
4. Check serial connection: `cat /dev/tty.usbserial-110` (should show logs)

### Memory Issues (Firmware)

If you see "section `.bss' will not fit in region `ram_tcm'":

1. Firmware uses optimized buffer sizes (Phase 2.5)
2. Check sniffer.h: SNIFFER_BUFFER_SIZE=80 (not higher)
3. Verify payload size: 127 bytes (not higher)
4. Ensure Makefile includes `project.mk` for correct flags

## System Architecture (Phase 2.5)

### Data Flow

```
BLE Devices
    |
    v
[BL602 Scanner (Promiscuous Mode)]
    |
    v
sniffer.c: parse_gatt_services()
  - Detects service UUIDs (0x180F, 0x180A, 0x180D, etc.)
  - Extracts battery from manufacturer data (Samsung: offset 3)
  - Buffers 80 packets (optimized)
    |
    v
Serial Output (HCI format)
    |
    v
Python sniffer.py: parse_line() + parse_ad_structures()
  - Error-safe HCI parsing (try-catch all malformed packets)
  - GATT data extraction (battery, services, device info)
  - Device database (_update_device)
    |
    v
+---------------------+
| CSV (9 GATT columns)|
| JSON (services)     |  <- Real-time or on-demand
| HTML (visual)       |
+---------------------+
```

### Key Improvements Over Phase 2.4

| Feature | Phase 2.4 | Phase 2.5 | Impact |
| ------- | --------- | --------- | ------ |
| Buffer Size | 200 packets | 80 packets | Fits in RAM (memory overflow fixed) |
| GATT Services | Not parsed | Service UUIDs detected | Device capability discovery |
| Battery Tracking | Not supported | Samsung extraction | Health monitoring |
| Error Handling | Crashes on bad packets | Graceful skip | Continuous operation |
| CSV Columns | 7 | 16 | Comprehensive device profiling |
| HTML Display | Basic stats | Visual indicators | Better data interpretation |
| Firmware Size | ~3.5MB | ~3.6MB | Optimized within constraints |

### Testing Results

**Real-world validation (Dec 11, 2025)**:
- Captured 2,076 packets in 53 seconds (39.3 packets/second)
- Identified 13+ unique devices
- 1 parse error in 2,076 packets (acceptable)
- CSV generated with all 9 GATT columns
- JSON structure correct with services_detected object
- Zero crashes during continuous capture

## Future Work (Phase 3+)

- Connection state tracking (connection/disconnection events)
- Encrypted packet detection and session establishment monitoring
- Enhanced manufacturer data parsing for more vendors
- GATT characteristic-level tracking (notifications, indications)
- Real-time dashboard with WebSocket streaming

## License

Part of the BL602 IoT SDK project.
