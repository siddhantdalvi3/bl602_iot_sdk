# BLE Sniffer Python Tools

Just some Python scripts to grab data from the BL602 over UART.
It parses the HCI packets and can dump them to Wireshark (via a pipe), JSON, CSV, or a simple HTML report.

## How to use

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Run it:

   ```bash
   # Basic usage
   python sniffer.py /dev/ttyUSB0

   # Export data to HTML report, JSON, and CSV
   python sniffer.py /dev/ttyUSB0 --html report.html --json capture.json --csv devices.csv

   # Verbose mode (see packet details in terminal)
   python sniffer.py /dev/ttyUSB0 -v

   # Live Wireshark streaming (requires Wireshark installed)
   python sniffer.py /dev/ttyUSB0 --fifo
   ```

   (Replace `/dev/ttyUSB0` with your actual serial port. On Mac it's usually `/dev/tty.usbserial...`)

## Features

- **Rich Reporting**: Generate professional HTML dashboards, CSV device lists, and JSON dumps.
- **Wireshark Integration**: Live streaming to Wireshark via named pipe (FIFO).
- **Vendor Identification**: Automatically identifies vendors (Apple, Samsung, etc.) from MAC addresses.
- **GATT Parsing**: Decodes Battery, Heart Rate, and Device Info services.

## TODO

- [ ] Fix the occasional crash when the serial port disconnects
- [ ] Add more vendor IDs (the list is kinda short right now)
- [ ] Make the web UI better
