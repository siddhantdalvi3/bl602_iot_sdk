# BLE Sniffer for BL602

This is a BLE sniffer we built for the BL602 chip (PineCone). It grabs BLE packets and sends them over UART.
There's a Python script to parse the data and a web UI if you want to be fancy.

## What's in here

- `suas_app_ble_sniffer/`: The C++ firmware for the BL602.
- `ble_sniffer_py/`: Python script to read from UART and dump data.
- `web_ui/`: Next.js dashboard.

## Performance

We ran a quick test:

- **Duration**: 53 seconds
- **Packets captured**: 2,076
- **Throughput**: ~39 packets/sec
- **Parsing success**: 99.95%

Not bad for a $2 chip!

## Getting Started

1. **Flash the firmware**:

   ```bash
   cd customer_app/suas_app_ble_sniffer
   make clean && make
   # Flash it to your board
   ```

2. **Run the Python script**:

   ```bash
   cd ble_sniffer_py
   pip install -r requirements.txt
   python sniffer.py /dev/ttyUSB0
   ```

3. **(Optional) Run the Web UI**:
   The Python script has a websocket server (port 8765).
   ```bash
   cd web_ui
   npm install
   npm run dev
   ```

## Notes

- The OUI database in the Python script is pretty basic. You might want to update it.
- The firmware buffer is set to 80 packets. If you're in a busy area, you might drop some.

## Credits (Group 05)

- Md Murshid Alam
- Siddhant Dalvi
- Parinaz Teimouri
- Yeasin Arafat
- Pranto Protim Roy
