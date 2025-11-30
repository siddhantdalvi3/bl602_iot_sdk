#
# Project configuration for BLE Sniffer App
#

# Enable Bluetooth
CONFIG_BT:=1

# Enable BLE Observer mode (for scanning)
CONFIG_BT_OBSERVER:=1

# Optional: Enable BLE Controller
CONFIG_BT_CTLR:=1

# Optional: Enable BLE Host
CONFIG_BT_HOST:=1

# Enable HCI Dump for Sniffer
CONFIG_BTSOONP_PRINT:=1

# Increase RX buffer count for high-traffic sniffing
# Default is 5-10, increase to handle more packets
CONFIG_BT_RX_BUF_COUNT:=40

# Rate-limited btsnoop output (print every Nth packet)
# Set to 1 for all packets, higher for less output
CONFIG_BTSNOOP_RATE_LIMIT:=1
