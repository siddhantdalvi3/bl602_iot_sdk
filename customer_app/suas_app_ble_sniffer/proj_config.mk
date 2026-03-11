#
# Project configuration for BLE Sniffer App
#

# Enable Bluetooth
CONFIG_BT:=1

# Enable BLE Observer mode (for scanning)
CONFIG_BT_OBSERVER:=1

# Enable BLE Controller
CONFIG_BT_CTLR:=1

# Enable BLE Host
CONFIG_BT_HOST:=1

# Enable HCI Dump for Sniffer
CONFIG_BTSOONP_PRINT:=1

# Increase RX buffer count for high-traffic sniffing
# Default is 5-10, increase to handle more packets
CONFIG_BT_RX_BUF_COUNT:=200

# Rate-limited btsnoop output (print every Nth packet)
# Set to 1 for all packets, higher for less output
CONFIG_BTSNOOP_RATE_LIMIT:=1

# Additional Bluetooth stack configuration (from working sender project)
CONFIG_BT_PERIPHERAL:=1
CONFIG_BT_CENTRAL:=1
CONFIG_BT_CONN:=1
CONFIG_BT_SMP:=1
CONFIG_BT_SETTINGS:=1
CONFIG_BLE_STACK_DBG_PRINT:=1

# Additional required configurations for net_buf and other components
CONFIG_NET_BUF_USER_DATA_SIZE:=4
CONFIG_BT_MAX_PAIRED:=0
CONFIG_BT_GATT_CCC_MAX:=1
