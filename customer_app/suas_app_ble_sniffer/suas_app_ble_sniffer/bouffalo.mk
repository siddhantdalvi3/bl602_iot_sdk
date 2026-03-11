# Include bluetooth stack
include $(BL60X_SDK_PATH)/components/network/ble/ble_common.mk

# Additional configuration for BLE sniffer
CFLAGS += -DCONFIG_NET_BUF_USER_DATA_SIZE=4
CFLAGS += -DCONFIG_BT_MAX_PAIRED=0
CFLAGS += -DCONFIG_BT_GATT_CCC_MAX=1
CFLAGS += -DCFG_CON=1  # CFG_CON macro for Bluetooth stack
CFLAGS += -DBFLB_BLE  # hci_driver_init function required config

# only compatible CFLAGS to CXXFLAGS for C++ compilation
CXXFLAGS += -DCONFIG_NET_BUF_USER_DATA_SIZE=4
CXXFLAGS += -DCONFIG_BT_MAX_PAIRED=0
CXXFLAGS += -DCONFIG_BT_GATT_CCC_MAX=1
CXXFLAGS += -DCFG_CON=1  # CFG_CON macro for Bluetooth stack
CXXFLAGS += -DBFLB_BLE  # hci_driver_init function required config

# Disable unused parameter warnings for Bluetooth stack headers
CXXFLAGS += -Wno-unused-parameter
