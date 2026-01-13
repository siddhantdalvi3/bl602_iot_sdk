# Source files
COMPONENT_SRCS := main.cpp central.cpp peripheral.cpp

# Include bluetooth stack
include $(BL60X_SDK_PATH)/components/network/ble/ble_common.mk

# Propagate CFLAGS to CXXFLAGS (excluding C standard)
CXXFLAGS += $(filter-out -std=% -Wno-int-conversion,$(CFLAGS))
CXXFLAGS += -Wno-missing-field-initializers