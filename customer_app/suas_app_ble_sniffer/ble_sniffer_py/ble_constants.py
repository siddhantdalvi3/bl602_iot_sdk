# BLE Constants for Sniffer
# Separated for better maintainability

# Common vendors I see around.
# TODO: Maybe sync this with an online OUI database later?
OUI_DATABASE = {
    # Apple
    "00:1C:B3": "Apple",
    "00:03:93": "Apple",
    "00:0A:95": "Apple",
    # ... lots of Apple OUIs, keeping just a few common ones for now
    "AC:BC:32": "Apple",
    "B0:65:BD": "Apple",

    # Samsung
    "00:12:47": "Samsung",
    "00:13:77": "Samsung",

    # Espressif (common in IoT)
    "24:0A:C4": "Espressif",
    "24:6F:28": "Espressif",

    # Nordic
    "C0:A5:E3": "Nordic",

    # Bouffalo Lab
    "18:B9:05": "Bouffalo Lab",

    # TI
    "00:12:37": "TI",
}

# BLE Company Identifiers (Bluetooth SIG)
COMPANY_IDS = {
    0x0006: "Microsoft",
    0x004C: "Apple",
    0x0075: "Samsung",
    0x0087: "Garmin",
    0x00D2: "Google",
    0x00E0: "Google",
    0x0157: "Polar",
    0x01D2: "Xiaomi",
    0x0310: "Amazfit",
    0x038F: "Xiaomi",
    0x0822: "adidas",
    0x09A8: "Shenzhen",
    0x0B37: "Anker"
}

# BLE Service UUIDs (16-bit)
SERVICE_UUIDS = {
    0x1800: "Generic Access",
    0x1801: "Generic Attribute",
    0x1802: "Immediate Alert",
    0x1803: "Link Loss",
    0x1804: "Tx Power",
    0x1805: "Current Time",
    0x1806: "Reference Time Update",
    0x1807: "Next DST Change",
    0x1808: "Glucose",
    0x1809: "Health Thermometer",
    0x180A: "Device Information",
    0x180D: "Heart Rate",
    0x180E: "Phone Alert Status",
    0x180F: "Battery",
    0x1810: "Blood Pressure",
    0x1811: "Alert Notification",
    0x1812: "Human Interface Device",
    0x1813: "Scan Parameters",
    0x1814: "Running Speed and Cadence",
    0x1815: "Automation IO",
    0x1816: "Cycling Speed and Cadence",
    0x1818: "Cycling Power",
    0x1819: "Location and Navigation",
    0x181A: "Environmental Sensing",
    0x181B: "Body Composition",
    0x181C: "User Data",
    0x181D: "Weight Scale",
    0x181E: "Bond Management",
    0x181F: "Continuous Glucose Monitoring",
    0x1820: "Internet Protocol Support",
    0x1821: "Indoor Positioning",
    0x1822: "Pulse Oximeter",
    0x1823: "HTTP Proxy",
    0x1824: "Transport Discovery",
    0x1825: "Object Transfer",
    0x1826: "Fitness Machine",
    0x1827: "Mesh Provisioning",
    0x1828: "Mesh Proxy",
    0xFE9F: "Google",
    0xFEAA: "Google Eddystone",
    0xFD6F: "Apple Exposure Notification",
}

# GATT Characteristics (16-bit UUIDs)
GATT_CHARACTERISTICS = {
    0x2A00: "Device Name",
    0x2A01: "Appearance",
    0x2A02: "Peripheral Privacy Flag",
    0x2A03: "Reconnection Address",
    0x2A04: "Peripheral Preferred Connection Parameters",
    0x2A05: "Service Changed",
    0x2A19: "Battery Level",
    0x2A24: "Model Number String",
    0x2A25: "Serial Number String",
    0x2A26: "Firmware Revision String",
    0x2A27: "Hardware Revision String",
    0x2A28: "Software Revision String",
    0x2A29: "Manufacturer Name String",
    0x2A37: "Heart Rate Measurement",
    0x2A38: "Body Sensor Location",
    0x2A8E: "TX Power Level",
}

# BLE Appearance values
APPEARANCES = {
    0x0000: "Unknown",
    0x0040: "Generic Phone",
    0x0080: "Generic Computer",
    0x00C0: "Generic Watch",
    0x00C1: "Sports Watch",
    0x0100: "Generic Clock",
    0x0140: "Generic Display",
    0x0180: "Generic Remote Control",
    0x01C0: "Generic Eye-glasses",
    0x0200: "Generic Tag",
    0x0240: "Generic Keyring",
    0x0280: "Generic Media Player",
    0x02C0: "Generic Barcode Scanner",
    0x0300: "Generic Thermometer",
    0x0340: "Generic Heart Rate Sensor",
    0x0380: "Generic Blood Pressure",
    0x03C0: "Generic HID",
    0x03C1: "Keyboard",
    0x03C2: "Mouse",
    0x03C3: "Joystick",
    0x03C4: "Gamepad",
    0x0440: "Generic Glucose Meter",
    0x0480: "Generic Running/Walking Sensor",
    0x04C0: "Generic Cycling",
    0x0540: "Generic Pulse Oximeter",
    0x0580: "Generic Weight Scale",
    0x05C0: "Generic Outdoor Sports",
}

# HCI Event Code Names
HCI_EVENT_NAMES = {
    0x0E: "Command Complete",
    0x0F: "Command Status",
    0x3E: "LE Meta Event",
    0x13: "Number of Completed Packets",
    0x05: "Disconnection Complete",
    0x08: "Encryption Change",
    0x0C: "Read Remote Version Complete",
    0x10: "Hardware Error",
}

# LE Meta Subevent Names
LE_META_SUBEVENTS = {
    0x01: "LE Connection Complete",
    0x02: "LE Advertising Report",
    0x03: "LE Connection Update Complete",
    0x04: "LE Read Remote Features Complete",
    0x05: "LE Long Term Key Request",
    0x06: "LE Remote Connection Parameter Request",
    0x07: "LE Data Length Change",
    0x0A: "LE Enhanced Connection Complete",
    0x0D: "LE Extended Advertising Report",
}

# HCI Command OGF Names
HCI_OGF_NAMES = {
    0x01: "Link Control",
    0x02: "Link Policy",
    0x03: "Controller & Baseband",
    0x04: "Informational",
    0x05: "Status",
    0x08: "LE Controller",
}
