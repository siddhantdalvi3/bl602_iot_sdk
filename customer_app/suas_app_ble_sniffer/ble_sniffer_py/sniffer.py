#!/usr/bin/env python3
"""
BL602 BLE Sniffer - Enhanced v3.0
=================================
Comprehensive BLE packet capture with multiple output formats.

Features:
- Real-time Wireshark integration (PCAP/FIFO)
- JSON export for data analysis
- CSV export for spreadsheets
- HTML report generation
- Device database with manufacturer lookup
- Full advertisement data decoding
- Statistics and analytics

Author: BL602 IoT SDK Team
"""

import serial
import time
import struct
import argparse
import re
import os
import json
import csv
from collections import defaultdict
from datetime import datetime
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path


# =============================================================================
# ANSI Colors
# =============================================================================
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'

    @staticmethod
    def disable():
        Colors.RESET = Colors.RED = Colors.GREEN = ''
        Colors.YELLOW = Colors.BLUE = Colors.MAGENTA = ''
        Colors.CYAN = Colors.GRAY = Colors.BOLD = ''


# =============================================================================
# OUI Manufacturer Database (IEEE)
# =============================================================================
OUI_DATABASE = {
    # Apple
    "00:1C:B3": "Apple",
    "00:03:93": "Apple",
    "00:0A:95": "Apple",
    "00:17:F2": "Apple",
    "00:1E:52": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "28:CF:DA": "Apple",
    "34:C0:59": "Apple",
    "3C:07:54": "Apple",
    "40:33:1A": "Apple",
    "54:4E:90": "Apple",
    "58:B0:35": "Apple",
    "5C:F7:E6": "Apple",
    "60:C5:47": "Apple",
    "78:31:C1": "Apple",
    "78:CA:39": "Apple",
    "84:85:06": "Apple",
    "8C:85:90": "Apple",
    "9C:04:EB": "Apple",
    "A4:B1:97": "Apple",
    "A8:86:DD": "Apple",
    "AC:BC:32": "Apple",
    "B0:65:BD": "Apple",
    "B8:C7:5D": "Apple",
    "B8:E8:56": "Apple",
    "BC:52:B7": "Apple",
    "C4:2C:03": "Apple",
    "C8:69:CD": "Apple",
    "CC:08:E0": "Apple",
    "D0:E1:40": "Apple",
    "D4:F4:6F": "Apple",
    "DC:2B:2A": "Apple",
    "E0:B5:2D": "Apple",
    "F0:B4:79": "Apple",
    "F4:1B:A1": "Apple",

    # Samsung
    "00:12:47": "Samsung",
    "00:13:77": "Samsung",
    "00:15:99": "Samsung",
    "00:16:32": "Samsung",
    "00:17:C9": "Samsung",
    "00:17:D5": "Samsung",
    "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung",
    "00:1C:43": "Samsung",
    "00:1D:25": "Samsung",
    "00:1D:F6": "Samsung",
    "00:1E:7D": "Samsung",
    "00:1F:CC": "Samsung",
    "00:1F:CD": "Samsung",
    "00:21:4C": "Samsung",
    "00:21:D1": "Samsung",
    "00:21:D2": "Samsung",
    "50:01:BB": "Samsung",
    "50:F5:20": "Samsung",
    "54:88:0E": "Samsung",
    "5C:0A:5B": "Samsung",
    "78:BD:BC": "Samsung",
    "8C:77:12": "Samsung",
    "94:35:0A": "Samsung",
    "A0:82:1F": "Samsung",
    "AC:5F:3E": "Samsung",
    "BC:20:A4": "Samsung",
    "C4:42:02": "Samsung",
    "C8:38:70": "Samsung",
    "D0:22:BE": "Samsung",
    "E4:7C:F9": "Samsung",
    "F8:04:2E": "Samsung",

    # Google
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "54:60:09": "Google",
    "94:EB:2C": "Google",
    "F4:F5:D8": "Google",
    "F8:8F:CA": "Google",

    # Microsoft
    "00:0D:3A": "Microsoft",
    "00:12:5A": "Microsoft",
    "00:15:5D": "Microsoft",
    "00:17:FA": "Microsoft",
    "00:1D:D8": "Microsoft",
    "00:22:48": "Microsoft",
    "00:25:AE": "Microsoft",
    "00:50:F2": "Microsoft",
    "28:18:78": "Microsoft",
    "7C:1E:52": "Microsoft",
    "7C:ED:8D": "Microsoft",

    # Amazon
    "00:FC:8B": "Amazon",
    "0C:47:C9": "Amazon",
    "10:CE:A9": "Amazon",
    "18:74:2E": "Amazon",
    "34:D2:70": "Amazon",
    "40:B4:CD": "Amazon",
    "44:65:0D": "Amazon",
    "50:DC:E7": "Amazon",
    "68:37:E9": "Amazon",
    "74:C2:46": "Amazon",
    "84:D6:D0": "Amazon",
    "A0:02:DC": "Amazon",
    "AC:63:BE": "Amazon",
    "B4:7C:9C": "Amazon",
    "F0:27:2D": "Amazon",
    "FC:65:DE": "Amazon",

    # Xiaomi
    "04:CF:8C": "Xiaomi",
    "0C:1D:AF": "Xiaomi",
    "10:2A:B3": "Xiaomi",
    "14:F6:5A": "Xiaomi",
    "18:59:36": "Xiaomi",
    "20:34:FB": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "34:80:B3": "Xiaomi",
    "38:A4:ED": "Xiaomi",
    "3C:BD:D8": "Xiaomi",
    "44:23:7C": "Xiaomi",
    "50:64:2B": "Xiaomi",
    "58:44:98": "Xiaomi",
    "64:09:80": "Xiaomi",
    "64:B4:73": "Xiaomi",
    "7C:1C:4E": "Xiaomi",
    "84:F3:EB": "Xiaomi",
    "8C:BE:BE": "Xiaomi",
    "98:FA:E3": "Xiaomi",
    "9C:99:A0": "Xiaomi",
    "A4:77:33": "Xiaomi",
    "B0:E2:35": "Xiaomi",
    "C4:6A:B7": "Xiaomi",
    "D4:97:0B": "Xiaomi",
    "E4:46:DA": "Xiaomi",
    "F0:B4:29": "Xiaomi",
    "F8:A4:5F": "Xiaomi",

    # Espressif (ESP32/ESP8266)
    "24:0A:C4": "Espressif",
    "24:6F:28": "Espressif",
    "24:B2:DE": "Espressif",
    "30:AE:A4": "Espressif",
    "3C:61:05": "Espressif",
    "3C:71:BF": "Espressif",
    "40:F5:20": "Espressif",
    "48:3F:DA": "Espressif",
    "4C:11:AE": "Espressif",
    "5C:CF:7F": "Espressif",
    "60:01:94": "Espressif",
    "68:C6:3A": "Espressif",
    "7C:9E:BD": "Espressif",
    "80:7D:3A": "Espressif",
    "84:0D:8E": "Espressif",
    "84:CC:A8": "Espressif",
    "84:F3:EB": "Espressif",
    "8C:AA:B5": "Espressif",
    "94:B9:7E": "Espressif",
    "98:F4:AB": "Espressif",
    "A0:20:A6": "Espressif",
    "A4:7B:9D": "Espressif",
    "A4:CF:12": "Espressif",
    "AC:67:B2": "Espressif",
    "B4:E6:2D": "Espressif",
    "BC:DD:C2": "Espressif",
    "C4:4F:33": "Espressif",
    "C8:2B:96": "Espressif",
    "CC:50:E3": "Espressif",
    "D8:A0:1D": "Espressif",
    "DC:4F:22": "Espressif",
    "E0:98:06": "Espressif",
    "E8:DB:84": "Espressif",
    "EC:FA:BC": "Espressif",
    "F0:08:D1": "Espressif",
    "F4:CF:A2": "Espressif",

    # Nordic Semiconductor
    "C0:A5:E3": "Nordic",
    "C6:5A:B8": "Nordic",
    "D4:CA:6E": "Nordic",
    "E7:8B:2E": "Nordic",
    "F0:5C:D5": "Nordic",
    "F2:4E:B9": "Nordic",

    # Bouffalo Lab (BL602)
    "18:B9:05": "Bouffalo Lab",

    # Texas Instruments
    "00:12:37": "Texas Instruments",
    "00:17:83": "Texas Instruments",
    "00:18:30": "Texas Instruments",
    "00:18:31": "Texas Instruments",
    "00:18:32": "Texas Instruments",
    "00:18:33": "Texas Instruments",
    "00:18:34": "Texas Instruments",
    "04:A3:16": "Texas Instruments",
    "34:03:DE": "Texas Instruments",
    "50:65:83": "Texas Instruments",
    "78:C5:E5": "Texas Instruments",
    "98:7B:F3": "Texas Instruments",
    "A0:E6:F8": "Texas Instruments",
    "B0:B4:48": "Texas Instruments",
    "C4:BE:84": "Texas Instruments",
    "D0:39:72": "Texas Instruments",
    "D0:B5:C2": "Texas Instruments",
    "D4:36:39": "Texas Instruments",
    "F4:B8:5E": "Texas Instruments",

    # Fitbit
    "39:91:FB": "Fitbit",
    "50:A4:D0": "Fitbit",
    "C0:D0:12": "Fitbit",

    # Tile
    "E4:F0:42": "Tile",
    "D0:03:4B": "Tile",
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


# =============================================================================
# Data Classes
# =============================================================================
@dataclass
class BLEDevice:
    """Represents a discovered BLE device"""
    mac: str
    name: str = ""
    manufacturer: str = ""
    addr_type: str = "public"
    rssi_min: int = 0
    rssi_max: int = -100
    rssi_avg: float = 0
    rssi_samples: List[int] = field(default_factory=list)
    tx_power: Optional[int] = None
    appearance: Optional[str] = None
    services: List[str] = field(default_factory=list)
    company_id: Optional[int] = None
    company_name: Optional[str] = None
    flags: int = 0
    first_seen: float = 0
    last_seen: float = 0
    packet_count: int = 0
    adv_types_seen: set = field(default_factory=set)
    raw_mfg_data: bytes = b''

    def update_rssi(self, rssi: int):
        self.rssi_samples.append(rssi)
        # Keep only last 100 samples
        if len(self.rssi_samples) > 100:
            self.rssi_samples = self.rssi_samples[-100:]
        self.rssi_min = min(self.rssi_samples)
        self.rssi_max = max(self.rssi_samples)
        self.rssi_avg = sum(self.rssi_samples) / len(self.rssi_samples)

    def to_dict(self) -> dict:
        return {
            'mac':
            self.mac,
            'name':
            self.name,
            'manufacturer':
            self.manufacturer,
            'addr_type':
            self.addr_type,
            'rssi_min':
            self.rssi_min,
            'rssi_max':
            self.rssi_max,
            'rssi_avg':
            round(self.rssi_avg, 1),
            'tx_power':
            self.tx_power,
            'appearance':
            self.appearance,
            'services':
            self.services,
            'company_id':
            f"0x{self.company_id:04X}" if self.company_id else None,
            'company_name':
            self.company_name,
            'flags':
            f"0x{self.flags:02X}",
            'first_seen':
            datetime.fromtimestamp(self.first_seen).isoformat()
            if self.first_seen else None,
            'last_seen':
            datetime.fromtimestamp(self.last_seen).isoformat()
            if self.last_seen else None,
            'packet_count':
            self.packet_count,
            'adv_types':
            list(self.adv_types_seen),
            'mfg_data_hex':
            self.raw_mfg_data.hex() if self.raw_mfg_data else None,
        }


@dataclass
class CapturePacket:
    """Represents a captured BLE packet with full metadata"""
    timestamp: float
    packet_type: str
    raw_data: bytes
    mac: Optional[str] = None
    rssi: Optional[int] = None
    name: Optional[str] = None
    event_code: Optional[int] = None
    subevent: Optional[int] = None
    adv_type: Optional[int] = None
    services: List[str] = field(default_factory=list)
    company_id: Optional[int] = None
    tx_power: Optional[int] = None
    flags: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso':
            datetime.fromtimestamp(self.timestamp).isoformat(),
            'packet_type': self.packet_type,
            'raw_hex': self.raw_data.hex(),
            'mac': self.mac,
            'rssi': self.rssi,
            'name': self.name,
            'event_code': self.event_code,
            'subevent': self.subevent,
            'adv_type': self.adv_type,
            'services': self.services,
            'company_id':
            f"0x{self.company_id:04X}" if self.company_id else None,
            'tx_power': self.tx_power,
            'flags': f"0x{self.flags:02X}" if self.flags else None,
        }


# =============================================================================
# Statistics Tracker
# =============================================================================
class SnifferStats:

    def __init__(self):
        self.start_time = time.time()
        self.total_packets = 0
        self.packet_types = defaultdict(int)
        self.devices: Dict[str, BLEDevice] = {}
        self.events_by_type = defaultdict(int)
        self.commands_by_ogf = defaultdict(int)
        self.bytes_captured = 0
        self.errors = 0
        self.last_print_time = time.time()
        self.all_packets: List[CapturePacket] = []
        self.max_packets_stored = 100000  # Limit memory usage

    def add_packet(self,
                   packet_data: bytes,
                   packet_info: Optional[dict] = None):
        self.total_packets += 1
        self.bytes_captured += len(packet_data)

        # Create packet record
        pkt = CapturePacket(
            timestamp=time.time(),
            packet_type=packet_info.get('type', 'unknown')
            if packet_info else 'unknown',
            raw_data=packet_data,
        )

        if packet_info:
            ptype = packet_info.get('type', 'unknown')
            self.packet_types[ptype] += 1

            pkt.event_code = packet_info.get('event_code')
            pkt.subevent = packet_info.get('subevent')
            pkt.mac = packet_info.get('mac')
            pkt.rssi = packet_info.get('rssi')
            pkt.name = packet_info.get('name')
            pkt.adv_type = packet_info.get('adv_type')
            pkt.services = packet_info.get('services', [])
            pkt.company_id = packet_info.get('company_id')
            pkt.tx_power = packet_info.get('tx_power')
            pkt.flags = packet_info.get('flags')

            if 'event_code' in packet_info:
                self.events_by_type[packet_info['event_code']] += 1

            if 'ogf' in packet_info:
                self.commands_by_ogf[packet_info['ogf']] += 1

            # Update device database
            if 'mac' in packet_info:
                self._update_device(packet_info)

        # Store packet (with limit)
        if len(self.all_packets) < self.max_packets_stored:
            self.all_packets.append(pkt)

    def _update_device(self, packet_info: dict):
        mac = packet_info['mac']
        now = time.time()

        if mac not in self.devices:
            manufacturer = self._lookup_manufacturer(mac)
            self.devices[mac] = BLEDevice(
                mac=mac,
                manufacturer=manufacturer,
                first_seen=now,
            )

        device = self.devices[mac]
        device.last_seen = now
        device.packet_count += 1

        if packet_info.get('rssi'):
            device.update_rssi(packet_info['rssi'])

        if packet_info.get('name'):
            device.name = packet_info['name']

        if packet_info.get('addr_type'):
            device.addr_type = packet_info['addr_type']

        if packet_info.get('tx_power') is not None:
            device.tx_power = packet_info['tx_power']

        if packet_info.get('appearance'):
            device.appearance = packet_info['appearance']

        if packet_info.get('services'):
            for svc in packet_info['services']:
                if svc not in device.services:
                    device.services.append(svc)

        if packet_info.get('company_id'):
            device.company_id = packet_info['company_id']
            device.company_name = COMPANY_IDS.get(packet_info['company_id'],
                                                  "Unknown")

        if packet_info.get('flags'):
            device.flags = packet_info['flags']

        if packet_info.get('adv_type') is not None:
            adv_type_names = {
                0: 'ADV_IND',
                1: 'ADV_DIRECT',
                2: 'ADV_SCAN',
                3: 'ADV_NONCONN',
                4: 'SCAN_RSP'
            }
            device.adv_types_seen.add(
                adv_type_names.get(packet_info['adv_type'],
                                   f"0x{packet_info['adv_type']:02X}"))

        if packet_info.get('mfg_data'):
            device.raw_mfg_data = packet_info['mfg_data']

    def _lookup_manufacturer(self, mac: str) -> str:
        prefix = mac[:8].upper()
        return OUI_DATABASE.get(prefix, "Unknown")

    def get_rate(self) -> float:
        elapsed = time.time() - self.start_time
        return self.total_packets / elapsed if elapsed > 0 else 0

    def print_status(self, force: bool = False):
        now = time.time()
        if not force and (now - self.last_print_time) < 5.0:
            return

        self.last_print_time = now
        elapsed = now - self.start_time
        rate = self.get_rate()

        print(f"\n{Colors.CYAN}{'═'*65}{Colors.RESET}")
        print(
            f"{Colors.BOLD}📊 BLE Sniffer Statistics{Colors.RESET} (running {elapsed:.0f}s)"
        )
        print(f"{Colors.CYAN}{'═'*65}{Colors.RESET}")
        print(
            f"  Packets:  {Colors.GREEN}{self.total_packets:,}{Colors.RESET} ({rate:.1f}/sec)"
        )
        print(
            f"  Data:     {Colors.GREEN}{self.bytes_captured:,}{Colors.RESET} bytes ({self.bytes_captured/1024:.1f} KB)"
        )
        print(
            f"  Devices:  {Colors.YELLOW}{len(self.devices)}{Colors.RESET} unique"
        )
        print(f"  Errors:   {Colors.RED}{self.errors}{Colors.RESET}")

        if self.packet_types:
            print(f"\n  {Colors.BOLD}Packet Types:{Colors.RESET}")
            for ptype, count in sorted(self.packet_types.items(),
                                       key=lambda x: -x[1]):
                pct = count / self.total_packets * 100 if self.total_packets > 0 else 0
                print(f"    {ptype}: {count} ({pct:.1f}%)")

        if self.devices:
            # Show top 5 devices by packet count
            sorted_devices = sorted(self.devices.values(),
                                    key=lambda d: -d.packet_count)[:10]
            print(f"\n  {Colors.BOLD}Top Devices:{Colors.RESET}")
            for dev in sorted_devices:
                name_str = f" \"{dev.name}\"" if dev.name else ""
                mfg_str = f" [{dev.manufacturer}]" if dev.manufacturer != "Unknown" else ""
                print(
                    f"    {Colors.MAGENTA}{dev.mac}{Colors.RESET}{name_str}{mfg_str}"
                )
                print(
                    f"      RSSI: {dev.rssi_avg:.0f}dBm (min:{dev.rssi_min}, max:{dev.rssi_max}), Pkts: {dev.packet_count}"
                )

        print(f"{Colors.CYAN}{'═'*65}{Colors.RESET}\n")


# Global stats instance
stats = SnifferStats()

# =============================================================================
# PCAP File Handling
# =============================================================================
PCAP_GLOBAL_HEADER_FMT = '<IHHIIII'
PCAP_MAGIC_NUMBER = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_THISZONE = 0
PCAP_SIGFIGS = 0
PCAP_SNAPLEN = 65535
LINKTYPE_BLUETOOTH_HCI_H4 = 187
PCAP_PACKET_HEADER_FMT = '<IIII'


def write_pcap_header(f):
    header = struct.pack(PCAP_GLOBAL_HEADER_FMT, PCAP_MAGIC_NUMBER,
                         PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR, PCAP_THISZONE,
                         PCAP_SIGFIGS, PCAP_SNAPLEN, LINKTYPE_BLUETOOTH_HCI_H4)
    f.write(header)
    f.flush()


def write_pcap_packet(f,
                      packet_data: bytes,
                      packet_info: Optional[dict] = None):
    ts = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1000000)
    length = len(packet_data)

    header = struct.pack(PCAP_PACKET_HEADER_FMT, ts_sec, ts_usec, length,
                         length)
    f.write(header)
    f.write(packet_data)
    f.flush()

    stats.add_packet(packet_data, packet_info)


# =============================================================================
# Advertisement Data Parsing
# =============================================================================
def parse_ad_structures(data: bytes) -> dict:
    """Parse BLE advertising data structures"""
    result = {
        'name': '',
        'tx_power': None,
        'appearance': None,
        'flags': None,
        'services': [],
        'company_id': None,
        'mfg_data': b'',
    }

    i = 0
    while i < len(data) - 1:
        length = data[i]
        if length == 0 or i + length >= len(data):
            break

        ad_type = data[i + 1]
        ad_data = data[i + 2:i + 1 + length]

        if ad_type == 0x01:  # Flags
            result['flags'] = ad_data[0] if ad_data else 0

        elif ad_type in (0x08, 0x09):  # Short/Complete Name
            try:
                result['name'] = ad_data.decode('utf-8', errors='ignore')
            except:
                pass

        elif ad_type == 0x0A:  # TX Power Level
            if ad_data:
                result['tx_power'] = ad_data[0] if ad_data[
                    0] < 128 else ad_data[0] - 256

        elif ad_type == 0x19:  # Appearance
            if len(ad_data) >= 2:
                appearance_val = ad_data[0] | (ad_data[1] << 8)
                result['appearance'] = APPEARANCES.get(
                    appearance_val, f"0x{appearance_val:04X}")

        elif ad_type in (0x02, 0x03):  # 16-bit UUIDs
            for j in range(0, len(ad_data) - 1, 2):
                uuid = ad_data[j] | (ad_data[j + 1] << 8)
                svc_name = SERVICE_UUIDS.get(uuid, f"0x{uuid:04X}")
                if svc_name not in result['services']:
                    result['services'].append(svc_name)

        elif ad_type == 0xFF:  # Manufacturer Data
            if len(ad_data) >= 2:
                result['company_id'] = ad_data[0] | (ad_data[1] << 8)
                result['mfg_data'] = bytes(ad_data[2:])

        i += length + 1

    return result


def decode_le_advertising_report(data: bytes) -> Optional[dict]:
    """Decode LE Advertising Report to extract device info"""
    if len(data) < 10:
        return None

    try:
        num_reports = data[1]
        if num_reports < 1:
            return None

        adv_type = data[2]
        addr_type = data[3]
        addr = data[4:10]
        mac = ':'.join(f'{b:02X}' for b in reversed(addr))

        data_len = data[10] if len(data) > 10 else 0
        adv_data = data[11:11 + data_len] if len(data) > 11 else b''
        rssi = data[11 + data_len] if len(data) > 11 + data_len else 0
        if rssi > 127:
            rssi = rssi - 256

        # Parse advertisement data
        ad_info = parse_ad_structures(adv_data)

        return {
            'mac': mac,
            'rssi': rssi,
            'name': ad_info['name'],
            'addr_type': 'random' if addr_type else 'public',
            'adv_type': adv_type,
            'tx_power': ad_info['tx_power'],
            'appearance': ad_info['appearance'],
            'services': ad_info['services'],
            'company_id': ad_info['company_id'],
            'flags': ad_info['flags'],
            'mfg_data': ad_info['mfg_data'],
        }
    except Exception as e:
        return None


def format_packet_description(packet_data: bytes, packet_info: dict) -> str:
    """Create human-readable packet description"""
    if not packet_info:
        return ""

    ptype = packet_info.get('type', '')

    if ptype == 'HCI_EVT':
        evt_code = packet_info.get('event_code', 0)
        evt_name = HCI_EVENT_NAMES.get(evt_code, f"0x{evt_code:02X}")

        if evt_code == 0x3E:  # LE Meta Event
            subevent = packet_info.get('subevent', 0)
            sub_name = LE_META_SUBEVENTS.get(subevent, f"0x{subevent:02X}")
            desc = f"{Colors.BLUE}EVT{Colors.RESET} {sub_name}"

            if 'mac' in packet_info:
                desc += f" [{packet_info['mac']}"
                if packet_info.get('name'):
                    desc += f" \"{packet_info['name']}\""
                if packet_info.get('rssi'):
                    desc += f" {packet_info['rssi']}dBm"
                if packet_info.get('services'):
                    desc += f" svc:{len(packet_info['services'])}"
                desc += "]"
            return desc
        else:
            return f"{Colors.BLUE}EVT{Colors.RESET} {evt_name}"

    elif ptype == 'HCI_CMD':
        ogf = packet_info.get('ogf', 0)
        ocf = packet_info.get('ocf', 0)
        ogf_name = HCI_OGF_NAMES.get(ogf, f"OGF=0x{ogf:02X}")
        return f"{Colors.GREEN}CMD{Colors.RESET} {ogf_name} OCF=0x{ocf:03X}"

    elif ptype == 'HCI_ACL':
        direction = packet_info.get('direction', 'unknown')
        return f"{Colors.YELLOW}ACL{Colors.RESET} {direction}"

    return ""


# =============================================================================
# Line Parser
# =============================================================================
def parse_line(line: str) -> Tuple[Optional[bytes], Optional[dict]]:
    """Parse btsnoop line and return (packet_bytes, packet_info)"""
    packet_info = {}

    # Normalize line - replace Unicode × with x (multiplication sign vs letter x)
    line = line.replace('×', 'x')

    # Handle HCI Events
    match = re.search(
        r'pkt_type\s*=\[0x([0-9a-fA-F]+)\].*data=\[([0-9a-fA-F]+)\]', line)
    if match:
        pkt_type_int = int(match.group(1), 16)
        data = bytes.fromhex(match.group(2))

        if pkt_type_int == 4:  # LE Event
            h4_type = 0x04
            evt_code = 0x3E
            length = len(data)
            packet = bytes([h4_type, evt_code, length]) + data

            packet_info = {
                'type': 'HCI_EVT',
                'event_code': evt_code,
                'subevent': data[0] if data else 0,
            }

            if data and data[0] == 0x02:
                adv_info = decode_le_advertising_report(data)
                if adv_info:
                    packet_info.update(adv_info)

            return packet, packet_info

        elif pkt_type_int == 5:  # General Event
            h4_type = 0x04
            packet = bytes([h4_type]) + data
            packet_info = {
                'type': 'HCI_EVT',
                'event_code': data[0] if data else 0
            }
            return packet, packet_info

        elif pkt_type_int == 2:  # Command Complete
            h4_type = 0x04
            evt_code = 0x0E
            length = len(data)
            packet = bytes([h4_type, evt_code, length]) + data
            packet_info = {'type': 'HCI_EVT', 'event_code': evt_code}
            return packet, packet_info

        elif pkt_type_int == 3:  # Command Status
            h4_type = 0x04
            evt_code = 0x0F
            length = len(data)
            packet = bytes([h4_type, evt_code, length]) + data
            packet_info = {'type': 'HCI_EVT', 'event_code': evt_code}
            return packet, packet_info

        return None, None

    # Handle ACL Data
    if "Acl_in_handle" in line or "Acl_out_handle" in line:
        direction = 'IN' if 'Acl_in' in line else 'OUT'
        match = re.search(
            r'handle\s*=\[0x([0-9a-fA-F]+)\],pb_bc_flag\s*=\[0x([0-9a-fA-F]+)\].*data=\[([0-9a-fA-F]+)\]',
            line)
        if match:
            handle = int(match.group(1), 16)
            pb_bc = int(match.group(2), 16)
            data = bytes.fromhex(match.group(3))
            length = len(data)

            h4_type = 0x02
            acl_header = bytes([
                handle & 0xFF, ((handle >> 8) & 0x0F) | ((pb_bc & 0x0F) << 4),
                length & 0xFF, (length >> 8) & 0xFF
            ])

            packet = bytes([h4_type]) + acl_header + data
            packet_info = {
                'type': 'HCI_ACL',
                'direction': direction,
                'handle': handle
            }
            return packet, packet_info

    # Handle Commands
    if "opcode" in line:
        match = re.search(
            r'opcode\s*=\[0x([0-9a-fA-F]+)\].*data=\[([0-9a-fA-F]*)\]', line)
        if match:
            opcode = int(match.group(1), 16)
            data_hex = match.group(2)
            data = bytes.fromhex(data_hex) if data_hex else bytes()
            length = len(data)

            h4_type = 0x01
            cmd_header = bytes(
                [opcode & 0xFF, (opcode >> 8) & 0xFF, length & 0xFF])

            packet = bytes([h4_type]) + cmd_header + data
            packet_info = {
                'type': 'HCI_CMD',
                'opcode': opcode,
                'ogf': (opcode >> 10) & 0x3F,
                'ocf': opcode & 0x3FF,
            }
            return packet, packet_info

    return None, None


# =============================================================================
# Export Functions
# =============================================================================
def export_json(output_path: str):
    """Export capture data to JSON"""
    export_data = {
        'capture_info': {
            'start_time': datetime.fromtimestamp(stats.start_time).isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration_seconds': time.time() - stats.start_time,
            'total_packets': stats.total_packets,
            'bytes_captured': stats.bytes_captured,
            'errors': stats.errors,
        },
        'statistics': {
            'packet_types': dict(stats.packet_types),
            'events_by_type': {
                f"0x{k:02X}": v
                for k, v in stats.events_by_type.items()
            },
            'packets_per_second': stats.get_rate(),
        },
        'devices': [
            dev.to_dict() for dev in sorted(stats.devices.values(),
                                            key=lambda d: -d.packet_count)
        ],
        'packets': [pkt.to_dict()
                    for pkt in stats.all_packets[-10000:]],  # Last 10k packets
    }

    with open(output_path, 'w') as f:
        json.dump(export_data, f, indent=2, default=str)

    print(f"{Colors.GREEN}✓ JSON export saved to: {output_path}{Colors.RESET}")


def export_csv(output_path: str):
    """Export device list to CSV"""
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'MAC Address', 'Name', 'Manufacturer', 'Address Type',
            'RSSI (Avg)', 'RSSI (Min)', 'RSSI (Max)', 'TX Power', 'Appearance',
            'Services', 'Company ID', 'Company Name', 'First Seen',
            'Last Seen', 'Packet Count', 'ADV Types'
        ])

        for dev in sorted(stats.devices.values(),
                          key=lambda d: -d.packet_count):
            writer.writerow([
                dev.mac,
                dev.name,
                dev.manufacturer,
                dev.addr_type,
                f"{dev.rssi_avg:.1f}",
                dev.rssi_min,
                dev.rssi_max,
                dev.tx_power if dev.tx_power else '',
                dev.appearance if dev.appearance else '',
                '; '.join(dev.services),
                f"0x{dev.company_id:04X}" if dev.company_id else '',
                dev.company_name if dev.company_name else '',
                datetime.fromtimestamp(
                    dev.first_seen).strftime('%Y-%m-%d %H:%M:%S')
                if dev.first_seen else '',
                datetime.fromtimestamp(
                    dev.last_seen).strftime('%Y-%m-%d %H:%M:%S')
                if dev.last_seen else '',
                dev.packet_count,
                '; '.join(dev.adv_types_seen),
            ])

    print(f"{Colors.GREEN}✓ CSV export saved to: {output_path}{Colors.RESET}")


def export_html_report(output_path: str):
    """Generate HTML report"""
    duration = time.time() - stats.start_time

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BLE Sniffer Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 10px; }}
        h2 {{ color: #00d4ff; margin: 20px 0 10px; border-bottom: 1px solid #333; padding-bottom: 5px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #16213e; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-value {{ font-size: 2em; color: #00d4ff; font-weight: bold; }}
        .stat-label {{ color: #888; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; background: #16213e; border-radius: 10px; overflow: hidden; }}
        th {{ background: #0f3460; color: #00d4ff; padding: 12px; text-align: left; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #333; }}
        tr:hover {{ background: #1f4068; }}
        .rssi-good {{ color: #4ade80; }}
        .rssi-medium {{ color: #facc15; }}
        .rssi-poor {{ color: #f87171; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; margin: 2px; }}
        .badge-service {{ background: #3b82f6; }}
        .badge-adv {{ background: #8b5cf6; }}
        .manufacturer {{ color: #a78bfa; }}
        .timestamp {{ color: #888; font-size: 0.9em; }}
        .mfg-data {{ font-family: monospace; font-size: 0.85em; color: #888; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔵 BLE Sniffer Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats.total_packets:,}</div>
                <div class="stat-label">Total Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(stats.devices)}</div>
                <div class="stat-label">Unique Devices</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.bytes_captured/1024:.1f} KB</div>
                <div class="stat-label">Data Captured</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get_rate():.1f}/s</div>
                <div class="stat-label">Packet Rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{duration:.0f}s</div>
                <div class="stat-label">Duration</div>
            </div>
        </div>
        
        <h2>📱 Discovered Devices ({len(stats.devices)})</h2>
        <table>
            <tr>
                <th>MAC Address</th>
                <th>Name</th>
                <th>Manufacturer</th>
                <th>RSSI</th>
                <th>TX Power</th>
                <th>Services</th>
                <th>Packets</th>
                <th>Last Seen</th>
            </tr>
"""

    for dev in sorted(stats.devices.values(), key=lambda d: -d.packet_count):
        rssi_class = 'rssi-good' if dev.rssi_avg > -60 else (
            'rssi-medium' if dev.rssi_avg > -80 else 'rssi-poor')
        services_html = ''.join(f'<span class="badge badge-service">{s}</span>'
                                for s in dev.services[:3])
        if len(dev.services) > 3:
            services_html += f'<span class="badge">+{len(dev.services)-3}</span>'

        last_seen = datetime.fromtimestamp(
            dev.last_seen).strftime('%H:%M:%S') if dev.last_seen else '-'

        html += f"""            <tr>
                <td><code>{dev.mac}</code></td>
                <td>{dev.name or '<em style="color:#666">Unknown</em>'}</td>
                <td class="manufacturer">{dev.manufacturer}</td>
                <td class="{rssi_class}">{dev.rssi_avg:.0f} dBm</td>
                <td>{f'{dev.tx_power} dBm' if dev.tx_power else '-'}</td>
                <td>{services_html or '-'}</td>
                <td>{dev.packet_count:,}</td>
                <td class="timestamp">{last_seen}</td>
            </tr>
"""

    html += """        </table>
        
        <h2>📊 Packet Types Distribution</h2>
        <table>
            <tr><th>Type</th><th>Count</th><th>Percentage</th></tr>
"""

    for ptype, count in sorted(stats.packet_types.items(),
                               key=lambda x: -x[1]):
        pct = count / stats.total_packets * 100 if stats.total_packets > 0 else 0
        html += f"            <tr><td>{ptype}</td><td>{count:,}</td><td>{pct:.1f}%</td></tr>\n"

    html += """        </table>
    </div>
</body>
</html>
"""

    with open(output_path, 'w') as f:
        f.write(html)

    print(f"{Colors.GREEN}✓ HTML report saved to: {output_path}{Colors.RESET}")


# =============================================================================
# Main
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description='BL602 BLE Sniffer - Enhanced v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -p /dev/tty.usbserial-110
  %(prog)s -p /dev/tty.usbserial-110 --fifo -v
  %(prog)s -p /dev/tty.usbserial-110 --json capture.json --csv devices.csv
  %(prog)s -p /dev/tty.usbserial-110 --html report.html --filter-mac AA:BB:CC:DD:EE:FF
        """)

    parser.add_argument('-p', '--port', required=True, help='Serial port')
    parser.add_argument('-b',
                        '--baud',
                        type=int,
                        default=115200,
                        help='Baud rate (default: 115200)')
    parser.add_argument('-o',
                        '--output',
                        default='capture.pcap',
                        help='Output PCAP file')
    parser.add_argument('--fifo',
                        action='store_true',
                        help='Use FIFO for real-time Wireshark')
    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',
                        help='Verbose packet output')
    parser.add_argument('-q',
                        '--quiet',
                        action='store_true',
                        help='Quiet mode')
    parser.add_argument('--no-color',
                        action='store_true',
                        help='Disable colored output')

    # Filtering options
    parser.add_argument('--filter-mac', type=str, help='Filter by MAC address')
    parser.add_argument('--filter-name',
                        type=str,
                        help='Filter by device name (substring)')
    parser.add_argument('--min-rssi',
                        type=int,
                        default=-100,
                        help='Minimum RSSI threshold')

    # Export options
    parser.add_argument('--json',
                        type=str,
                        metavar='FILE',
                        help='Export to JSON file on exit')
    parser.add_argument('--csv',
                        type=str,
                        metavar='FILE',
                        help='Export devices to CSV on exit')
    parser.add_argument('--html',
                        type=str,
                        metavar='FILE',
                        help='Generate HTML report on exit')

    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    filter_mac = args.filter_mac.upper() if args.filter_mac else None
    filter_name = args.filter_name.lower() if args.filter_name else None

    # Print banner
    print(
        f"\n{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════════════════════════════╗{Colors.RESET}"
    )
    print(
        f"{Colors.BOLD}{Colors.CYAN}║         BL602 BLE Sniffer - Enhanced v3.0                ║{Colors.RESET}"
    )
    print(
        f"{Colors.BOLD}{Colors.CYAN}║   PCAP • JSON • CSV • HTML • Device Database • OUI       ║{Colors.RESET}"
    )
    print(
        f"{Colors.BOLD}{Colors.CYAN}╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n"
    )

    output_file = args.output

    if args.fifo:
        if os.path.exists(output_file):
            os.remove(output_file)
        try:
            os.mkfifo(output_file)
            print(
                f"{Colors.YELLOW}Created FIFO at {output_file}. Waiting for Wireshark...{Colors.RESET}"
            )
            print(
                f"Run: {Colors.GREEN}wireshark -k -i {output_file}{Colors.RESET}"
            )
            f = open(output_file, 'wb')
            print(f"{Colors.GREEN}Wireshark connected!{Colors.RESET}")
        except OSError as e:
            print(f"{Colors.RED}Failed to create FIFO: {e}{Colors.RESET}")
            return
    else:
        f = open(output_file, 'wb')
        print(f"PCAP output: {Colors.GREEN}{output_file}{Colors.RESET}")

    write_pcap_header(f)

    if filter_mac:
        print(f"Filter MAC: {Colors.YELLOW}{filter_mac}{Colors.RESET}")
    if filter_name:
        print(f"Filter name: {Colors.YELLOW}{filter_name}{Colors.RESET}")
    if args.min_rssi > -100:
        print(f"Min RSSI: {Colors.YELLOW}{args.min_rssi} dBm{Colors.RESET}")

    if args.json:
        print(f"JSON export: {Colors.CYAN}{args.json}{Colors.RESET}")
    if args.csv:
        print(f"CSV export: {Colors.CYAN}{args.csv}{Colors.RESET}")
    if args.html:
        print(f"HTML report: {Colors.CYAN}{args.html}{Colors.RESET}")

    try:
        ser = serial.Serial(args.port, args.baud, timeout=1)
        print(
            f"\nConnected to {Colors.GREEN}{args.port}{Colors.RESET} @ {args.baud} baud"
        )
        print(f"{Colors.CYAN}Capturing... (Ctrl+C to stop){Colors.RESET}\n")

        while True:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if line and "[btsnoop]" in line:
                # Skip Stop markers if present (for older firmware)
                if line.endswith(":Stop") or "]:Stop" in line:
                    continue

                packet, packet_info = parse_line(line)
                if packet:
                    # Apply filters
                    if filter_mac and packet_info:
                        if packet_info.get('mac', '') != filter_mac:
                            continue

                    if filter_name and packet_info:
                        name = packet_info.get('name', '').lower()
                        if filter_name not in name:
                            continue

                    if args.min_rssi > -100 and packet_info:
                        rssi = packet_info.get('rssi', 0)
                        if rssi and rssi < args.min_rssi:
                            continue

                    write_pcap_packet(f, packet, packet_info)

                    if args.verbose:
                        desc = format_packet_description(packet, packet_info)
                        if desc:
                            print(f"  {desc}")
                    elif not args.quiet:
                        print(".", end='', flush=True)

                    stats.print_status()
                else:
                    stats.errors += 1
                    if args.verbose:
                        print(
                            f"\n{Colors.RED}Parse error: {line[:80]}...{Colors.RESET}"
                        )

    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Stopping capture...{Colors.RESET}")
    except BrokenPipeError:
        print(
            f"\n{Colors.RED}Broken pipe - Wireshark disconnected{Colors.RESET}"
        )
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
    finally:
        if 'ser' in locals() and ser.is_open:
            ser.close()
        f.close()

        if args.fifo and os.path.exists(output_file):
            os.remove(output_file)

        # Final statistics
        stats.print_status(force=True)

        # Export files
        if args.json:
            export_json(args.json)
        if args.csv:
            export_csv(args.csv)
        if args.html:
            export_html_report(args.html)

        print(f"\n{Colors.GREEN}Capture complete!{Colors.RESET}")
        print(f"  Packets: {stats.total_packets:,}")
        print(f"  Devices: {len(stats.devices)}")
        print(f"  PCAP: {output_file}")


if __name__ == '__main__':
    main()
