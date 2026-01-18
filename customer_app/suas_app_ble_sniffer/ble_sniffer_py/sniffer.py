#!/usr/bin/env python3
"""
Simple BLE Sniffer for BL602
Connects to the UART, parses HCI packets, and dumps them to Wireshark/JSON/CSV.

Usage:
    python3 sniffer.py /dev/ttyUSB0
"""

import serial
import time
import struct
import argparse
import re
import os
import json
import csv
import asyncio
import websockets
import threading
import queue
from collections import defaultdict
from datetime import datetime
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path


# Quick hack for colors in terminal
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

    # GATT Service Information (Phase 2)
    battery_level: Optional[int] = None
    manufacturer_name: str = ""
    model_number: str = ""
    firmware_rev: str = ""
    has_battery_service: bool = False
    has_device_info_service: bool = False
    has_heart_rate_service: bool = False

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

            # GATT Service Data
            'battery_level':
            self.battery_level,
            'manufacturer_name':
            self.manufacturer_name,
            'model_number':
            self.model_number,
            'firmware_rev':
            self.firmware_rev,
            'services_detected': {
                'battery': self.has_battery_service,
                'device_info': self.has_device_info_service,
                'heart_rate': self.has_heart_rate_service,
            }
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
            # Send to WebSocket
            try:
                ws_queue.put(packet_info)
            except NameError:
                pass  # ws_queue might not be defined yet during init
            except Exception as e:
                # print(f"WS Queue Error: {e}")
                pass

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

        # GATT Service Data (Phase 2)
        if packet_info.get('battery_level') is not None and packet_info.get(
                'battery_level') != 0xFF:
            device.battery_level = packet_info['battery_level']

        if packet_info.get('manufacturer_name'):
            device.manufacturer_name = packet_info['manufacturer_name']

        if packet_info.get('model_number'):
            device.model_number = packet_info['model_number']

        if packet_info.get('firmware_rev'):
            device.firmware_rev = packet_info['firmware_rev']

        if packet_info.get('has_battery_service'):
            device.has_battery_service = True

        if packet_info.get('has_device_info_service'):
            device.has_device_info_service = True

        if packet_info.get('has_heart_rate_service'):
            device.has_heart_rate_service = True

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
def hex_to_ascii(data: bytes) -> str:
    """Convert bytes to ASCII string, replacing non-printables with dot"""
    return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)


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
        'battery_level': None,
        'manufacturer_name': '',
        'model_number': '',
        'firmware_rev': '',
        'has_battery_service': False,
        'has_device_info_service': False,
        'has_heart_rate_service': False,
    }

    try:
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
                try:
                    for j in range(0, len(ad_data) - 1, 2):
                        uuid = ad_data[j] | (ad_data[j + 1] << 8)
                        svc_name = SERVICE_UUIDS.get(uuid, f"0x{uuid:04X}")
                        if svc_name not in result['services']:
                            result['services'].append(svc_name)

                        # Detect GATT services
                        if uuid == 0x180F:  # Battery Service
                            result['has_battery_service'] = True
                        elif uuid == 0x180A:  # Device Information Service
                            result['has_device_info_service'] = True
                        elif uuid == 0x180D:  # Heart Rate Service
                            result['has_heart_rate_service'] = True
                except:
                    pass

            elif ad_type == 0xFF:  # Manufacturer Data
                if len(ad_data) >= 2:
                    result['company_id'] = ad_data[0] | (ad_data[1] << 8)
                    result['mfg_data'] = bytes(ad_data[2:])
                    result['mfg_data_ascii'] = hex_to_ascii(result['mfg_data'])

                    # Extract battery from manufacturer-specific data
                    try:
                        company_id = result['company_id']
                        mfg_bytes = ad_data[2:]

                        # Samsung (0x0075) - battery at offset 3
                        if company_id == 0x0075 and len(mfg_bytes) >= 4:
                            result['battery_level'] = mfg_bytes[3]

                        # Apple (0x004C) - various formats, try common battery patterns
                        elif company_id == 0x004C and len(mfg_bytes) >= 5:
                            # Apple sometimes encodes battery in specific positions
                            # Common pattern: byte 4-5 may contain info
                            pass
                    except:
                        pass

            i += length + 1

    except Exception as e:
        # Silently ignore parsing errors and return partial results
        pass

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
            'mfg_data_ascii': ad_info.get('mfg_data_ascii', ''),
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

    try:
        # Normalize line - replace Unicode × with x (multiplication sign vs letter x)
        line = line.replace('×', 'x')

        # Handle HCI Commands (opcode based log)
        # Format: [btsnoop]:opcode =[0xc03],len =[0x0],data=[]
        # Updated regex to allow spaces in data
        match_cmd = re.search(
            r'opcode\s*=\s*\[\s*0x([0-9a-fA-F]+)\s*\].*data\s*=\s*\[\s*([0-9a-fA-F\s]*)\s*\]',
            line, re.IGNORECASE)
        if match_cmd:
            opcode_int = int(match_cmd.group(1), 16)
            data_str = match_cmd.group(2).replace(' ',
                                                  '')  # Remove spaces if any
            data = bytes.fromhex(data_str) if data_str else b''

            # Construct HCI Command Packet (Type 0x01)
            # Opcode is 2 bytes Little Endian
            h4_type = 0x01
            packet = bytes([h4_type]) + struct.pack('<H', opcode_int) + bytes(
                [len(data)]) + data

            packet_info = {
                'type': 'HCI_CMD',
                'opcode': opcode_int,
                'len': len(data),
                'payload': data,
                'payload_ascii': hex_to_ascii(data)
            }
            return packet, packet_info

        # Handle HCI Events
        # Relaxed regex to handle spaces and empty data
        match = re.search(
            r'pkt_type\s*=\s*\[\s*0x([0-9a-fA-F]+)\s*\].*data\s*=\s*\[\s*([0-9a-fA-F\s]*)\s*\]',
            line, re.IGNORECASE)
        if match:
            pkt_type_int = int(match.group(1), 16)
            # data might be empty string
            data_str = match.group(2).replace(' ', '')  # Remove spaces if any
            data = bytes.fromhex(data_str) if data_str else b''

            if pkt_type_int == 4:  # LE Event
                h4_type = 0x04
                evt_code = 0x3E
                length = len(data)
                packet = bytes([h4_type, evt_code, length]) + data

                packet_info = {
                    'type': 'HCI_EVT',
                    'event_code': evt_code,
                    'subevent': data[0] if data else 0,
                    'payload': data,
                    'payload_ascii': hex_to_ascii(data)
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
                    'event_code': data[0] if data else 0,
                    'payload': data,
                    'payload_ascii': hex_to_ascii(data)
                }
                return packet, packet_info

            elif pkt_type_int == 2:  # Command Complete
                h4_type = 0x04
                evt_code = 0x0E
                length = len(data)
                packet = bytes([h4_type, evt_code, length]) + data
                packet_info = {
                    'type': 'HCI_EVT',
                    'event_code': evt_code,
                    'payload': data,
                    'payload_ascii': hex_to_ascii(data)
                }
                return packet, packet_info

            elif pkt_type_int == 3:  # Command Status
                h4_type = 0x04
                evt_code = 0x0F
                length = len(data)
                packet = bytes([h4_type, evt_code, length]) + data
                packet_info = {
                    'type': 'HCI_EVT',
                    'event_code': evt_code,
                    'payload': data,
                    'payload_ascii': hex_to_ascii(data)
                }
                return packet, packet_info

    except (ValueError, struct.error) as e:
        return None, {'error': str(e)}
    except Exception as e:
        return None, {'error': str(e)}

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
            'Services', 'Company ID', 'Company Name', 'Battery Level (%)',
            'Manufacturer Name', 'Model Number', 'Firmware Revision',
            'Has Battery Service', 'Has Device Info Service',
            'Has Heart Rate Service', 'First Seen', 'Last Seen',
            'Packet Count', 'ADV Types'
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
                dev.battery_level if dev.battery_level is not None
                and dev.battery_level < 255 else '',
                dev.manufacturer_name if dev.manufacturer_name else '',
                dev.model_number if dev.model_number else '',
                dev.firmware_rev if dev.firmware_rev else '',
                'Yes' if dev.has_battery_service else 'No',
                'Yes' if dev.has_device_info_service else 'No',
                'Yes' if dev.has_heart_rate_service else 'No',
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
        .battery-indicator {{ display: inline-block; width: 30px; height: 16px; border: 1px solid #00d4ff; border-radius: 2px; margin-right: 5px; vertical-align: middle; overflow: hidden; }}
        .battery-fill {{ height: 100%; background: linear-gradient(90deg, #4ade80 0%, #facc15 70%, #f87171 100%); }}
        .gatt-service {{ font-size: 0.85em; padding: 4px 8px; border-radius: 3px; display: inline-block; margin: 2px; }}
        .gatt-battery {{ background: #7c3aed; }}
        .gatt-device-info {{ background: #06b6d4; }}
        .gatt-heart-rate {{ background: #ef4444; }}
        .info-section {{ background: #16213e; padding: 10px; border-radius: 5px; margin: 5px 0; font-size: 0.9em; }}
        .info-row {{ display: flex; justify-content: space-between; padding: 3px 0; }}
        .info-label {{ color: #888; }}
        .info-value {{ color: #00d4ff; font-weight: bold; }}
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
                <th>Battery</th>
                <th>Device Info</th>
                <th>RSSI</th>
                <th>Services</th>
                <th>Packets</th>
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

        # Build GATT Battery display
        battery_html = '-'
        if dev.battery_level is not None and dev.battery_level < 255:
            battery_pct = int(dev.battery_level)
            battery_fill_width = max(0, min(100, battery_pct))
            battery_color = '#4ade80' if battery_pct > 50 else (
                '#facc15' if battery_pct > 20 else '#f87171')
            battery_html = f'<div class="battery-indicator"><div class="battery-fill" style="width:{battery_fill_width}%;background-color:{battery_color}"></div></div>{battery_pct}%'

        # Build GATT Device Info display
        device_info_parts = []
        if dev.manufacturer_name:
            device_info_parts.append(f"<b>{dev.manufacturer_name}</b>")
        if dev.model_number:
            device_info_parts.append(f"Model: {dev.model_number}")
        if dev.firmware_rev:
            device_info_parts.append(f"FW: {dev.firmware_rev}")

        device_info_html = '<div class="info-section">' + '<br>'.join(
            device_info_parts) + '</div>' if device_info_parts else '-'

        # Build GATT Services display
        gatt_services = []
        if dev.has_battery_service:
            gatt_services.append(
                '<span class="gatt-service gatt-battery">🔋 Battery</span>')
        if dev.has_device_info_service:
            gatt_services.append(
                '<span class="gatt-service gatt-device-info">ℹ️ Device Info</span>'
            )
        if dev.has_heart_rate_service:
            gatt_services.append(
                '<span class="gatt-service gatt-heart-rate">❤️ Heart Rate</span>'
            )

        gatt_services_html = ' '.join(gatt_services) if gatt_services else '-'

        html += f"""            <tr>
                <td><code>{dev.mac}</code></td>
                <td>{dev.name or '<em style="color:#666">Unknown</em>'}</td>
                <td class="manufacturer">{dev.manufacturer}</td>
                <td>{battery_html}</td>
                <td>{device_info_html}</td>
                <td class="{rssi_class}">{dev.rssi_avg:.0f} dBm</td>
                <td>{gatt_services_html}</td>
                <td>{dev.packet_count:,}</td>
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
# WebSocket Server
# =============================================================================
ws_queue = queue.Queue()
connected_clients = set()


def json_serializer(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, set):
        return list(obj)
    return str(obj)


async def ws_handler(websocket):
    connected_clients.add(websocket)
    try:
        await websocket.wait_closed()
    finally:
        connected_clients.remove(websocket)


async def broadcast_loop():
    while True:
        try:
            # Non-blocking get from queue
            try:
                data = ws_queue.get_nowait()
                if connected_clients:
                    message = json.dumps(data, default=json_serializer)
                    websockets.broadcast(connected_clients, message)
            except queue.Empty:
                await asyncio.sleep(0.01)
        except Exception as e:
            print(f"WS Broadcast Error: {e}")
            await asyncio.sleep(1)


async def start_ws_server_async():
    async with websockets.serve(ws_handler, "0.0.0.0", 8765):
        print(
            f"{Colors.GREEN}WebSocket server started on port 8765{Colors.RESET}"
        )
        await broadcast_loop()


def run_ws_server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_ws_server_async())


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

    # Start WebSocket Server in background
    threading.Thread(target=run_ws_server, daemon=True).start()

    try:
        ser = serial.Serial(args.port, args.baud, timeout=1)
        print(
            f"\nConnected to {Colors.GREEN}{args.port}{Colors.RESET} @ {args.baud} baud"
        )
        print(f"{Colors.CYAN}Capturing... (Ctrl+C to stop){Colors.RESET}\n")

        line_buffer = b""
        while True:
            try:
                # Buffer read logic to handle split lines (timeout/baud rate issues)
                while b'\n' not in line_buffer:
                    chunk = ser.readline()
                    if not chunk:
                        break
                    line_buffer += chunk

                if b'\n' not in line_buffer:
                    continue

                raw_line, line_buffer = line_buffer.split(b'\n', 1)
                line = raw_line.decode('utf-8', errors='ignore').strip()

                if line and "[btsnoop]" in line:
                    # Handle firmware assertions/errors mixed in output
                    # Check for assert or error keywords (case-insensitive)
                    line_lower = line.lower()
                    if "assert" in line_lower or "error" in line_lower or "plld_evt_end" in line_lower:
                        print(
                            f"\n{Colors.RED}Firmware Error: {line}{Colors.RESET}",
                            flush=True)
                        continue

                    # Skip Stop markers if present (for older firmware)
                    if line.endswith(":Stop") or "]:Stop" in line:
                        continue

                    # Ensure we are looking at a valid btsnoop line structure
                    # Filter out debug logs that might abuse the tag
                    if "pkt_type" not in line and "opcode" not in line:
                        if args.verbose:
                            print(
                                f"\n{Colors.GRAY}Ignored log: {line}{Colors.RESET}",
                                flush=True)
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

                        if args.verbose and packet_info:
                            desc = format_packet_description(
                                packet, packet_info)
                            if desc:
                                print(f"  {desc}", flush=True)
                        elif not args.quiet:
                            print(".", end='', flush=True)

                        stats.print_status()
                    else:
                        stats.errors += 1
                        if args.verbose:
                            reason = ""
                            if packet_info and 'error' in packet_info:
                                reason = f" ({packet_info['error']})"

                            print(
                                f"\n{Colors.RED}Parse error{reason}: {line}{Colors.RESET}",
                                flush=True)
            except BrokenPipeError:
                print(
                    f"\n{Colors.RED}Broken pipe - Output closed (Wireshark disconnected?){Colors.RESET}"
                )
                break
            except Exception as e:
                print(f"\n{Colors.RED}Loop Error: {e}{Colors.RESET}",
                      flush=True)
                continue

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
