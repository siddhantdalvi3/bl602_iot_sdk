#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BLE Advertisement Types */
#define BLE_ADV_IND 0x00         /* Connectable undirected */
#define BLE_ADV_DIRECT_IND 0x01  /* Connectable directed */
#define BLE_ADV_SCAN_IND 0x02    /* Scannable undirected */
#define BLE_ADV_NONCONN_IND 0x03 /* Non-connectable undirected */
#define BLE_SCAN_RSP 0x04        /* Scan response */

/* BLE Address Types */
#define BLE_ADDR_PUBLIC 0x00
#define BLE_ADDR_RANDOM 0x01

/* Common GATT Service UUIDs (16-bit) */
#define GATT_SERVICE_BATTERY 0x180F
#define GATT_SERVICE_DEVICE_INFO 0x180A
#define GATT_SERVICE_HEART_RATE 0x180D
#define GATT_SERVICE_ENVIRONMENTAL 0x181A
#define GATT_SERVICE_GENERIC_ACCESS 0x1800
#define GATT_SERVICE_GENERIC_ATTRIBUTE 0x1801
#define GATT_SERVICE_IMMEDIATE_ALERT 0x1802
#define GATT_SERVICE_LINK_LOSS 0x1803
#define GATT_SERVICE_TX_POWER 0x1804

/* Common GATT Characteristic UUIDs */
#define GATT_CHAR_BATTERY_LEVEL 0x2A19
#define GATT_CHAR_DEVICE_NAME 0x2A00
#define GATT_CHAR_APPEARANCE 0x2A01
#define GATT_CHAR_MANUFACTURER_NAME 0x2A29
#define GATT_CHAR_MODEL_NUMBER 0x2A24
#define GATT_CHAR_FIRMWARE_REV 0x2A26
#define GATT_CHAR_HEART_RATE 0x2A37

/**
 * @brief Enhanced BLE packet structure for sniffer output
 */
typedef struct {
  uint8_t mac[6];            /* Source MAC address */
  int8_t rssi;               /* Signal strength (dBm) */
  uint8_t channel;           /* BLE channel (37, 38, 39) */
  uint32_t timestamp;        /* Packet timestamp (ms) */
  uint8_t payload_len;       /* Payload length */
  uint8_t payload[127];      /* Raw payload data (reduced from 255) */
  char device_name[32];      /* Device name from advertisement */
  uint8_t adv_type;          /* Advertisement type (0-4) */
  uint8_t addr_type;         /* Address type (public/random) */
  int8_t tx_power;           /* TX power level (if present, else -128) */
  uint16_t appearance;       /* Device appearance (if present) */
  uint8_t flags;             /* AD flags (if present) */
  uint16_t company_id;       /* Manufacturer company ID (if present) */
  uint8_t mfg_data[48];      /* Manufacturer specific data (reduced from 64) */
  uint8_t mfg_data_len;      /* Manufacturer data length */
  uint16_t service_uuids[8]; /* Service UUIDs (16-bit) */
  uint8_t num_services;      /* Number of service UUIDs */

  /* GATT Service Parsing Results */
  uint8_t battery_level;      /* Battery percentage (if available, else 0xFF) */
  char manufacturer_name[24]; /* Manufacturer name (if available) */
  char model_number[16];      /* Model number (if available) */
  char firmware_rev[16];      /* Firmware revision (if available) */
  uint8_t has_battery_service;     /* 1 if battery service detected */
  uint8_t has_device_info_service; /* 1 if device info service detected */
  uint8_t has_heart_rate_service;  /* 1 if heart rate service detected */
} ble_packet_t;

/**
 * @brief Initialize BLE sniffer with promiscuous mode
 */
void sniffer_init(void);

/**
 * @brief Start sniffing BLE packets
 */
void sniffer_start(void);

/**
 * @brief Get next captured packet from buffer
 * @param packet Pointer to packet structure to fill
 * @return 1 if packet available, 0 if buffer empty
 */
int sniffer_get_packet(ble_packet_t* packet);

/**
 * @brief Send captured packet to serial (CSV format)
 * @param packet Pointer to packet to send
 */
void sniffer_send_packet_serial(const ble_packet_t* packet);

/**
 * @brief Legacy callback - calls extended version
 */
void sniffer_on_packet_received(const uint8_t* mac, int8_t rssi,
                                uint8_t channel, uint32_t timestamp,
                                const uint8_t* payload, uint8_t payload_len);

/**
 * @brief Extended callback from scanner with full packet info
 * @param mac Source MAC address (6 bytes)
 * @param rssi Signal strength indicator
 * @param channel BLE channel (37-39)
 * @param timestamp Packet timestamp (ms)
 * @param payload Raw payload data
 * @param payload_len Payload length
 * @param adv_type Advertisement type (0-4)
 * @param addr_type Address type (0=public, 1=random)
 */
void sniffer_on_packet_received_ex(const uint8_t* mac, int8_t rssi,
                                   uint8_t channel, uint32_t timestamp,
                                   const uint8_t* payload, uint8_t payload_len,
                                   uint8_t adv_type, uint8_t addr_type);

/**
 * @brief Create and start packet processing task
 */
void sniffer_create_task(void);

/**
 * @brief Get sniffer statistics
 */
void sniffer_get_stats(uint32_t* total_packets, uint32_t* overflow_count,
                       uint32_t* buffer_count);

/**
 * @brief Get service name from UUID
 */
const char* gatt_get_service_name(uint16_t uuid);

/**
 * @brief Parse GATT service data and extract common fields
 */
void parse_gatt_services(ble_packet_t* packet);

#ifdef __cplusplus
}
#endif

#endif /* __SNIFFER_H__ */
