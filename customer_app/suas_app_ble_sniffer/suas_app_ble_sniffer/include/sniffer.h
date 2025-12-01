#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <stdint.h>
#include <stdbool.h>

/* BLE Advertisement Types */
#define BLE_ADV_IND          0x00  /* Connectable undirected */
#define BLE_ADV_DIRECT_IND   0x01  /* Connectable directed */
#define BLE_ADV_SCAN_IND     0x02  /* Scannable undirected */
#define BLE_ADV_NONCONN_IND  0x03  /* Non-connectable undirected */
#define BLE_SCAN_RSP         0x04  /* Scan response */

/* BLE Address Types */
#define BLE_ADDR_PUBLIC      0x00
#define BLE_ADDR_RANDOM      0x01

/**
 * @brief Enhanced BLE packet structure for sniffer output
 */
typedef struct {
    uint8_t mac[6];              /* Source MAC address */
    int8_t rssi;                 /* Signal strength (dBm) */
    uint8_t channel;             /* BLE channel (37, 38, 39) */
    uint32_t timestamp;          /* Packet timestamp (ms) */
    uint8_t payload_len;         /* Payload length */
    uint8_t payload[255];        /* Raw payload data */
    char device_name[32];        /* Device name from advertisement */
    uint8_t adv_type;            /* Advertisement type (0-4) */
    uint8_t addr_type;           /* Address type (public/random) */
    int8_t tx_power;             /* TX power level (if present, else -128) */
    uint16_t appearance;         /* Device appearance (if present) */
    uint8_t flags;               /* AD flags (if present) */
    uint16_t company_id;         /* Manufacturer company ID (if present) */
    uint8_t mfg_data[64];        /* Manufacturer specific data */
    uint8_t mfg_data_len;        /* Manufacturer data length */
    uint16_t service_uuids[8];   /* Service UUIDs (16-bit) */
    uint8_t num_services;        /* Number of service UUIDs */
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
int sniffer_get_packet(ble_packet_t *packet);

/**
 * @brief Send captured packet to serial (CSV format)
 * @param packet Pointer to packet to send
 */
void sniffer_send_packet_serial(const ble_packet_t *packet);

/**
 * @brief Legacy callback - calls extended version
 */
void sniffer_on_packet_received(const uint8_t *mac, int8_t rssi, 
                                uint8_t channel, uint32_t timestamp,
                                const uint8_t *payload, uint8_t payload_len);

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
void sniffer_on_packet_received_ex(const uint8_t *mac, int8_t rssi, 
                                   uint8_t channel, uint32_t timestamp,
                                   const uint8_t *payload, uint8_t payload_len,
                                   uint8_t adv_type, uint8_t addr_type);

/**
 * @brief Create and start packet processing task
 */
void sniffer_create_task(void);

/**
 * @brief Get sniffer statistics
 */
void sniffer_get_stats(uint32_t *total_packets, uint32_t *overflow_count, 
                       uint32_t *buffer_count);

#endif /* __SNIFFER_H__ */
