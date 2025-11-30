#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief BLE packet structure for sniffer output
 */
typedef struct {
    uint8_t mac[6];              /* Source MAC address */
    int8_t rssi;                 /* Signal strength */
    uint8_t channel;             /* BLE channel (37, 38, 39) */
    uint32_t timestamp;          /* Packet timestamp */
    uint8_t payload_len;         /* Payload length */
    uint8_t payload[255];        /* Raw payload data */
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
 * @brief Callback from HAL when BLE packet received
 * Called by scanner.c to inject raw packets into sniffer buffer
 * @param mac Source MAC address (6 bytes)
 * @param rssi Signal strength indicator
 * @param channel BLE channel (37-39)
 * @param timestamp Packet timestamp
 * @param payload Raw payload data
 * @param payload_len Payload length
 */
void sniffer_on_packet_received(const uint8_t *mac, int8_t rssi, 
                                uint8_t channel, uint32_t timestamp,
                                const uint8_t *payload, uint8_t payload_len);

/**
 * @brief Create and start packet processing task
 */
void sniffer_create_task(void);

#endif /* __SNIFFER_H__ */
