/**
 * @file sniffer.c
 * @brief BLE Promiscuous Sniffer Implementation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <FreeRTOS.h>
#include <task.h>

#include "sniffer.h"

#define SNIFFER_BUFFER_SIZE 100

/* BLE AD types for name fields */
#define AD_TYPE_COMPLETE_NAME 0x09
#define AD_TYPE_SHORT_NAME 0x08

typedef struct {
    ble_packet_t packets[SNIFFER_BUFFER_SIZE];
    uint16_t head;
    uint16_t tail;
    uint16_t count;
    uint32_t overflow_count;
    uint32_t packet_count;
} packet_buffer_t;

static packet_buffer_t g_packet_buffer = {0};



/**
 * @brief Extract device name from BLE advertisement payload
 * @param payload Raw BLE advertisement payload
 * @param payload_len Length of payload
 * @param name_out Output buffer for device name
 * @param name_len Size of output buffer
 */
static void extract_device_name(const uint8_t *payload, uint8_t payload_len,
                                char *name_out, int name_len)
{
    int i = 0;
    
    if (!payload || !name_out || name_len <= 1) {
        if (name_out && name_len > 0) {
            name_out[0] = '\0';
        }
        return;
    }
    
    /* Clear output buffer */
    memset(name_out, 0, name_len);
    
    /* Parse AD structures */
    while (i < payload_len - 1) {
        uint8_t ad_len = payload[i];
        uint8_t ad_type = payload[i + 1];
        
        /* Check if this is a complete or short name */
        if ((ad_type == AD_TYPE_COMPLETE_NAME || ad_type == AD_TYPE_SHORT_NAME) && ad_len > 1) {
            int name_data_len = ad_len - 1;  /* Subtract type byte */
            int copy_len = (name_data_len < name_len - 1) ? name_data_len : name_len - 1;
            
            /* Copy name bytes (they are already ASCII) */
            memcpy(name_out, &payload[i + 2], copy_len);
            name_out[copy_len] = '\0';
            return;  /* Found name, exit */
        }
        
        /* Move to next AD structure */
        i += ad_len + 1;
    }
    
    /* No name found */
    name_out[0] = '\0';
}

static void sniffer_enqueue_packet(const ble_packet_t *packet)
{
    taskENTER_CRITICAL();
    
    if (g_packet_buffer.count >= SNIFFER_BUFFER_SIZE) {
        g_packet_buffer.overflow_count++;
        g_packet_buffer.tail = (g_packet_buffer.tail + 1) % SNIFFER_BUFFER_SIZE;
    } else {
        g_packet_buffer.count++;
    }
    
    memcpy(&g_packet_buffer.packets[g_packet_buffer.head], packet, sizeof(ble_packet_t));
    g_packet_buffer.head = (g_packet_buffer.head + 1) % SNIFFER_BUFFER_SIZE;
    g_packet_buffer.packet_count++;
    
    taskEXIT_CRITICAL();
}

static int sniffer_dequeue_packet(ble_packet_t *packet)
{
    int result = 0;
    
    taskENTER_CRITICAL();
    
    if (g_packet_buffer.count > 0) {
        memcpy(packet, &g_packet_buffer.packets[g_packet_buffer.tail], sizeof(ble_packet_t));
        g_packet_buffer.tail = (g_packet_buffer.tail + 1) % SNIFFER_BUFFER_SIZE;
        g_packet_buffer.count--;
        result = 1;
    }
    
    taskEXIT_CRITICAL();
    
    return result;
}

void sniffer_send_packet_serial(const ble_packet_t *packet)
{
    int i;
    
    if (!packet) {
        return;
    }
    
    printf("%02x:%02x:%02x:%02x:%02x:%02x,", 
           packet->mac[0], packet->mac[1], packet->mac[2],
           packet->mac[3], packet->mac[4], packet->mac[5]);
    
    printf("%d,", packet->rssi);
    printf("%d,", packet->channel);
    printf("%u,", packet->timestamp);
    printf("%d,", packet->payload_len);
    
    for (i = 0; i < packet->payload_len; i++) {
        printf("%02x", packet->payload[i]);
    }
    
    printf(",%s", packet->device_name);
    printf("\r\n");
}

void sniffer_on_packet_received(const uint8_t *mac, int8_t rssi, 
                                uint8_t channel, uint32_t timestamp,
                                const uint8_t *payload, uint8_t payload_len)
{
    ble_packet_t packet = {0};
    
    if (!mac || !payload || payload_len == 0) {
        return;
    }
    
    
    memcpy(packet.mac, mac, 6);
    packet.rssi = rssi;
    packet.channel = channel;
    packet.timestamp = timestamp;
    packet.payload_len = payload_len;
    memcpy(packet.payload, payload, payload_len);
    
    /* Extract device name from advertisement payload */
    extract_device_name(payload, payload_len, packet.device_name, sizeof(packet.device_name));
    
    sniffer_enqueue_packet(&packet);
}

void sniffer_init(void)
{
    printf("[SNIFFER] Initializing BLE promiscuous sniffer\r\n");
    memset(&g_packet_buffer, 0, sizeof(packet_buffer_t));
    printf("[SNIFFER] Packet capture initialized (buffer size: %d)\r\n", SNIFFER_BUFFER_SIZE);
}

void sniffer_start(void)
{
    printf("[SNIFFER] Starting BLE packet capture...\r\n");
    printf("[SNIFFER] Listening for all BLE advertisements\r\n");
    printf("[SNIFFER] Output format: MAC,RSSI,CHANNEL,TIMESTAMP,LEN,PAYLOAD\r\n");
}

int sniffer_get_packet(ble_packet_t *packet)
{
    if (!packet) {
        return 0;
    }
    
    return sniffer_dequeue_packet(packet);
}

static void sniffer_task(void *pvParameters)
{
    (void)pvParameters;
    ble_packet_t packet = {0};
    uint32_t last_status = 0;
    uint32_t packet_count_last = 0;
    
    printf("[SNIFFER] Packet processing task started\r\n");
    
    while (1) {
        if (sniffer_get_packet(&packet)) {
            sniffer_send_packet_serial(&packet);
            /* Add delay between packets to prevent UART buffer overflow and allow CLI input */
            vTaskDelay(pdMS_TO_TICKS(5));
        } else {
            /* No packets - longer delay to prevent CPU spinning */
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        /* Print status every 5 seconds */
        uint32_t now = xTaskGetTickCount();
        if ((now - last_status) > pdMS_TO_TICKS(5000)) {
            last_status = now;
            uint32_t packets_per_sec = (g_packet_buffer.packet_count - packet_count_last) / 5;
            printf("[SNIFFER] Status: Total=%lu, Rate=%lu/sec, Overflow=%lu, Buffer=%u/%u\r\n",
                   g_packet_buffer.packet_count, packets_per_sec, 
                   g_packet_buffer.overflow_count, g_packet_buffer.count, SNIFFER_BUFFER_SIZE);
            packet_count_last = g_packet_buffer.packet_count;
        }
    }
}

void sniffer_create_task(void)
{
    static StaticTask_t task_buffer;
    static StackType_t task_stack[1024];
    
    xTaskCreateStatic(sniffer_task, 
                      "sniffer_task",
                      1024,
                      NULL,
                      10,
                      task_stack,
                      &task_buffer);
}


