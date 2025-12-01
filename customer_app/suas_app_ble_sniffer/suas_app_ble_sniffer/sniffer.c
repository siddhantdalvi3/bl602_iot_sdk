#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <FreeRTOS.h>
#include <task.h>

#include "include/sniffer.h"

#define SNIFFER_BUFFER_SIZE 200

// AD types
#define AD_TYPE_FLAGS              0x01
#define AD_TYPE_UUID16_INCOMPLETE  0x02
#define AD_TYPE_UUID16_COMPLETE    0x03
#define AD_TYPE_UUID32_INCOMPLETE  0x04
#define AD_TYPE_UUID32_COMPLETE    0x05
#define AD_TYPE_UUID128_INCOMPLETE 0x06
#define AD_TYPE_UUID128_COMPLETE   0x07
#define AD_TYPE_SHORT_NAME         0x08
#define AD_TYPE_COMPLETE_NAME      0x09
#define AD_TYPE_TX_POWER           0x0A
#define AD_TYPE_DEVICE_CLASS       0x0D
#define AD_TYPE_APPEARANCE         0x19
#define AD_TYPE_ADV_INTERVAL       0x1A
#define AD_TYPE_MFG_DATA           0xFF

typedef struct {
    ble_packet_t packets[SNIFFER_BUFFER_SIZE];
    uint16_t head;
    uint16_t tail;
    uint16_t count;
    uint32_t overflow_count;
    uint32_t packet_count;
} packet_buffer_t;

static packet_buffer_t g_packet_buffer = {0};

static void parse_advertisement_data(const uint8_t *payload, uint8_t payload_len,
                                     ble_packet_t *packet)
{
    int i = 0;
    
    if (!payload || !packet || payload_len == 0) {
        return;
    }
    
    packet->device_name[0] = '\0';
    packet->tx_power = -128;
    packet->appearance = 0;
    packet->flags = 0;
    packet->company_id = 0;
    packet->mfg_data_len = 0;
    packet->num_services = 0;
    
    // Parse AD structures
    while (i < payload_len - 1) {
        uint8_t ad_len = payload[i];
        
        if (ad_len == 0 || (i + ad_len) > payload_len) {
            break;
        }
        
        uint8_t ad_type = payload[i + 1];
        const uint8_t *ad_data = &payload[i + 2];
        uint8_t ad_data_len = ad_len - 1;
        
        switch (ad_type) {
            case AD_TYPE_FLAGS:
                if (ad_data_len >= 1) {
                    packet->flags = ad_data[0];
                }
                break;
                
            case AD_TYPE_SHORT_NAME:
            case AD_TYPE_COMPLETE_NAME: {
                // Copy name (truncate if too long)
                int len = ad_data_len < 31 ? ad_data_len : 31;
                memcpy(packet->device_name, ad_data, len);
                packet->device_name[len] = '\0';
                break;
            }
            
            case AD_TYPE_TX_POWER:
                if (ad_data_len >= 1) {
                    packet->tx_power = (int8_t)ad_data[0];
                }
                break;
                
            case AD_TYPE_APPEARANCE:
                if (ad_data_len >= 2) {
                    packet->appearance = ad_data[0] | (ad_data[1] << 8);
                }
                break;
                
            case AD_TYPE_UUID16_INCOMPLETE:
            case AD_TYPE_UUID16_COMPLETE: {
                // Parse UUIDs
                int n = ad_data_len / 2;
                for (int j = 0; j < n && packet->num_services < 8; j++) {
                    packet->service_uuids[packet->num_services++] = 
                        ad_data[j*2] | (ad_data[j*2+1] << 8);
                }
                break;
            }
            
            case AD_TYPE_MFG_DATA:
                if (ad_data_len >= 2) {
                    packet->company_id = ad_data[0] | (ad_data[1] << 8);
                    uint8_t mfg_len = ad_data_len - 2;
                    if (mfg_len > (uint8_t)sizeof(packet->mfg_data)) {
                        mfg_len = (uint8_t)sizeof(packet->mfg_data);
                    }
                    memcpy(packet->mfg_data, &ad_data[2], mfg_len);
                    packet->mfg_data_len = mfg_len;
                }
                break;
                
            default:
                break;
        }
        
        i += ad_len + 1;
    }
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
    if (!packet) {
        return;
    }
}

// Legacy wrapper
void sniffer_on_packet_received(const uint8_t *mac, int8_t rssi, 
                                uint8_t channel, uint32_t timestamp,
                                const uint8_t *payload, uint8_t payload_len)
{
    sniffer_on_packet_received_ex(mac, rssi, channel, timestamp, 
                                  payload, payload_len, 0, 0);
}

/* Extended callback with full packet info */
void sniffer_on_packet_received_ex(const uint8_t *mac, int8_t rssi, 
                                   uint8_t channel, uint32_t timestamp,
                                   const uint8_t *payload, uint8_t payload_len,
                                   uint8_t adv_type, uint8_t addr_type)
{
    ble_packet_t packet = {0};
    
    if (!mac || !payload || payload_len == 0) {
        return;
    }
    
    // Fill packet struct
    memcpy(packet.mac, mac, 6);
    packet.rssi = rssi;
    packet.channel = channel;
    packet.timestamp = timestamp;
    packet.payload_len = payload_len;
    packet.adv_type = adv_type;
    packet.addr_type = addr_type;
    
    /* payload_len is uint8_t (max 255), packet.payload is 255 bytes, so always fits */
    memcpy(packet.payload, payload, payload_len);
    
    // Parse advertisement data
    parse_advertisement_data(payload, payload_len, &packet);
    
    sniffer_enqueue_packet(&packet);
}

void sniffer_init(void)
{
    printf("[SNIFFER] Init (buffer: %d)\r\n", SNIFFER_BUFFER_SIZE);
    memset(&g_packet_buffer, 0, sizeof(packet_buffer_t));
}

void sniffer_start(void)
{
    printf("[SNIFFER] Capture started\r\n");
}

int sniffer_get_packet(ble_packet_t *packet)
{
    if (!packet) {
        return 0;
    }
    return sniffer_dequeue_packet(packet);
}

void sniffer_get_stats(uint32_t *total_packets, uint32_t *overflow_count, 
                       uint32_t *buffer_count)
{
    taskENTER_CRITICAL();
    if (total_packets) *total_packets = g_packet_buffer.packet_count;
    if (overflow_count) *overflow_count = g_packet_buffer.overflow_count;
    if (buffer_count) *buffer_count = g_packet_buffer.count;
    taskEXIT_CRITICAL();
}

static void sniffer_task(void *arg)
{
    (void)arg;
    ble_packet_t pkt = {0};
    uint32_t last_status = 0;
    uint32_t last_cnt = 0;
    
    printf("[SNIFFER] Task running\r\n");
    
    while (1) {
        if (sniffer_get_packet(&pkt)) {
            sniffer_send_packet_serial(&pkt);
            vTaskDelay(pdMS_TO_TICKS(2));
        } else {
            vTaskDelay(pdMS_TO_TICKS(20));
        }
        
        // Status every 10s
        uint32_t now = xTaskGetTickCount();
        if ((now - last_status) > pdMS_TO_TICKS(10000)) {
            last_status = now;
            uint32_t rate = (g_packet_buffer.packet_count - last_cnt) / 10;
            printf("[SNIFFER] Total=%lu Rate=%lu/s Overflow=%lu Buffer=%u/%u\r\n",
                   g_packet_buffer.packet_count, rate, 
                   g_packet_buffer.overflow_count, g_packet_buffer.count, SNIFFER_BUFFER_SIZE);
            last_cnt = g_packet_buffer.packet_count;
        }
    }
}

void sniffer_create_task(void)
{
    static StaticTask_t task_buf;
    static StackType_t stack[1536];
    
    xTaskCreateStatic(sniffer_task, "sniffer", 1536, NULL, 12, stack, &task_buf);
}

