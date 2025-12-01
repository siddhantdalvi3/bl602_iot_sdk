#include <FreeRTOS.h>
#include <task.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ble_lib_api.h>
#include <gatt.h>
#include <hci_driver.h>

#include "include/sniffer.h"
#include "include/scanner.h"

static struct bt_le_scan_param scan_param;

static uint8_t g_scan_mode = 0;
static uint8_t g_current_channel = 37;

static uint32_t g_adv_count = 0;
static uint32_t g_scan_rsp_count = 0;

static void scanner_device_found(const bt_addr_le_t *addr, int8_t rssi,
                                  uint8_t adv_type, struct net_buf_simple *ad)
{
    uint32_t ts;
    
    if (!addr || !ad) {
        return;
    }
    
    ts = (uint32_t)xTaskGetTickCount() * portTICK_PERIOD_MS;
    
    // Track scan responses vs regular adverts
    if (adv_type == 0x04) {
        g_scan_rsp_count++;
    } else {
        g_adv_count++;
    }
    
    // HACK: approximate channel cycling (no access to actual channel info)
    g_current_channel = 37 + (g_adv_count % 3);
    
    sniffer_on_packet_received_ex(
        addr->a.val, rssi, g_current_channel, ts,
        ad->data, ad->len, adv_type, addr->type
    );
}

static void scanner_ble_enabled(int err)
{
    if (err) {
        printf("[SCANNER] BLE enable failed: %d\r\n", err);
        return;
    }
    
    printf("[SCANNER] BLE enabled, starting scan...\r\n");
    scanner_start();
}

static void ble_stack_init(void)
{
    int err;
    
    printf("[SCANNER] Initializing BLE stack...\r\n");
    
    // Set up scan params
    scan_param.type = g_scan_mode ? BT_LE_SCAN_TYPE_ACTIVE : BT_LE_SCAN_TYPE_PASSIVE;
    scan_param.filter_dup = 0;  // Get all packets, no filtering
    
    // 100% duty cycle: scan continuously
    scan_param.interval = 0x30;
    scan_param.window = 0x30;

    printf("[SCANNER] Scan mode: %s (interval: %d ms)\r\n", 
           g_scan_mode ? "ACTIVE" : "PASSIVE", (scan_param.interval * 625) / 1000);
    
    ble_controller_init(configMAX_PRIORITIES - 1);
    printf("[SCANNER] BLE controller initialized\r\n");
    
    hci_driver_init();
    printf("[SCANNER] HCI driver init done\r\n");
    
    // Enable and wait for callback
    err = bt_enable(scanner_ble_enabled);
    if (err) {
        printf("[SCANNER] bt_enable() failed: %d\r\n", err);
    }
}

void scanner_start(void)
{
    int err = bt_le_scan_start(&scan_param, scanner_device_found);
    if (err) {
        printf("[SCANNER] Scan start failed: %d\r\n", err);
        return;
    }
    
    printf("[SCANNER] Scanning started (ch 37, 38, 39)\r\n");
}

void scanner_stop(void)
{
    int err = bt_le_scan_stop();
    if (err) {
        printf("[SCANNER] Scan stop failed: %d\r\n", err);
        return;
    }
    
    printf("[SCANNER] Scan stopped - ADV:%lu SCAN_RSP:%lu\r\n", 
           g_adv_count, g_scan_rsp_count);
}

void scanner_set_mode(uint8_t active)
{
    g_scan_mode = active ? 1 : 0;
    printf("[SCANNER] Mode: %s\r\n", g_scan_mode ? "ACTIVE" : "PASSIVE");
}

void scanner_get_stats(uint32_t *adv_count, uint32_t *scan_rsp_count)
{
    if (adv_count) *adv_count = g_adv_count;
    if (scan_rsp_count) *scan_rsp_count = g_scan_rsp_count;
}

void scanner_init(void)
{
    printf("[SCANNER] Initializing scanner...\r\n");
    
    g_adv_count = 0;
    g_scan_rsp_count = 0;
    g_scan_mode = 1;  // Default to active mode
    
    ble_stack_init();
}
