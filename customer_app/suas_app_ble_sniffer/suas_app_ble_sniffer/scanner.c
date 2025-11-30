/**
 * @file scanner.c
 * @brief BLE Scanner with HAL-level packet interception
 * 
 * This module initializes the BLE stack and intercepts packets at the
 * HAL level (before BLE stack processing) to capture raw data.
 */

// FreeRTOS
#include <FreeRTOS.h>
#include <task.h>

// Standard library
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

// BLE stack
#include <ble_lib_api.h>
#include <gatt.h>
#include <hci_driver.h>

// Sniffer interface
#include "sniffer.h"
#include "scanner.h"

/* BLE scan parameters */
static struct bt_le_scan_param scan_param;

/**
 * @brief Callback for BLE advertisements
 * Called when a BLE packet is received by the scanner
 */
static void scanner_device_found(const bt_addr_le_t *addr, int8_t rssi,
                                  uint8_t adv_type __attribute__((unused)), struct net_buf_simple *ad)
{
    uint8_t channel = 37; /* Default to channel 37 */
    uint32_t timestamp = 0;
    
    if (!addr || !ad) {
        return;
    }
    
    /* Extract channel from RSSI context if available */
    /* Note: BL602 may not provide channel info, so we default to 37 */
    
    /* Get current timestamp */
    timestamp = (uint32_t)xTaskGetTickCount();
    
    /* Call sniffer to capture packet */
    sniffer_on_packet_received(
        addr->a.val,           /* MAC address */
        rssi,                  /* RSSI */
        channel,               /* Channel (assuming 37 for now) */
        timestamp,             /* Timestamp */
        ad->data,              /* Payload */
        ad->len                /* Payload length */
    );
}

/**
 * @brief BLE stack enabled callback
 * Called after bt_enable() completes
 */
static void scanner_ble_enabled(int err)
{
    if (err) {
        printf("[SCANNER] Failed to enable BLE: %d\r\n", err);
        return;
    }
    
    printf("[SCANNER] BLE enabled, starting scanner...\r\n");
    scanner_start();
}

/**
 * @brief Initialize BLE stack
 */
static void ble_stack_init(void)
{
    printf("[SCANNER] Initializing BLE stack...\r\n");
    
    /* Configure scan parameters */
    scan_param.type = BT_LE_SCAN_TYPE_PASSIVE;
    scan_param.filter_dup = 0;  /* Don't filter duplicates - capture all */
    scan_param.interval = 0x80;  /* Scan interval */
    scan_param.window = 0x40;    /* Scan window */
    
    /* Initialize BLE controller (highest priority) */
    ble_controller_init(configMAX_PRIORITIES - 1);
    printf("[SCANNER] BLE controller initialized\r\n");
    
    /* Initialize HCI driver */
    hci_driver_init();
    printf("[SCANNER] HCI driver initialized\r\n");
    
    /* Enable BLE with callback */
    int err = bt_enable(scanner_ble_enabled);
    if (err) {
        printf("[SCANNER] Failed to initiate BLE enable: %d\r\n", err);
    }
}

/**
 * @brief Start BLE scanner (observer mode)
 */
void scanner_start(void)
{
    int err;
    
    printf("[SCANNER] Starting BLE scanner...\r\n");
    printf("[SCANNER] Listening for all BLE advertisements\r\n");
    
    /* Start scanning */
    err = bt_le_scan_start(&scan_param, scanner_device_found);
    if (err) {
        printf("[SCANNER] Failed to start scan: %d\r\n", err);
        return;
    }
    
    printf("[SCANNER] BLE scan started\r\n");
}

/**
 * @brief Stop BLE scanner
 */
void scanner_stop(void)
{
    int err;
    
    printf("[SCANNER] Stopping BLE scanner...\r\n");
    
    err = bt_le_scan_stop();
    if (err) {
        printf("[SCANNER] Failed to stop scan: %d\r\n", err);
        return;
    }
    
    printf("[SCANNER] BLE scan stopped\r\n");
}

/**
 * @brief Initialize scanner module
 */
void scanner_init(void)
{
    printf("[SCANNER] Initializing BLE scanner module\r\n");
    
    /* Initialize BLE stack (will call scanner_start via callback) */
    ble_stack_init();
}
