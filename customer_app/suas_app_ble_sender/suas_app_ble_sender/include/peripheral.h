#ifndef __PERIPHERAL_H
#define __PERIPHERAL_H

#ifdef __cplusplus
extern "C" {
#endif

// Function prototypes
void ble_peripheral_start_advertising();
void start_peripheral_application();
void ble_peripheral_send_notification();
void ble_peripheral_exchange_mtu();

#ifdef __cplusplus
}
#endif

#endif
