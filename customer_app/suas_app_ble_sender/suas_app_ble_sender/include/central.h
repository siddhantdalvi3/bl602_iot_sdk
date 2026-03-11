#ifndef __CENTRAL_H
#define __CENTRAL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes */
void ble_central_start_scanning();
void start_central_application();
void ble_central_write();
void ble_central_exchange_mtu();

#ifdef __cplusplus
}
#endif

#endif