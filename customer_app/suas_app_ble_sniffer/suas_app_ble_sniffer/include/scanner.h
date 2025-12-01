#ifndef __SCANNER_H__
#define __SCANNER_H__

#include <stdint.h>

/**
 * @brief Initialize BLE scanner (starts BLE stack and scanning)
 */
void scanner_init(void);

/**
 * @brief Start BLE scanner
 */
void scanner_start(void);

/**
 * @brief Stop BLE scanner
 */
void scanner_stop(void);

/**
 * @brief Set scan mode
 * @param active 1 for active scanning (gets SCAN_RSP), 0 for passive
 */
void scanner_set_mode(uint8_t active);

/**
 * @brief Get scanner statistics
 * @param adv_count Pointer to store advertisement count
 * @param scan_rsp_count Pointer to store scan response count
 */
void scanner_get_stats(uint32_t *adv_count, uint32_t *scan_rsp_count);

#endif /* __SCANNER_H__ */
