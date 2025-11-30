#ifndef __SCANNER_H__
#define __SCANNER_H__

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

#endif /* __SCANNER_H__ */
