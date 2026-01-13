#ifndef __BLE_H
#define __BLE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Event codes used by PineCone to communicate with the Bluetooth controller */
#define BLE_ADV_START 0x01
#define BLE_ADV_STOP 0x02
#define BLE_DEV_CONN 0x03
#define BLE_DEV_DISCONN 0x04
#define BLE_SCAN_START 0x05
#define BLE_SCAN_STOP 0x06
#define BLE_DEV_SUBSCRIBED 0x07
#define EV_BLE_TEST 0x0504

/* UUIDs to reference services */
#ifdef __cplusplus
#include <uuid.h>
/* C++ compatible definitions using static const to avoid rvalue address issues */
static const struct bt_uuid_16 _UUID_TEST = BT_UUID_INIT_16(0xFFF0);
static const struct bt_uuid_16 _UUID_TEST_RX = BT_UUID_INIT_16(0xFFF1);
static const struct bt_uuid_16 _UUID_TEST_TX = BT_UUID_INIT_16(0xFFF2);
#define BT_UUID_TEST ((const struct bt_uuid *)&_UUID_TEST)
#define BT_UUID_TEST_RX ((const struct bt_uuid *)&_UUID_TEST_RX)
#define BT_UUID_TEST_TX ((const struct bt_uuid *)&_UUID_TEST_TX)

/* Fix standard UUIDs for C++ */
#undef BT_UUID_GATT_PRIMARY
static const struct bt_uuid_16 _UUID_GATT_PRIMARY = BT_UUID_INIT_16(0x2800);
#define BT_UUID_GATT_PRIMARY ((const struct bt_uuid *)&_UUID_GATT_PRIMARY)

#undef BT_UUID_GATT_CHRC
static const struct bt_uuid_16 _UUID_GATT_CHRC = BT_UUID_INIT_16(0x2803);
#define BT_UUID_GATT_CHRC ((const struct bt_uuid *)&_UUID_GATT_CHRC)

#undef BT_UUID_GATT_CCC
static const struct bt_uuid_16 _UUID_GATT_CCC = BT_UUID_INIT_16(0x2902);
#define BT_UUID_GATT_CCC ((const struct bt_uuid *)&_UUID_GATT_CCC)

#else
/* C definitions */
#define BT_UUID_TEST BT_UUID_DECLARE_16(0xFFF0)
#define BT_UUID_TEST_RX BT_UUID_DECLARE_16(0xFFF1)
#define BT_UUID_TEST_TX BT_UUID_DECLARE_16(0xFFF2)
#endif

/* Constants */
#define NAME_LEN 30

#ifdef __cplusplus
}
#endif

#endif
