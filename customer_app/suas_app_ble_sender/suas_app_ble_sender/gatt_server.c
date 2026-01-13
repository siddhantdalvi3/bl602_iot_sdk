#include <config.h>
#include <bluetooth.h>
#include <gatt.h>
#include <uuid.h>
#include "include/ble.h"

/* Extern callbacks implemented in C++ */
extern void ble_bl_ccc_cfg_changed(const struct bt_gatt_attr* attr, u16_t value);
extern int ble_blf_recv(struct bt_conn* conn, const struct bt_gatt_attr* attr,
                 const void* buf, u16_t len, u16_t offset, u8_t flags);

/* Advertising data */
struct bt_data advertising_data[] = {
    /* Gerneral discoverable, BR/EDR nor supported (BLE only) */
    BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),

    /* Name of discoverable device */
    BT_DATA(BT_DATA_NAME_COMPLETE, "BL602_Sender", 12),

    /* Manufacturer specific data */
    BT_DATA(BT_DATA_MANUFACTURER_DATA, "BL602_Sender", 12),
};

size_t get_advertising_data_count(void) {
    return ARRAY_SIZE(advertising_data);
}

/* Definition of the server */
struct bt_gatt_attr blattrs[] = {
    /* (Primary) Service */
    BT_GATT_PRIMARY_SERVICE(BT_UUID_TEST), /* Service UUID */

    /* Characteristic */
    BT_GATT_CHARACTERISTIC(
        BT_UUID_TEST_RX,     /* Attribute UUID */
        BT_GATT_CHRC_NOTIFY, /* Atribute properties: permit notifications sent
                                from client */
        BT_GATT_PERM_READ,   /* Attribute access permissions (read-only) */
        NULL,                /* Attribute read callback */
        NULL,                /* Attribute write callback */
        NULL),               /* Attribute value */

    /* Client Characteristic Configuration */
    BT_GATT_CCC(
        ble_bl_ccc_cfg_changed, /* Configuration changed callback */
        BT_GATT_PERM_READ |
            BT_GATT_PERM_WRITE), /* CCC access permissions: read and write */

    /* Characteristic */
    BT_GATT_CHARACTERISTIC(
        BT_UUID_TEST_TX,                 /* Attribute UUID*/
        BT_GATT_CHRC_WRITE_WITHOUT_RESP, /* Attribute properties: write without
                                            response */
        BT_GATT_PERM_READ | BT_GATT_PERM_WRITE, /* Attribute access permissions
                                                   (read and write) */
        NULL,                                   /* Attribute read callback */
        ble_blf_recv,                           /* Attribute write callback */
        NULL)                                   /* Attribute value */
};

/* Create server data structure*/
struct bt_gatt_service ble_bl_server = BT_GATT_SERVICE(blattrs);
