// FreeRTOS
extern "C" {
#include <config.h>
#include <FreeRTOS.h>
}

// Bluetooth stack
extern "C" {
#include <ble_lib_api.h>
#include <gatt.h>
#include <hci_driver.h>
#include <bluetooth.h>

// AOS HAL
#include <aos/yloop.h>
}

// Standard library
#include <stdint.h>
#include <stdio.h>

// Own headers
#include "include/ble.h"
#include "include/peripheral.h"

/* Connection data structure */
static struct bt_conn* default_conn;

/* Function prototypes */
extern "C" void ble_bl_ccc_cfg_changed(const struct bt_gatt_attr* attr, u16_t vblfue);
extern "C" int ble_blf_recv(struct bt_conn* conn, const struct bt_gatt_attr* attr,
                 const void* buf, u16_t len, u16_t offset, u8_t flags);
extern "C" void ble_peripheral_connected(struct bt_conn* conn, uint8_t err);
extern "C" void ble_peripheral_disconnected(struct bt_conn* conn, uint8_t reason);

/* Connection callback function definitions */

static struct bt_conn_cb conn_callbacks;

/* Helper to get array size from C file */
extern "C" size_t get_advertising_data_count(void);

/* Is notify feature enabled? */
static bool notify_flag = false;

/* Advertising data (defined in gatt_server.c) */
extern struct bt_data advertising_data[];

/* Definition of the server (defined in gatt_server.c) */
extern struct bt_gatt_attr blattrs[];

/* Create server data structure (defined in gatt_server.c) */
extern struct bt_gatt_service ble_bl_server;

/* Send notification */
void ble_peripheral_send_notification() {
  static int counter = 0;
  // Data to send (Manufacturer Data: 2 bytes Company ID + Data)
  uint8_t mfg_data[32];
  
  // Set Dummy Company ID (0xFFFF)
  mfg_data[0] = 0xFF;
  mfg_data[1] = 0xFF;
  
  // Append MockData string
  int msg_len = snprintf((char*)&mfg_data[2], sizeof(mfg_data) - 2, "This is a MockData line %d", counter++);
  int total_len = msg_len + 2;

  // Update Advertisement Data to include MockData in Manufacturer Data
  uint8_t flags[] = { (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR) };
  struct bt_data ad[] = {
      { BT_DATA_FLAGS, sizeof(flags), flags },
      { BT_DATA_NAME_COMPLETE, 12, (const u8_t*)"BL602_Sender" },
      { BT_DATA_MANUFACTURER_DATA, (u8_t)total_len, mfg_data },
  };
  bt_le_adv_update_data(ad, sizeof(ad) / sizeof(ad[0]), NULL, 0);

  // Send data if connection available and notifications allowed
  if (default_conn != NULL && notify_flag == true) {
    char* msg_ptr = (char*)&mfg_data[2];
    printf("[PERIPHERAL] Sending notification: %s\r\n", msg_ptr);

    /* Send notification:
        Parameters:
        1: Connection
        2: Characteristic to handle: notification
        3: Data to send
        4: Length of the data
    */
    bt_gatt_notify(default_conn, &blattrs[1], msg_ptr, msg_len);
  }
}

/* Received data callback function */
extern "C" int ble_blf_recv([[gnu::unused]] struct bt_conn* conn,
                 [[gnu::unused]] const struct bt_gatt_attr* attr,
                 const void* buf, u16_t len, [[gnu::unused]] u16_t offset,
                 [[gnu::unused]] u8_t flags) {
  // Get storage to hold received data
  uint8_t recv_buffer[len];

  // Copy received data to storage
  memcpy(recv_buffer, buf, len);

  // Print received data byte-wise, interpreted as character
  printf("[PERIPHERAL] Received data: '");
  for (uint16_t i = 0; i < len; i++) {
    printf("%c", recv_buffer[i]);
  }
  printf("'\r\n");
  return 0;
}

/* Changes in client characteristic configuration */
extern "C" void ble_bl_ccc_cfg_changed([[gnu::unused]] const struct bt_gatt_attr* attr,
                            u16_t value) {
  // Enable notifications if requested
  if (value == BT_GATT_CCC_NOTIFY) {
    notify_flag = true;
    printf("[PERIPHERAL] Enabled notifications\r\n");
  } else {
    notify_flag = false;
    printf("[PERIPHERAL] Disabled notifications\r\n");
  }
}

/* Start advertising */
void ble_peripheral_start_advertising() {
  bt_set_name("BL602_Sender");
  printf("[PERIPHERAL] Started advertising\r\n");

  /* Start advertising:
      Parameters:
          1: Advertising parameters (defined by macro)
          2: Advertising data
          3: Size of advertising data
          4: Data to send in scan response packets to other devices
          5: Size of scan response data
  */
  struct bt_le_adv_param adv_param = {
      .id = 0,
      .options = (BT_LE_ADV_OPT_CONNECTABLE | BT_LE_ADV_OPT_USE_NAME),
      .interval_min = BT_GAP_ADV_FAST_INT_MIN_2,
      .interval_max = BT_GAP_ADV_FAST_INT_MAX_2,
  };
  int err = bt_le_adv_start(&adv_param, advertising_data,
                            get_advertising_data_count(), NULL, 0);
  if (err) {
    printf("[PERIPHERAL] Advertising failed to start: %d\r\n", err);
  } else {
    // Send advertising start message to event handler
    aos_post_event(EV_BLE_TEST, BLE_ADV_START, NULL);
  }
}

/* Bluetooth stack started callback */
extern "C" void ble_peripheral_init(int err) {
  if (err != 0) {
    printf("[PERIPHERAL] Bluetooth initialization failed\r\n");
  } else {
    printf("[PERIPHERAL] Bluetooth initialization successed\r\n");

    // Register connection callbacks
    conn_callbacks.connected = ble_peripheral_connected;
    conn_callbacks.disconnected = ble_peripheral_disconnected;
    bt_conn_cb_register(&conn_callbacks);

    // Start advertising
    ble_peripheral_start_advertising();
  }
}

/* Start peripheral application */
extern "C" void start_peripheral_application() {
  // Initialize BLE stack
  bt_enable(ble_peripheral_init);
}

/* Connected to device */
extern "C" void ble_peripheral_connected(struct bt_conn* conn, uint8_t err) {
  // Set connection parameters
  struct bt_le_conn_param param;
  param.interval_max = 24;
  param.interval_min = 24;
  param.latency = 0;
  param.timeout = 600;

  if (err) {
    printf("[PERIPHERAL] Connection failed\r\n");
  } else {
    default_conn = bt_conn_ref(conn);
    printf("[PERIPHERAL] Connected\r\n");

    // Update connection parameters
    int err = bt_conn_le_param_update(conn, &param);
    if (err) {
      printf("[PERIPHERAL] Connection parameters update failed: %d\r\n", err);
    } else {
      printf("[PERIPHERAL] Connection parameters update pending\r\n");
    }

    // Post event to message broker
    aos_post_event(EV_BLE_TEST, BLE_DEV_CONN, NULL);
  }
}

/* Disconnected from device */
extern "C" void ble_peripheral_disconnected(struct bt_conn* conn, uint8_t reason) {
  (void)conn;
  printf("[PERIPHERAL] Disconnected (reason: %u)\r\n", reason);

  if (default_conn) {
    bt_conn_unref(default_conn);
    default_conn = NULL;
  }

  // Post event to message broker
  aos_post_event(EV_BLE_TEST, BLE_DEV_DISCONN, NULL);
  
  // Restart advertising
  ble_peripheral_start_advertising();
}
