extern "C" {
// FreeRTOS
#include <FreeRTOS.h>

// Bluetooth stack
#include <ble_lib_api.h>
#include <gatt.h>
#include <hci_driver.h>

// AOS HAL
#include <aos/yloop.h>

// Standard library
#include <stdint.h>
#include <stdio.h>

// Declaration for hci_driver_init if not defined by BFLB_BLE
int hci_driver_init(void);
}

// Own headers
#include "include/ble.h"
#include "include/peripheral.h"

/* Connection data structure */
static struct bt_conn* default_conn;

/* Function prototypes */
void ble_bl_ccc_cfg_changed(const struct bt_gatt_attr* attr, u16_t vblfue);
ssize_t ble_blf_recv(struct bt_conn* conn, const struct bt_gatt_attr* attr,
                     const void* buf, u16_t len, u16_t offset, u8_t flags);
void ble_peripheral_connected(struct bt_conn* conn, uint8_t err);
void ble_peripheral_disconnected(struct bt_conn* conn, uint8_t reason);

/* Connection callback function definitions */

static struct bt_conn_cb conn_callbacks = {
    .connected = ble_peripheral_connected,
    .disconnected = ble_peripheral_disconnected,
    .le_param_req = NULL,
    .le_param_updated = NULL,
    ._next = NULL,
};

/* Is notify feature enabled? */
static bool notify_flag = false;

/* Advertising data */
static uint8_t adv_flags[] = {BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR};
static const struct bt_data advertising_data[] = {
    /* Gerneral discoverable, BR/EDR nor supported (BLE only) */
    BT_DATA(BT_DATA_FLAGS, adv_flags, sizeof(adv_flags)),

    /* Name of discoverable device */
    BT_DATA(BT_DATA_NAME_COMPLETE, "BL602_Sender", 12),

    /* Manufacturer specific data */
    BT_DATA(BT_DATA_MANUFACTURER_DATA, "BL602_Sender", 12),
};

/* Definition of the server */
static struct bt_uuid_16 uuid_test_struct = BT_UUID_INIT_16(0xFFF0);
static struct bt_uuid_16 uuid_test_rx_struct = BT_UUID_INIT_16(0xFFF1);
static struct bt_uuid_16 uuid_test_tx_struct = BT_UUID_INIT_16(0xFFF2);

// Standard GATT UUIDs
static struct bt_uuid_16 uuid_gatt_primary_service = BT_UUID_INIT_16(0x2800);
static struct bt_uuid_16 uuid_gatt_chrc = BT_UUID_INIT_16(0x2803);
static struct bt_uuid_16 uuid_gatt_ccc = BT_UUID_INIT_16(0x2902);

/* Characteristic Values */
static struct bt_gatt_chrc rx_chrc_val = {
    .uuid = &uuid_test_rx_struct.uuid,
    .value_handle = 0U,
    .properties = BT_GATT_CHRC_NOTIFY,
};

static struct bt_gatt_chrc tx_chrc_val = {
    .uuid = &uuid_test_tx_struct.uuid,
    .value_handle = 0U,
    .properties = BT_GATT_CHRC_WRITE_WITHOUT_RESP,
};

/* CCC Configuration */
static struct _bt_gatt_ccc ccc_config = {
    .cfg = {},
    .value = 0,
    .cfg_changed = ble_bl_ccc_cfg_changed,
    .cfg_write = NULL,
    .cfg_match = NULL,
};

static struct bt_gatt_attr blattrs[] = {
    /* (Primary) Service */
    {
        .uuid = &uuid_gatt_primary_service.uuid,
        .read = bt_gatt_attr_read_service,
        .write = NULL,
        .user_data = &uuid_test_struct.uuid,
        .handle = 0,
        .perm = BT_GATT_PERM_READ,
    },

    /* RX Characteristic Declaration */
    {
        .uuid = &uuid_gatt_chrc.uuid,
        .read = bt_gatt_attr_read_chrc,
        .write = NULL,
        .user_data = &rx_chrc_val,
        .handle = 0,
        .perm = BT_GATT_PERM_READ,
    },
    /* RX Characteristic Value */
    {
        .uuid = &uuid_test_rx_struct.uuid,
        .read = NULL,
        .write = NULL,
        .user_data = NULL,
        .handle = 0,
        .perm = BT_GATT_PERM_READ,
    },

    /* Client Characteristic Configuration */
    {
        .uuid = &uuid_gatt_ccc.uuid,
        .read = bt_gatt_attr_read_ccc,
        .write = bt_gatt_attr_write_ccc,
        .user_data = &ccc_config,
        .handle = 0,
        .perm = BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
    },

    /* TX Characteristic Declaration */
    {
        .uuid = &uuid_gatt_chrc.uuid,
        .read = bt_gatt_attr_read_chrc,
        .write = NULL,
        .user_data = &tx_chrc_val,
        .handle = 0,
        .perm = BT_GATT_PERM_READ,
    },
    /* TX Characteristic Value */
    {
        .uuid = &uuid_test_tx_struct.uuid,
        .read = NULL,
        .write = ble_blf_recv,
        .user_data = NULL,
        .handle = 0,
        .perm = BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
    }};

/* Create server data structure*/
static struct bt_gatt_service ble_bl_server = {
    .attrs = blattrs,
    .attr_count = sizeof(blattrs) / sizeof(blattrs[0]),
    .node = {0},
};

/* Send notification */
void ble_peripheral_send_notification() {
  static int counter = 0;
  // Data to send (Manufacturer Data: 2 bytes Company ID + Data)
  uint8_t mfg_data[32];

  // Set Dummy Company ID (0xFFFF)
  mfg_data[0] = 0xFF;
  mfg_data[1] = 0xFF;

  // Append MockData string
  int msg_len = snprintf((char*)&mfg_data[2], sizeof(mfg_data) - 2,
                         "This is a MockData line %d", counter++);
  int total_len = msg_len + 2;

  // Update Advertisement Data to include MockData in Manufacturer Data
  uint8_t adv_flags[] = {BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR};
  struct bt_data ad[] = {
      BT_DATA(BT_DATA_FLAGS, adv_flags, sizeof(adv_flags)),
      BT_DATA(BT_DATA_NAME_COMPLETE, "BL602_Sender", 12),
      BT_DATA(BT_DATA_MANUFACTURER_DATA, mfg_data, (u8_t)total_len),
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
ssize_t ble_blf_recv([[gnu::unused]] struct bt_conn* conn,
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
  return len;
}

/* Changes in client characteristic configuration */
void ble_bl_ccc_cfg_changed([[gnu::unused]] const struct bt_gatt_attr* attr,
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

/* Advertising parameters */
static struct bt_le_adv_param adv_param = {
    .id = 0,
    .options = BT_LE_ADV_OPT_CONNECTABLE | BT_LE_ADV_OPT_USE_NAME,
    .interval_min = BT_GAP_ADV_FAST_INT_MIN_2,
    .interval_max = BT_GAP_ADV_FAST_INT_MAX_2,
};

/* Start advertising */
void ble_peripheral_start_advertising() {
  bt_set_name("BL602_Sender");
  printf("[PERIPHERAL] Started advertising\r\n");

  /* Start advertising:
      Parameters:
          1: Advertising parameters (defined by static struct)
          2: Advertising data
          3: Size of advertising data
          4: Data to send in scan response packets to other devices
          5: Size of scan response data
  */
  int err = bt_le_adv_start(
      &adv_param, advertising_data,
      sizeof(advertising_data) / sizeof(advertising_data[0]), NULL, 0);
  if (err) {
    printf("[PERIPHERAL] Advertising failed to start: %d\r\n", err);
  } else {
    // Send advertising start message to event handler
    aos_post_event(EV_BLE_TEST, BLE_ADV_START, NULL);
  }
}

/* Bluetooth stack started callback */
void ble_peripheral_init(int err) {
  if (err != 0) {
    printf("[PERIPHERAL] Bluetooth initialization failed\r\n");
  } else {
    printf("[PERIPHERAL] Bluetooth initialization successed\r\n");

    // Start advertising
    ble_peripheral_start_advertising();
  }
}

/* Connected to device */
void ble_peripheral_connected(struct bt_conn* conn, uint8_t err) {
  // Set connection parameters
  struct bt_le_conn_param param;
  param.interval_max = 24;
  param.interval_min = 24;
  param.latency = 0;
  param.timeout = 600;

  if (err) {
    printf("[PERIPHERAL] Connection failed: 0x%02x\r\n", err);
  } else {
    printf("[PERIPHERAL] Connected to a device\r\n");

    // Update connection data
    default_conn = conn;
    int update_err = bt_conn_le_param_update(conn, &param);

    if (update_err) {
      printf("[PERIPHERAL] Connection update failed: %d\r\n", update_err);
    } else {
      printf("[PERIPHERAL] Connection update initiated\r\n");
    }

    // Send connection established message to device handler
    aos_post_event(EV_BLE_TEST, BLE_DEV_CONN, NULL);
  }
}

/* Device disconnected */
void ble_peripheral_disconnected([[gnu::unused]] struct bt_conn* conn,
                                 uint8_t reason) {
  printf("[PERIPHERAL] Disconnected, reason: 0x%02x\r\n", reason);

  // Send device disconnected message to device handler
  aos_post_event(EV_BLE_TEST, BLE_DEV_DISCONN, NULL);
}

/* Start bluetooth stack */
void ble_stack_start() {
  // Start up controller
  ble_controller_init(configMAX_PRIORITIES -
                      1);  // BLE Controller has maximum priority

  // Initialize host-controller driver
  hci_driver_init();

  // Enable bluetooth
  // Parameter: Callback function
  bt_enable(ble_peripheral_init);
}

/* Set up device as peripheral */
void start_peripheral_application() {
  // Start bluetooth stack
  ble_stack_start();

  // Register connection callbacks
  bt_conn_cb_register(&conn_callbacks);

  // Register GATT service
  int err = bt_gatt_service_register(&ble_bl_server);

  if (err == 0) {
    printf("[PERIPHERAL] GATT server started\r\n");
  } else {
    printf("[PERIPHERAL] Error happened during GATT server registration\r\n");
  }
}
