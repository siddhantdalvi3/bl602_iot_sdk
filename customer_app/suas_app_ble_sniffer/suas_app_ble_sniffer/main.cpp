extern "C" {
// FreeRTOS
#include <FreeRTOS.h>
#include <task.h>

// HAL & Hardware
#include <bl_dma.h>
#include <bl_gpio.h>
#include <hal_board.h>
#include <hal_uart.h>
#include <libfdt.h>

// AOS / Loop
#include <aos/yloop.h>
#include <looprt.h>
#include <loopset.h>

// CLI & Utils
#include <blog.h>
#include <cli.h>
#include <vfs.h>

// BLE
#include <ble_lib_api.h>
#include <event_device.h>
}

extern "C" {
void bl_uart_setbaud(uint8_t id, uint32_t baud);
}

// Project headers
#include "include/scanner.h"
#include "include/sniffer.h"

extern "C" void fdt_button_module_init(const void* fdt, int offset);

// These are for the DT-BL10 module.
// FIXME: If you use a different board, check your schematic!
#define LED_BLUE 11
#define LED_GREEN 14
#define LED_RED 17

#define LOOPRT_STACK_SIZE 512
#define LOOP_PROC_STACK_SIZE 1024

// TODO: move this somewhere else, hardcoded for now
void board_leds_off(void) {
  bl_gpio_output_set(LED_BLUE, 1);
  bl_gpio_output_set(LED_GREEN, 1);
  bl_gpio_output_set(LED_RED, 1);
}

static int get_dts_addr(const char* name, uint32_t* start, uint32_t* off) {
  const void* fdt = (const void*)hal_board_get_factory_addr();
  int offset = fdt_subnode_offset(fdt, 0, name);

  if (offset <= 0) {
    printf("Error: %s is invalid\r\n", name);
    return -1;
  }

  *start = (uint32_t)fdt;
  *off = offset;
  return 0;
}

extern "C" {
static void aos_loop_proc(void* pvParameters) {
  (void)pvParameters;
  uint32_t fdt = 0, off = 0;
  static StackType_t task_looprt_stack[LOOPRT_STACK_SIZE];
  static StaticTask_t task_looprt_task;

  looprt_start(task_looprt_stack, LOOPRT_STACK_SIZE, &task_looprt_task);
  loopset_led_hook_on_looprt();
  vfs_init();
  vfs_device_init();

  // Init UART from device tree
  if (get_dts_addr("uart", &fdt, &off) == 0) {
    vfs_uart_init(fdt, off);
    // Force baud rate to 115200
    bl_uart_setbaud(0, 115200);
  }

  // Init GPIO (button stuff)
  if (get_dts_addr("gpio", &fdt, &off) == 0) {
    fdt_button_module_init((const void*)fdt, (int)off);
  }

  aos_loop_init();
  sniffer_init();
  sniffer_create_task();
  scanner_init();

  aos_loop_run();
  printf("Exited the real time loop!\r\n");
  vTaskDelete(NULL);
}
}

extern "C" void bfl_main(void) {
  static StackType_t aos_loop_proc_stack[LOOP_PROC_STACK_SIZE];
  static StaticTask_t aos_loop_proc_task;

  vInitializeBL602();

  // Setup LED pins
  bl_gpio_enable_output(LED_BLUE, 1, 0);
  bl_gpio_enable_output(LED_RED, 1, 0);
  bl_gpio_enable_output(LED_GREEN, 1, 0);
  board_leds_off();

  printf("\r\n");
  printf("--------\r\n");
  printf("BLE Promiscuous Sniffer\r\n");
  printf("--------\r\n");
  printf("Listening for BLE packets...\r\n");

  // Start event loop task
  xTaskCreateStatic(aos_loop_proc, "event loop", LOOP_PROC_STACK_SIZE, NULL, 15,
                    aos_loop_proc_stack, &aos_loop_proc_task);
  vTaskStartScheduler();
}
