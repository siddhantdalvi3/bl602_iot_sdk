#include <FreeRTOS.h>
#include <task.h>
#include <bl_dma.h>
#include <bl_gpio.h>
#include <blog.h>
#include <hal_board.h>
#include <hal_uart.h>
#include <stdio.h>

/* BLE includes */
#include <ble_lib_api.h>

/* AOS includes */
#include <aos/yloop.h>
#include <cli.h>
#include <looprt.h>
#include <loopset.h>

/* VFS includes */
#include <event_device.h>
#include <libfdt.h>
#include <vfs.h>

#include "sniffer.h"
#include "scanner.h"

/* Forward declarations */
extern void fdt_button_module_init(const void *fdt, int offset);
extern void sniffer_create_task(void);

/* LED pins */
#define LED_BLUE   (11)
#define LED_GREEN  (14)
#define LED_RED    (10)

#define LOOPRT_STACK_SIZE 512
#define LOOP_PROC_STACK_SIZE 1024

void board_leds_off(void) {
    bl_gpio_output_set(LED_BLUE, 1);
    bl_gpio_output_set(LED_GREEN, 1);
    bl_gpio_output_set(LED_RED, 1);
}

/* Helper function to read device tree */
static int get_dts_addr(const char *name, uint32_t *start, uint32_t *off) {
    if (!name) {
        return -1;
    }

    const void *fdt = (const void *)hal_board_get_factory_addr();
    int offset = fdt_subnode_offset(fdt, 0, name);

    if (offset <= 0) {
        printf("ERROR: %s is invalid\r\n", name);
        return -1;
    }

    *start = (uint32_t)fdt;
    *off = offset;
    return 0;
}

/* Event loop */
static void aos_loop_proc(void *pvParameters) {
    (void)pvParameters;
    // Setup looprt task
    uint32_t fdt = 0, offset = 0;
    static StackType_t task_looprt_stack[LOOPRT_STACK_SIZE];
    static StaticTask_t task_looprt_task;

    /* Init looprt */
    looprt_start(task_looprt_stack, LOOPRT_STACK_SIZE, &task_looprt_task);
    loopset_led_hook_on_looprt();

    /* Initialize VFS */
    vfs_init();
    vfs_device_init();

    /* Setup UART */
    if (get_dts_addr("uart", &fdt, &offset) == 0) {
        vfs_uart_init(fdt, offset);
    }

    /* Setup GPIO */
    if (get_dts_addr("gpio", &fdt, &offset) == 0) {
        fdt_button_module_init((const void *)fdt, (int)offset);
    }

    /* Start loop */
    aos_loop_init();

    /* Initialize sniffer */
    sniffer_init();
    
    /* Start sniffer task for packet processing */
    sniffer_create_task();

    /* Initialize and start BLE scanner */
    scanner_init();

    aos_loop_run();

    printf("Exited real time loop!\r\n");
    vTaskDelete(NULL);
}

void bfl_main(void) {
    /* Task declarations */
    static StackType_t aos_loop_proc_stack[LOOP_PROC_STACK_SIZE];
    static StaticTask_t aos_loop_proc_task;

    /* Initialize system */
    vInitializeBL602();

    /* Initialize LEDs (all off initially) */
    bl_gpio_enable_output(LED_BLUE, 1, 0);
    bl_gpio_enable_output(LED_RED, 1, 0);
    bl_gpio_enable_output(LED_GREEN, 1, 0);
    board_leds_off();

    printf("\r\n");
    printf("*****************************\r\n");
    printf("  BLE Promiscuous Sniffer\r\n");
    printf("*****************************\r\n");
    printf("Listening for BLE packets...\r\n");

    /* Create tasks */
    xTaskCreateStatic(aos_loop_proc, "event loop",
                      LOOP_PROC_STACK_SIZE, NULL, 15, aos_loop_proc_stack,
                      &aos_loop_proc_task);

    /* Start tasks */
    vTaskStartScheduler();
}
