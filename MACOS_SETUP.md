# macOS Development Setup for BL602 SDK

This guide describes how to set up the development environment for the BL602 IoT SDK on macOS.

## 1. Prerequisites

- **macOS**: Tested on macOS Sequoia (should work on recent versions).
- **Homebrew**: Required for installing packages. [Install Homebrew](https://brew.sh/).
- **Rust/Cargo**: Required for the flashing tool. [Install Rust](https://rustup.rs/).

## 2. Automated Setup

We have provided a script to automate the installation of dependencies and configuration.

1.  Open a terminal in the `bl602_iot_sdk` directory.
2.  Run the setup script:

    ```bash
    chmod +x macos_setup.sh
    ./macos_setup.sh
    ```

3.  Follow the instructions at the end of the script to export the necessary environment variables. Add them to your `~/.zshrc`:

    ```bash
    export BL60X_SDK_PATH=/path/to/your/bl602_iot_sdk
    export CONFIG_CHIP_NAME=BL602
    export CONFIG_TOOLPREFIX=riscv64-unknown-elf-
    ```

4.  Reload your shell configuration:
    ```bash
    source ~/.zshrc
    ```

## 3. Building a Project

To build an example project (e.g., `suas_app_helloworld`):

1.  Navigate to the project directory:

    ```bash
    cd customer_app/suas_app_helloworld
    ```

2.  Run `make`:

    ```bash
    make
    ```

The output binary will be located at `build_out/suas_app_helloworld.bin`.

## 4. Flashing the Firmware

We use `blflash` to flash the firmware.

1.  **Connect your PineCone/BL602 board** via USB.
2.  **Enter Bootloader Mode**:
    - Press and **HOLD** the **BOOT** button.
    - Press and **RELEASE** the **RESET** button.
    - **RELEASE** the **BOOT** button.
3.  **Identify your serial port**:

    ```bash
    ls /dev/tty.*
    ```

    (Usually `/dev/tty.usbserial-XXXX` or `/dev/tty.usbmodemXXXX`)

4.  **Flash**:
    ```bash
    blflash flash build_out/suas_app_helloworld.bin --port /dev/tty.usbserial-110 --baud-rate 115200
    ```
    _(Replace `/dev/tty.usbserial-110` with your actual port)_

## 5. Monitoring Output

To view the serial output (printf debugging):

1.  **Reset the board** (Press RESET button) to start the application.
2.  **Open a serial monitor**:

    ```bash
    screen /dev/tty.usbserial-110 115200
    ```

    - **To exit screen**: Press `Ctrl + A`, then `k`, then `y`.

## Troubleshooting

- **"Operation timed out" during flashing**:

  - Unplug and replug the device.
  - Ensure you are correctly entering Bootloader mode (Hold BOOT, press RESET, release BOOT).
  - Try a lower baud rate (e.g., `--baud-rate 115200`).

- **"Resource busy"**:

  - Another program (like `screen`) might be using the serial port. Close it or run `killall screen`.

- **Compiler errors**:
  - Ensure `CONFIG_TOOLPREFIX` is set correctly.
  - Ensure `project.mk` is patched to use `-march=rv32imafc` (the setup script does this).
