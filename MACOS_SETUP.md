# macOS Development Setup for BL602 SDK

This guide describes how to set up the development environment for the BL602 IoT SDK on macOS.

## 1. Prerequisites

- **macOS**: Tested on macOS Sequoia (should work on recent versions).
- **Homebrew**: Required for installing packages. [Install Homebrew](https://brew.sh/).
- **Rust/Cargo**: Required for the flashing tool (will be installed automatically by the setup script if missing).

## 2. Automated Setup

We have provided a script to automate the installation of dependencies and configuration.

1.  Open a terminal in the `bl602_iot_sdk` directory.
2.  Run the setup script:

    ```bash
    chmod +x macos_setup.sh
    ./macos_setup.sh
    ```

    This script will:

    - Install the RISC-V toolchain, CMake, Ninja, Python3, and DTC via Homebrew.
    - Create a Python virtual environment (`venv`) to avoid "externally-managed-environment" errors.
    - Install Python dependencies inside the virtual environment.
    - Patch `project.mk` for macOS toolchain compatibility.
    - Install Rust (if missing) and the `blflash` flashing tool.

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

**Important:** Before building, you must activate the Python virtual environment.

### Setting Up the Python Virtual Environment (Manual Method)

If you didn't run the setup script, or need to recreate the virtual environment manually:

1.  Create the virtual environment (only needed once):

    ```bash
    cd /path/to/bl602_iot_sdk
    python3 -m venv venv
    ```

2.  Activate the virtual environment:

    ```bash
    source venv/bin/activate
    ```

    _(You will see `(venv)` at the start of your terminal prompt)_

3.  Install the required Python packages:

    ```bash
    pip install --upgrade pip
    pip install -r image_conf/requirements.txt
    ```

### Building

1.  Activate the virtual environment:

    ```bash
    source /path/to/bl602_iot_sdk/venv/bin/activate
    ```

    _(You will see `(venv)` at the start of your terminal prompt)_

2.  Navigate to the project directory:

    ```bash
    cd customer_app/suas_app_helloworld
    ```

3.  Run `make`:

    ```bash
    make
    ```

The output binary will be located at `build_out/suas_app_helloworld.bin`.

> **Note:** You must activate the virtual environment every time you open a new terminal window before running `make`.

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

- **"externally-managed-environment" error during `make`**:

  - You forgot to activate the Python virtual environment.
  - Run: `source /path/to/bl602_iot_sdk/venv/bin/activate`
  - Then retry `make`.

- **"Operation timed out" during flashing**:

  - Unplug and replug the device.
  - Ensure you are correctly entering Bootloader mode (Hold BOOT, press RESET, release BOOT).
  - Try a lower baud rate (e.g., `--baud-rate 115200`).

- **"Resource busy"**:

  - Another program (like `screen`) might be using the serial port. Close it or run `killall screen`.

- **Compiler errors (ABI incompatible / elf64 vs elf32)**:

  - Ensure `CONFIG_TOOLPREFIX` is set correctly to `riscv64-unknown-elf-`.
  - Ensure `project.mk` is patched to use `-march=rv32imafc` (the setup script does this automatically).

- **`blflash` build fails with `console::Term` error**:
  - The setup script installs `blflash` from the local patched version in `tools/blflash`.
  - If you need to reinstall manually, run: `cargo install --path tools/blflash/blflash`
