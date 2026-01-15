# BLE Central & Peripheral Demo for BL602

This is a dual-role BLE application for the BL602 chip. It can operate as either a **Peripheral (Sender)** or a **Central (Receiver)**, selectable via onboard buttons.

## Features

- **Dual Mode**: Switch between Central and Peripheral roles at runtime.
- **Peripheral Mode**:
  - Advertises as "BL602_Sender".
  - Sends "MockData" notifications every 2 seconds.
  - Custom Service UUID: `0xFFF0`.
- **Central Mode**:
  - Scans and connects to the "BL602_Sender".
  - Subscribes to notifications.
  - Can send data back to the peripheral.
- **LED Status**:
  - **Blue**: Advertising or Scanning.
  - **Green**: Connected.
  - **Red**: Disconnected.

## Directory Structure

- `suas_app_ble_sender/`: Source code.
  - `main.cpp`: Main loop and button handling.
  - `peripheral.cpp`: Peripheral role implementation (GATT Server).
  - `central.cpp`: Central role implementation (GATT Client).

## Usage & Controls

The application uses the onboard button (GPIO 2 usually, depends on board) to switch modes:

| Action | Duration | Result |
|--------|----------|--------|
| **Short Press** | 100ms - 3s | **Start as Peripheral** (Sender) |
| **Long Press** | 6s - 10s | **Start as Central** (Receiver) |
| **Very Long Press** | > 15s | **Trigger Action** (Send Notification or Write Data) |

### Default Behavior
On startup, the application defaults to **Peripheral** mode.

## Getting Started

1. **Build and Flash**:
   ```bash
   cd customer_app/suas_app_ble_sender
   make clean && make
   make flash
   ```

2. **Testing Peripheral Mode**:
   - Power on. Blue LED should be on (Advertising).
   - Use a BLE scanner app (nRF Connect) to find "BL602_Sender".
   - Connect and subscribe to the characteristic `0xFFF1`.
   - You should see "This is a MockData line X" notifications.

3. **Testing Central Mode** (Requires 2 BL602 boards):
   - **Board A**: Leave in default Peripheral mode.
   - **Board B**: Long press the button until it switches to Central mode.
   - Board B should scan, find Board A, and connect (Green LED on both).
   - Board B will print received notifications to UART.

## Credits
- Group 05
