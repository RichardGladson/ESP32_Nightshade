# ESP32 Nightshade

A portable Wi-Fi testing tool built on the ESP32 with a 1.8" ST7735 TFT display, analog joystick, and full web control interface.

**Before proceeding further, please read [`DISCLAIMER.md`](DISCLAIMER.md).**

---

## Features

### Core Capabilities
- **Network Scanner** – Scans nearby 2.4 GHz Wi-Fi networks and displays SSID, channel, RSSI, BSSID, and encryption type
- **Client Sniffer** – Passively discovers devices connected to the target network using promiscuous mode
- **Multiple Attack Modes**:
  - **Deauth** – Sends deauthentication + disassociation frames
  - **CSA** – Channel Switch Announcement frames
  - **Beacon Spam** – Fake beacon frames
  - **Chaos** – Combination of the above modes
- **Target Lock** – Attacks only activate if the selected network matches the configured target SSID
- **Dual Control**:
  - On-device TFT + Joystick interface
  - Full web control panel via SoftAP

### Web Interface
- SoftAP Name: `RG's ESP32`
- Password: `rgisking`
- Access URL: `http://192.168.4.1`
- Modern dark-themed UI
- Real-time status (clients, packet count, temperature)
- Network list with RSSI and encryption
- Detailed view of the selected network
- Active mode buttons highlight in green

---

## Hardware Required

| Component              | Details                          |
|------------------------|----------------------------------|
| Microcontroller        | ESP32 (WROOM / DevKit)           |
| Display                | 1.8" ST7735 TFT (160×128)        |
| Joystick               | HW-504 (or compatible analog)    |
| Power                  | USB or powerbank                 |

### Pinout

| Component   | ESP32 Pin |
|-------------|-----------|
| TFT CS      | GPIO 5    |
| TFT RST     | GPIO 17   |
| TFT DC      | GPIO 16   |
| Joystick VRX| GPIO 34   |
| Joystick VRY| GPIO 35   |
| Joystick SW | GPIO 32   |

*(SPI pins SCK/MOSI use default ESP32 SPI pins)*

---

## Software Setup

### PlatformIO (`platformio.ini`)

~~~~ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200

lib_deps =
    adafruit/Adafruit GFX Library
    adafruit/Adafruit ST7735 and ST7789 Library
    esp32async/ESPAsyncWebServer
    esp32async/AsyncTCP

build_flags = 
    -Wl,--wrap=ieee80211_raw_frame_sanity_check
    -D CORE_DEBUG_LEVEL=0
~~~~

### Key Technical Details
- Uses `WIFI_IF_AP` for raw frame injection
- 28-byte deauthentication frames (includes Duration field)
- Channel is set immediately before every attack burst
- FreeRTOS task handles the attack loop
- Promiscuous mode sniffer for client discovery
- SoftAP is used for both the web UI and proper AP interface initialization

---

## How to Use

### Physical Interface (TFT + Joystick)
1. Power on the device
2. Wait for the network scan to finish
3. Scroll through networks using the joystick
4. Press the joystick to select a network
5. Navigate the options:
   - **SNIFF** – Start client discovery
   - **DEAUTH** – Deauthentication attack
   - **CSA** – Channel Switch Announcement
   - **BEACON SPAM** – Fake beacons
   - **CHAOS** – Combined attack
   - **CLIENTS** – View discovered clients
   - **BACK** – Return to network list

### Web Interface
1. Connect your phone or laptop to the Wi-Fi network **`RG's ESP32`**
2. Enter password: **`rgisking`**
3. Open a browser and go to **`http://192.168.4.1`**
4. Use the control panel to start/stop attacks and view live status

---

## Attack Modes

| Mode          | Description                                      |
|---------------|--------------------------------------------------|
| Sniff         | Passively listens for clients on the target      |
| Deauth        | Sends deauth + disassoc frames                   |
| CSA           | Sends Channel Switch Announcement frames         |
| Beacon Spam   | Injects fake beacon frames                       |
| Chaos         | Runs Deauth + CSA + Beacon together              |

---

## Version History

- **v4.3** – Enhanced web UI (network details, RSSI, encryption, active button highlighting, temperature)
- **v4.2** – Added full web control interface
- **v4.1** – Improved deauth reliability (`WIFI_IF_AP` + 28-byte frames)
- **v4.0** – Major rewrite with client sniffing, multiple attack modes, and FreeRTOS task

---

## Credits

Inspired by projects such as ESP32 Marauder, Bruce Firmware, and nyanBOX.