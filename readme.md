# ESP32 Nightshade v4.2

A portable Wi-Fi testing tool built on the ESP32 with a 1.8" ST7735 TFT display, analog joystick, and full web control interface.

**Important:** This tool is intentionally restricted so that attacks only work on the network named **F307**. It is designed for testing your own network only.  

**Do not use this Project for any illegal purpose.**

### **🚫Do not be a [_skid_](https://www.google.com/search?q=skid+meaning+in+programming+slang).**

---

## Features

### Core Capabilities
- **Network Scanner** – Scans nearby 2.4 GHz Wi-Fi networks and displays SSID, channel, RSSI, and BSSID
- **Client Sniffer** – Passively discovers devices connected to the target network using promiscuous mode
- **Multiple Attack Modes**:
  - **Deauth** – Sends deauthentication + disassociation frames
  - **CSA** – Channel Switch Announcement frames
  - **Beacon Spam** – Fake beacon frames
  - **Chaos** – Combination of the above modes
- **Safety Lock** – Attacks only activate if the selected network is `F307`
- **Dual Control**:
  - On-device TFT + Joystick interface
  - Full web control panel via SoftAP

### Web Interface
- SoftAP Name: `RG's ESP32`
- Password: `rgisking`
- Access URL: `http://192.168.4.1`
- Modern dark-themed, minimal UI
- Real-time status (clients + packet count)
- Same attack controls as the physical interface

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

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200

lib_deps =
    adafruit/Adafruit GFX Library
    adafruit/Adafruit ST7735 and ST7789 Library
    me-no-dev/ESP Async WebServer
    me-no-dev/AsyncTCP

build_flags =
-Wl,--wrap=ieee80211_raw_frame_sanity_check
-D CORE_DEBUG_LEVEL=0 
```


### Key Technical Details
- Uses `WIFI_IF_AP` for more reliable raw frame injection
- 28-byte deauthentication frames (includes Duration field)
- Channel is set immediately before every attack burst
- FreeRTOS task handles the attack loop for better performance
- Promiscuous mode sniffer for client discovery
- SoftAP is started both for the web UI and to properly initialize the AP interface

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
6. Attack options only work when **F307** is selected

### Web Interface
1. Connect your phone or laptop to the Wi-Fi network **`RG's ESP32`**
2. Enter password: **`rgisking`**
3. Open a browser and go to **`http://192.168.4.1`**
4. Use the control panel to start/stop attacks and view live status

---

## Attack Modes Explained

| Mode          | Description                                      |
|---------------|--------------------------------------------------|
| Sniff         | Passively listens for clients on F307            |
| Deauth        | Sends deauth + disassoc frames (broadcast or targeted) |
| CSA           | Sends Channel Switch Announcement frames         |
| Beacon Spam   | Injects fake beacon frames                       |
| Chaos         | Runs Deauth + CSA + Beacon together              |

---

## Safety & Legal Notice

- This tool is **hard-locked** to only attack the network named `F307`.
- It is intended solely for testing and learning on networks you own or have explicit permission to test.
- Unauthorized use of deauthentication or related techniques against networks you do not own is illegal in most countries.
- The author assumes no responsibility for misuse.

---

## Version History

- **v4.2** – Added full web control interface (`RG's ESP32` / `rgisking`)
- **v4.1** – Improved deauth reliability (`WIFI_IF_AP` + 28-byte frames)
- **v4.0** – Major rewrite with client sniffing, multiple attack modes, and FreeRTOS task
- Earlier versions – Basic deauth + TFT UI development

---

## Credits & Inspiration

- Inspired by projects such as ESP32 Marauder, Bruce Firmware, and nyanBOX
- Built iteratively with focus on stability, usability, and safety restrictions

---

**ESP32 Nightshade** – A personal Wi-Fi testing companion.

**Do not use this Project for any illegal purpose.**

# **🚫Do not be a [_skid_](https://www.google.com/search?q=skid+meaning+in+programming+slang).**
