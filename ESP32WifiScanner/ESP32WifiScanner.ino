#include "Cipher.h"
#include <base64.h>
extern "C" {
#include "crypto/base64.h"
}
#include "esp_wifi.h"

#define AES_KEY "dontforgettochangethekey"

Cipher * cipher = new Cipher();
base64 b;

int LEDPIN = LED_BUILTIN;

int channelload [15];
int sortedkeys [64];
String maclist[64][4];
int listcount = 0;

bool flagsenddata = false;
String defaultTTL = "60"; // Maximum time (Apx seconds) elapsed before device is consirded offline

const wifi_promiscuous_filter_t filt = { //Idk what this does
  .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
};

typedef struct { // or this
  uint8_t mac[6];
} __attribute__((packed)) MacAddr;

typedef struct { // still dont know much about this
  int16_t fctl;
  int16_t duration;
  MacAddr da;
  MacAddr sa;
  MacAddr bssid;
  int16_t seqctl;
  unsigned char payload[];
} __attribute__((packed)) WifiMgmtHdr;



#define maxCh 13 //max Channel -> US = 11, EU = 13, Japan = 14


int curChannel = 1;

typedef struct {
  unsigned frame_ctrl: 16;
  unsigned duration_id: 16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl: 16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;


void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) { //This is where packets end up after they get sniffed
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf; // Dont know what these 3 lines do
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)p->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  int len = p->rx_ctrl.sig_len;
  WifiMgmtHdr *wh = (WifiMgmtHdr*)p->payload;
  len -= sizeof(WifiMgmtHdr);

  String packet;
  //String fullpacket;
  String mac;
  int fctl = ntohs(wh->fctl);
  for (int i = 8; i <= 8 + 6 + 1; i++) { // This reads the first couple of bytes of the packet. This is where you can read the whole packet replaceing the "8+6+1" with "p->rx_ctrl.sig_len"
    packet += String(p->payload[i], HEX);
  }
  for (int i = 4; i <= 15; i++) { // This removes the 'nibble' bits from the stat and end of the data we want. So we only get the mac address.
    mac += String(packet[i]);
  }
  channelload[p->rx_ctrl.channel - 1] += 1;
  signed int rssi = p->rx_ctrl.rssi;
  //Serial.println(fullpacket);
  mac.toUpperCase();

  int newmac = 1;
  for (int i = 0; i < listcount; i++) { // checks if the MAC address has been added before
    if (mac == maclist[i][0]) {
      maclist[i][1] = defaultTTL;
      maclist[i][3] = rssi;
      if (maclist[i][2] == "OFFLINE") {
        maclist[i][2] = "0";
      }
      newmac = 0;
    }
  }

  if (newmac == 1) { // If its new. add it to the array.
    maclist[listcount][0] = mac;
    maclist[listcount][3] = rssi;
    maclist[listcount][1] = defaultTTL;
    listcount ++;
    if (listcount >= 64) {
      Serial.println("Too many addresses");
      listcount = 0;
    }
  }
}



//===== SETUP =====//
void setup() {
  for (int i = 0; i < maxCh; i++) {
    channelload[i] = 0;
  }
  /* start Serial */
  Serial.begin(115200);
  pinMode (LEDPIN, OUTPUT);
  /* setup wifi */
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

  for (int i = 0; i <= 63; i++) {
    maclist[i][3] = -1000;
    sortedkeys[i] = i;
  }

  char * key = AES_KEY;
  cipher->setKey(key);

}

int statusled = 0;
int statusledblink = 1;
unsigned long lasttimestamp = millis();

size_t outputLength;
String serialdata;
//===== LOOP =====//
void loop() {
  //Serial.println("Changed channel:" + String(curChannel));
  if (curChannel > maxCh) {
    curChannel = 1;
  }
  channelload[curChannel] = channelload[curChannel] / 2;
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  int firstmac = sortedkeys[0];
  //listcount = 0;
  if (statusledblink == 1){
    statusled = (statusled + 1) % 2;
    digitalWrite(LEDPIN,statusled);
  }
  if (flagsenddata){
    int datasend = 0;
    for (int i = 0; i < listcount; i++) { // checks if the MAC address has been added before
      if (maclist[i][0].length() > 0) {
        Serial.println("{\"c\":" + String(i) + ",\"m\":\"" + maclist[i][0] + "\",\"r\":" + maclist[i][3] + "}");
        datasend = 1;
      }
    }
    int flickerdelay = 100 + (listcount * 5);
    listcount = 0;
    if (datasend == 1){
      digitalWrite(LEDPIN,LOW);
      delay(flickerdelay);
      digitalWrite(LEDPIN,HIGH);
      delay(flickerdelay);
      digitalWrite(LEDPIN,statusled);
    }
    lasttimestamp = vardelay(1000,lasttimestamp);
  }
  else{
      delay(100);
      listcount = 0;
  }
  curChannel++;
  if (Serial.available()) {
    String cmd = Serial.readStringUntil(0);
    String value = Serial.readStringUntil(0);
    if (cmd == "startscan") {
      flagsenddata = true;
      statusledblink = 0;
      statusled = HIGH;
      digitalWrite(LEDPIN,statusled);
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "stopscan"){
      flagsenddata = false;
      statusledblink = 1;
      statusled = LOW;
      digitalWrite(LEDPIN,statusled);
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "ledon"){
      statusled = HIGH;
      digitalWrite(LEDPIN,statusled);
      statusledblink = 0;
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "ledoff"){
      statusledblink = 0;
      statusled = LOW;
      digitalWrite(LEDPIN,statusled);
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "checkin"){
      digitalWrite(LEDPIN,LOW);
      delay(100);
      digitalWrite(LEDPIN,HIGH);
      delay(100);
      digitalWrite(LEDPIN,LOW);
      delay(100);
      digitalWrite(LEDPIN,HIGH);
      delay(100);
      digitalWrite(LEDPIN,statusled);
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "checkout"){
      digitalWrite(LEDPIN,LOW);
      delay(200);
      digitalWrite(LEDPIN,HIGH);
      delay(200);
      digitalWrite(LEDPIN,statusled);
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "ledblinkon"){
      statusledblink = 1;
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "ledblinkoff"){
      statusledblink = 0;
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "encrypt") {
      String encrypted = b.encode(cipher->encryptString(value));
      Serial.println(encrypted);
    }
    else if (cmd == "decrypt") {
      int bufferlen = value.length();
      char decodebuffer[bufferlen]; // half may be enough
      sprintf(decodebuffer, "%s", value.c_str());
      unsigned char * decoded = base64_decode((const unsigned char *) decodebuffer, bufferlen, &outputLength);
      sprintf(decodebuffer, "%s", decoded);
      String decrypted = cipher->decryptString(decodebuffer);
      Serial.println(decrypted);
      decrypted = "";
      bufferlen = 0;
      free(decoded);
      //this free causes heap corruption, maybe due to the use base64 and crypto/base64.h?
      //free(decodebuffer);
    }
  }
}

unsigned long vardelay(int targetdelay, unsigned long delay_lasttimestamp){
  unsigned long mssincelascall =  millis() - delay_lasttimestamp;  
  if (mssincelascall < targetdelay){
    int actualdelay = targetdelay - mssincelascall;
    delay(actualdelay);
  }
  return millis();
}

