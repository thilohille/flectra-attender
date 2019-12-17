#include "mbedtls/aes.h"
extern "C" {
#include "crypto/base64.h"
}
#include "esp_wifi.h"
#include "util.h"

uint8_t LEDA = A12;

mbedtls_aes_context aes;
char * key = "abcdefghijklmnop";


//DH
unsigned char *xferkey;
const long a = 6;
const long q = 761;


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

  /*printf("ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
    " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
    " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",

    hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
    hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],

    hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
    hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],

    hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
    hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
  );*/
  char macchar[20]; 
  snprintf(macchar, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
    hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
    hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]
  );
  String mac = String(macchar);
  String packet;
  //String fullpacket;
  int fctl = ntohs(wh->fctl);
  for (int i = 8; i <= 8 + 6 + 1; i++) { // This reads the first couple of bytes of the packet. This is where you can read the whole packet replaceing the "8+6+1" with "p->rx_ctrl.sig_len"
    packet += String(p->payload[i], HEX);
  }
  /*String mac;
  for (int i = 4; i <= 15; i++) { // This removes the 'nibble' bits from the stat and end of the data we want. So we only get the mac address.
    mac += String(packet[i]);
  }
  */
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
  ledcAttachPin(LEDA, 1);
  ledcSetup(1, 12000, 8);
  ledcWrite(1, 255);
  /* setup wifi */
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();
  /*esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  */
  for (int i = 0; i <= 63; i++) {
    maclist[i][3] = -1000;
    sortedkeys[i] = i;
  }
  
}

int statusled = 0;
int statusledblink = 1;
unsigned long lasttimestamp = millis();
float ledbeat = 0;
float ledbeatstep = 0.0003;
double ledbeatfactor = 90;
int ledbeatlevel = 255;

size_t outputLength;
String serialdata;
//===== LOOP =====//
void loop() {
  //Serial.println("Changed channel:" + String(curChannel));
  if (curChannel > maxCh) {
    curChannel = 1;
  }

  int firstmac = sortedkeys[0];
  //listcount = 0;
  if (statusledblink == 1){
    statusled = (statusled + 1) % 2;
    ledcWrite(1, statusled * ledbeatlevel);  
  }
  if (flagsenddata){
    channelload[curChannel] = channelload[curChannel] / 2;
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
    int datasend = 0;
    for (int i = 0; i < listcount; i++) { // checks if the MAC address has been added before
      if (maclist[i][0].length() > 0) {
        Serial.println("{\"c\":" + String(i) + ",\"m\":\"" + maclist[i][0] + "\",\"r\":" + maclist[i][3] + "}");
        datasend = 1;
      }
    }
    int flickerdelay = 5;
    listcount = 0;
    lasttimestamp = vardelay(1000,lasttimestamp);
  }
  else{
      delay(50);
      listcount = 0;
  }
  curChannel++;
  if (Serial.available()) {
    String cmd = Serial.readStringUntil(0);
    String valuestr = Serial.readStringUntil(0);
    char *value = (char *) valuestr.c_str();
    value[valuestr.length()]='\0';
    /*
    String valuestr = Serial.readStringUntil(0);
    char value[256];
    if (valuestr.length()<256){
      sprintf(value,"%s",valuestr.c_str());
      value[valuestr.length()]='\0';
    }
    */
    if (cmd == "startscan") {
      esp_wifi_set_promiscuous(true);
      esp_wifi_set_promiscuous_filter(&filt);
      esp_wifi_set_promiscuous_rx_cb(&sniffer);
      esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
      flagsenddata = true;
      statusledblink = 0;
      statusled = HIGH;
      ledcWrite(1, statusled * ledbeatlevel);  
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "stopscan"){
      esp_wifi_set_promiscuous(false);
      flagsenddata = false;
      statusledblink = 1;
      statusled = LOW;
      ledcWrite(1, statusled * ledbeatlevel);  
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "ledon"){
      statusled = HIGH;
      ledcWrite(1, statusled * ledbeatlevel);  
      statusledblink = 0;
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "ledoff"){
      statusledblink = 0;
      statusled = LOW;
      ledcWrite(1, statusled * ledbeatlevel);  
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "checkin"){
      for (int c=0; c<=2; c++){
        for (int f = 0; f< 256; f+=10){
          ledcWrite(1, f);  
          delay(10);
        }
      }
      ledcWrite(1, statusled * ledbeatlevel);  
      Serial.println("ACK-" + cmd);
    }
    else if (cmd == "checkout"){
      for (int c=0; c<=2; c++){
        for (int f = 255; f> 0; f-=10){
          ledcWrite(1, f);  
          delay(10);
        }
      }
      ledcWrite(1, statusled * ledbeatlevel);  
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
      char *cipherTextOutput[(((strlen(value)/16) + 1) * 16) + 1];
      encrypt((char *)value,(char *) key,  (char *) cipherTextOutput);
      unsigned char * encoded = base64_encode((const unsigned char *) (cipherTextOutput), strlen((char*) cipherTextOutput), &outputLength);
      char encodebuffer[outputLength]; // half may be enough
      int c = 0;
      for (int i=0; i<outputLength; i++){
        //Serial.printf("%i, %i: %c, %i\n", i,c,encoded[i], (byte) encoded[i] );
        if (((byte)encoded[i] != 10) && ((byte)encoded[i] != 13)){
          encodebuffer[c] = encoded[i]; 
          c++;
        }
      }
      encodebuffer[c] = 0; 
      Serial.println(encodebuffer);
    }
    else if (cmd == "decrypt") {
      unsigned char * cipherText = base64_decode((const unsigned char*) value, strlen(value), &outputLength);
      char decipheredTextOutput[outputLength];
      decrypt((char *) cipherText, (char *) key, (char *) decipheredTextOutput);
      Serial.println((char *) decipheredTextOutput);
    }
    else if (cmd == "kxdh") {
      for (int i = 0; i < 16; ++i) {
        xferkey[i] = Diffie_Hellman_num_exchange();
      }
      // read key starts again
      char indication[MOST_NO_OF_DIGITS + 1];
      Serial.readBytes(indication, MOST_NO_OF_DIGITS);
      indication[MOST_NO_OF_DIGITS] = '\0';
      while (strcmp(indication, "2&g&xb3leL") != 0) {
        for (int i = 0; i < 16; ++i) {
          xferkey[i] = Diffie_Hellman_num_exchange();
         }
        Serial.readBytes(indication, MOST_NO_OF_DIGITS);
      }
    }
  }
}


unsigned long vardelay(int targetdelay, unsigned long delay_lasttimestamp){
  unsigned long mssincelascall =  millis() - delay_lasttimestamp;  
  while (mssincelascall < targetdelay){
    mssincelascall =  millis() - delay_lasttimestamp;
    //int actualdelay = targetdelay - mssincelascall;
    ledbeat = ledbeat + ledbeatstep;
    if (ledbeat > 180){
      ledbeat = 0;
    }
    ledbeatlevel = 255 - (statusled * (ledbeatfactor + (ledbeatfactor * sin(degrees(ledbeat)))));
    ledcWrite(1, statusled * ledbeatlevel);
    delay(10);
  }
  return millis();
}

void encrypt(char* plainText, char* key, char* outputBuffer){
  mbedtls_aes_context aes;
  mbedtls_aes_init( &aes );
  mbedtls_aes_setkey_enc( &aes, (const unsigned char*) key, strlen(key) * 8 );
  int remaining = strlen(plainText);
  int lenmod = strlen(plainText) % 16;
  for (int c = 0; c < (strlen(plainText)+lenmod);c=c+16){
    unsigned char plainTextblkbuffer[17];
    for (int b=c; b < (c + 16); b++){
      int idx = b % 16;
      if (b<strlen(plainText)){
        plainTextblkbuffer[idx] = (unsigned char)plainText[b];
        remaining = strlen(plainText) - b;
      }
      else{
          plainTextblkbuffer[idx] = '\0';
      }
      //Serial.printf("Enc: %i: %i, %i, %c,\n",c,b,idx,(char)plainTextblkbuffer[idx]);
    }
    plainTextblkbuffer[16] = '\0';
    char cypheroutputbuffer[16];
    mbedtls_aes_crypt_ecb( &aes, MBEDTLS_AES_ENCRYPT, (const unsigned char*)plainTextblkbuffer , (unsigned char*) cypheroutputbuffer);
    for (int b=c; b < (c + 16); b++){
      int idx = b % 16;
      outputBuffer[b] = (char)cypheroutputbuffer[idx];
    }
  }
  mbedtls_aes_free( &aes );
}

void decrypt(char *chipherText, char *key, char *outputBuffer){
  //Serial.println("decrypt start");
  mbedtls_aes_context aes;
  mbedtls_aes_init( &aes );
  mbedtls_aes_setkey_dec( &aes, (const unsigned char*) key, strlen(key) * 8 );
  int cipherlen = strlen(chipherText);
  unsigned char cypherTextblkbuffer[17];
  unsigned char plainoutputbuffer[17];
  int pos = 0;
  int done = 0;
  for (int c = 0; c < cipherlen;c=c+16){
    for (int b=c; b < (c + 16); b++){
      int idx = b % 16;
      if (b<cipherlen){
        cypherTextblkbuffer[idx] = chipherText[b];
        //remaining = strlen(chipherText) - b;
      }
      else{
        cypherTextblkbuffer[idx] = '\0';
      }
    }
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char*)cypherTextblkbuffer, (unsigned char*)plainoutputbuffer);
    for (int b=c; b < (c + 16); b++){
      int idx = b % 16;
      //Serial.printf("Dec: %i: %i, %i %i %c\n",c,b,idx,cipherlen,(char) plainoutputbuffer[idx]);
      outputBuffer[b] = plainoutputbuffer[idx];
      if (outputBuffer[b] == '\0'){
        done = 1;
        break;
      }
    }
    if (done == 1){
      break;
    }
  }
  //Serial.println("decrypt done");
  mbedtls_aes_free( &aes );
}


unsigned char Diffie_Hellman_num_exchange(){

  long X, Y, Y_other, K, temp;
  char Y_other_str[MOST_NO_OF_DIGITS + 1], incByte;
  
  X = random(2, q-1);
  
  Y = raiseto_mod(a, X, q);
  
  Serial.readBytes(Y_other_str, MOST_NO_OF_DIGITS);
  Serial.println(to_string(Y));
  
  Y_other_str[MOST_NO_OF_DIGITS] = '\0';

  Y_other = to_num(Y_other_str);
  
  K = raiseto_mod(Y_other, X, q);
  int diffie_hellman_num = K % 256;
  return (unsigned char) diffie_hellman_num;
}


