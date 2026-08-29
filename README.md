# NUS Mobile Key — ESP32 door opener (Salto XS4 / JustIN BLE v0200)

Reverse engineering of the **NUS Mobile Key** Android app (`com.trevo.nus`, built on the
**SaltOS JustIN Mobile SDK** at Salto XS4 One / E1722 locks) and a working ESP32 firmware
that emulates the phone over BLE.

> **Credential note:** the firmware in this repo has `KN` and the tag-1 blob replaced with
> zeros. You must inject **your own** credential, extracted from a phone enrolled with
> the lock you own/lan authorized on. Re-capture after every key rotation.

## What's in here

| Path | Contents |
|---|---|
| `firmware/` | ESP32 (Arduino + NimBLE-Arduino 2.5) central that replays the full protocol |
| `apk/` | Instrumented re-signed copy of the vendor apk (dumps key material to logcat + files at runtime) |
| `analysis/` | `parse_dump.py` (session decoder/verifier), Frida-style hook script |

## The protocol (Salto JustIN Mobile, BLE v0200 "SSP")

GATT:
- Service `B6E60001-E2E3-BC82-4C72-929D0D29CA17`
- Write char (h=0x000e) `B6E60003-…`, read/notify char (h=0x000b) `B6E60002-…`, CCCD h=0x000c
- MTU exchange: client asks 250, phone answers 517 (negotiated 250 is fine)

Session flow (byte-verified against live captures + app logcat):

```
phone: write C0 01 01                        (SBAPS select)
phone: read blob  -> 01 00 02                (protocol info)
phone: write CCCD (enable notifications)
lock --> 00 02 03   (ReadTag tag 3)   -> phone 00 02 (NOT_FOUND)
lock --> 00 02 01   (ReadTag tag 1)   -> phone 00 00 | tag1 (KEY_BINARY blob)
lock --> 01 01 00   (SSP open session) -> phone: 03 | AES-CBC(KN, 0^16, {01,B16,CRC})
lock --> 03 | AES(KN,{02,A16,rotR(B),CRC}) -> phone verifies rotR(B),
       -> 03 | AES(KN,{02,rotR(A),CRC});  sessionKey = A[0:4]B[0:4]A[12:16]B[12:16]
lock --> 02 | AES(sk,{02,tag,crc})  ReadTag(0x10 ...)   -> {02} NOT_FOUND
lock --> 02 | AES(sk,{03,0b,…})     WriteTag(0x0b, result) -> {00} SUCCESS
[door opens; result byte 02 = accepted, 01 = rejected]
```

Crypto:
- AES-128-CBC **NoPadding**, ISO-7816 padding (`0x80` + zeros)
- Single running IV for BOTH directions: after every op, `IV := last ciphertext block`
- `CRC_A` = MIFARE CRC (init 0x6363, nibble-wise poly 0x1021, little-endian 2 bytes), inside the plaintext
- Structure mirrors MIFARE Classic 3-pass auth with AES swapped in for Crypto-1
- SSP header semantics: bit1 = encrypted payload, bit0 = control packet; the header byte is
  OUTSIDE the ciphertext (a common mistake when replicating — the app's internal buffer adds
  it back, but the wire frames do not)

Digital key (`DigitalKeyBase`, BER-TLV):
- tag 0 = protocol version (`0100`), tag 1 = KEY_BINARY (per-key, variable length — 64 B or 80 B
  observed across issuances), tag 2 = **KN** (the 16-byte AES key), tags 10/16 empty
- KN never travels; it's derived from the cloud-issued key blob

## Getting your own credential (no root, needs adb + your logged-in phone)

1. Repack the vendor apk with our patches (PairIP license check stubbed, `NoopLogger` →
   logcat, `KD` dumper prints key at `DigitalKeyBase.<init>`, `q1` KN getter, and every
   `SaltoEncryptor` AES op; plus a background-loaded Frida gadget if you prefer hooks).
2. Install, log in (email link needs an `am start -d` push on re-signed builds — app links
   break), do ONE unlock at a door while capturing:
   - `adb logcat -s SALTO` → the `Sending <hex>` line is tag-1; `KN: <hex>` is the key
   - or the dumper's `salto_*.txt` files on-device
3. Write the two values into `firmware/src/main.cpp` (`KN_HEX`, `NEG_TAG1[80]`).

## History / gotchas (cost us hours)

- Frida gadget hangs the app on this HyperOS build (white screen + ANR) → dropped it
- Scan-then-connect vs direct paging: on this ESP32/NimBLE combo, scanning appeared to wedge
  the controller (silent 8ms connect rejects); behavior was erratic → the firmware reconnect
  strategy is a "shotgun" burst with reboot fallback (the lock only accepts connections in a
  short window; a rejected attempt costs ~10 ms)
- mbedTLS needs `setkey_dec` for AES-CBC decrypt (esp32 hw AES path is lenient, sw is not)
- SSP step2 content is 33 bytes (`02+A16+rotR(B)16`) — an off-by-one (34) silently failed it

## Run

```
cd firmware && pio run -t upload          # ESP32 with CP2102 on /dev/ttyUSB0
pio device monitor -b 115200
```

Watch for `[CONN] ok after …`, `session established`, then the door's WriteTag result.