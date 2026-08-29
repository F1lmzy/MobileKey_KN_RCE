# SALTO XS4 One (E1722) — ESP32 BLE credential emulator

Re-implements the phone side of the Salto **JustIN Mobile BLE v0200** protocol
(`com.trevo.nus` / SaltOS Justin SDK) on ESP32 with NimBLE-Arduino.

## Reverse-engineering source (from jadx decompile)

| Class | Role |
|---|---|
| `obscured/SecureProtocolManager.java` (n2) | SSP 3-pass auth (MIFARE-style, AES-128-CBC) |
| `obscured/JustinProtocolManager.java` (q1) | JustIN commands: Open/Close/ReadTag/WriteTag |
| `obscured/MasterDeviceManagerVersion0200.java` (e2) | BLE v0200 orchestrator |
| `obscured/JustinStack0100.java` (r1) | = SecureProtocolManager wrapping JustinProtocolManager |
| `obscured/SaltoEncryptor.java` (m2) | AES/CBC/NoPadding + 0x80 padding |
| `obscured/MasterDeviceManager.java` (z1) | writes `C0 01 01`, reads 64-byte blob, version select |

## Protocol (v0200)

```
ESP32 (phone role)                      Lock (reader role)
   |--- GATT connect, MTU 517 ------------->|
   |--- write C0 01 01 (SBAPS select) ----->|
   |--- read B6E60002 -> 64B blob --------->|
   |--- enable notify on B6E60002 -------->|
   |<--- notify: 01 01 (open session) ------|
   |--- write: 03 || AES(KN, 0^16, {01,B16,crc}) --->|   B = random
   |<--- notify: 03 || AES(KN, {02,A16,rotR(B),crc}) --|
   | verify rotR(B), derive session key     |
   |--- write: 03 || AES(KN, {02,rotR(A),crc}) ------>|
   sessKey = A[0:4] B[0:4] A[12:16] B[12:16]
   |<--- notify: 02 || AES(sessKey, {cmd,...}) -------|
   |--- write: 02 || AES(sessKey, {reply,crc}) ------>|
```

- Header bits: bit1 = encrypted, bit0 = control packet. `0x03`=encrypted control,
  `0x02`=encrypted data.
- IV is a **single shared running IV** across both directions, updated to the last
  ciphertext block after every encrypt/decrypt. (Crypto weakness of the vendor —
  we just replicate it.)
- Padding: ISO-7816-4 style (`0x80` + zeros), AES-128-CBC NoPadding.
- CRC: MIFARE CRC_A (init 0x6363, nibble-wise poly 0x1021, little-endian 2 bytes),
  appended *inside* the plaintext before padding.

## Build

- PlatformIO (recommended): board `esp32dev` (or `esp32-s3-devkitc-1`),
  lib_deps = `h2zero/NimBLE-Arduino@^2.2.3`, framework arduino.
- Plain Arduino IDE: install esp32 core + NimBLE-Arduino library, open
  `salto_esp32.ino`.

## Config

In `salto_esp32.ino`:

```c
static const char* LOCK_MAC = "84:fd:27:2f:18:60"; // door's BLE MAC
static const char* KN_HEX   = "00112233445566778899aabbccddeeff"; // your KN
```

## Known gaps (fill from a real captured session)

The lock issues JustIN commands after the session opens; the phone answers from
its digital-key TLV. For a plain Open/Close the status responses are enough,
but the lock may issue:

- `READ TAG` (cmd 2) with a tag id → expects that tag's value from your key blob
- `WRITE TAG` (cmd 3) → expects ack + stores opresult (this is where the final
  ACCEPT/REJECT comes back)

To fill `justinHandle()` exactly: do one unlock with the **dumper-patched app**
and read the `salto_AES-*` dumps — the `pt=` lines contain every plaintext
command/response pair byte-for-byte. Map each `cmd`+payload to its reply and
hardcode them here (they are static per key).

## Serial output

The sketch logs every packet both directions (hex) with `[SSP]`/`[JUSTIN]`
annotations. Expected login sequence:

```
<= lock: 0101
[SSP] control op 1
=> lock: 03<32 hex>
<= lock: 03<48 hex>
[SSP] step2 ... session key: <hex>
=> lock: 03<32 hex>
[SSP] session established
<= lock: 02<ciphertext>   (JustIN command)
...
```

Serial needs ~115200, and the door must be within ~10 m.