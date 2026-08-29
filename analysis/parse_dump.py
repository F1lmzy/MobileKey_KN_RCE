#!/usr/bin/env python3
"""Parse salto_dump.txt -> reconstruct each SSP session step by step."""
import re, sys

raw = open(sys.argv[1] if len(sys.argv) > 1 else "salto_dump.txt").read()
blocks = re.findall(r"==== (.*?) ====\n([0-9a-fA-F]+)", raw)

def parse(hexstr):
    return bytes.fromhex(hexstr)

def crcA(data):
    crc = 0x6363
    for b in data:
        crc = (crc >> 4) ^ (((crc ^ b) & 0x0F) * 0x1081)
        crc = (crc >> 4) ^ ((((b >> 4) ^ crc) & 0x0F) * 0x1081)
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])

def rot(buf):
    return bytes([buf[0]] + list(buf[1:]))  # placeholder

def strip_pad(pt):
    # remove trailing 0x00 and single 0x80
    n = len(pt)
    while n > 0 and pt[n-1] == 0x00: n -= 1
    if n > 0 and pt[n-1] == 0x80: n -= 1
    return pt[:n]

def show(label, pt):
    body = strip_pad(pt)
    if len(body) >= 2:
        cnt = body[:-2]; crc = body[-2:]
        ok = "crc-ok" if crc == crcA(cnt) else "crc-BAD(%s)" % crc.hex()
    else:
        cnt = body; ok = "?"
    print(f"  {label}: pt={pt.hex()}")
    print(f"      content={cnt.hex()} [{ok}]")

i = 0
sess = 0
while i < len(blocks):
    tag, hx = blocks[i]
    if tag == "KEYBLOB":
        sess += 1
        print(f"\n========== SESSION {sess} ==========")
        print(f"  KEYBLOB({len(hx)//2}B)")
        i += 1
        # KN follows
        t2, hx2 = blocks[i]
        assert t2 == "KN", t2
        i += 1
        print(f"  KN = {hx2}")
        kn = bytes.fromhex(hx2)
        continue
    t, hx = tag, hx
    val = parse(hx)
    if t == "AES-ENC key" or t == "AES-DEC key":
        print(f"  key: {hx}")
    elif t == "AES-ENC iv" or t == "AES-DEC iv":
        pass
    elif t == "AES-ENC pt":
        show("ENC(phone->lock) pt", val)
    elif t == "AES-ENC ct":
        print(f"  ENC ct: {hx}")
    elif t == "AES-DEC pt":
        show("DEC(lock->phone) pt", val)
    elif t == "AES-DEC ct":
        pass
    i += 1