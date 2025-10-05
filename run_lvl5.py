#!/usr/bin/env python3
import os, sys, hashlib, base58
from urllib.request import urlretrieve

IMG_URL = "https://crypto.haluska.sk/crypto5fix.png"
IMG_PATH = "crypto5fix.png"

try:
    import cv2, numpy as np
    from ecdsa import SigningKey, SECP256k1
except Exception:
    print("Installing missing dependencies...")
    os.system("pip install opencv-python-headless numpy ecdsa base58 pillow")
    import cv2, numpy as np
    from ecdsa import SigningKey, SECP256k1

def download():
    if not os.path.exists(IMG_PATH):
        print("Downloading image...")
        urlretrieve(IMG_URL, IMG_PATH)
    else:
        print("Image already present:", IMG_PATH)

def wif_from_privkey(hex_privkey, compressed=True):
    priv = bytes.fromhex(hex_privkey)
    prefix = b'\x80' + priv
    if compressed:
        prefix += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58.b58encode(prefix + checksum).decode()

def pubkey_from_priv(hex_privkey, compressed=True):
    sk = SigningKey.from_string(bytes.fromhex(hex_privkey), curve=SECP256k1)
    vk = sk.get_verifying_key()
    px = vk.to_string()
    parity = px[-1] & 1
    return (b'\x02' if parity == 0 else b'\x03') + px[:32]

def address_from_pub(pubkey_bytes):
    rip = hashlib.new('ripemd160', hashlib.sha256(pubkey_bytes).digest()).digest()
    pref = b'\x00' + rip
    checksum = hashlib.sha256(hashlib.sha256(pref).digest()).digest()[:4]
    return base58.b58encode(pref + checksum).decode()

def detect_rectangles(path):
    img = cv2.imread(path)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (3,3), 0)
    _, th = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    if cv2.countNonZero(th) < th.size // 2:
        th = cv2.bitwise_not(th)
    contours, _ = cv2.findContours(th, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    rects = []
    for cnt in contours:
        approx = cv2.approxPolyDP(cnt, 0.01*cv2.arcLength(cnt, True), True)
        if len(approx) == 4 and cv2.isContourConvex(approx):
            x,y,w,h = cv2.boundingRect(approx)
            rects.append((x,y,w,h,w*h))
    seen=set(); unique=[]
    for x,y,w,h,a in rects:
        key=(round(x/2),round(y/2),round(w/2),round(h/2))
        if key not in seen:
            seen.add(key); unique.append((x,y,w,h,a))
    unique.sort(key=lambda r: r[4], reverse=True)
    return unique, th, img

def try_basic_transforms(shell_areas):
    sums = [shell_areas[i]+(shell_areas[i+1] if i+1<len(shell_areas) else 0) for i in range(len(shell_areas))]
    transforms = []
    b = [s & 0xFF for s in sums[:32]]
    transforms.append(("mod256", b))
    for k in range(1,9):
        transforms.append((f"shr{k}", [ (s>>k)&0xFF for s in sums[:32] ]))
    for d in [2,3,4,5,7,11,13,17]:
        transforms.append((f"div{d}", [ (s//d)&0xFF for s in sums[:32] ]))
    for k in [0x00,0xFF,0xAA,0x55,0x77]:
        transforms.append((f"xor{hex(k)}", [ (s^k)&0xFF for s in sums[:32] ]))
    return transforms

def main():
    download()
    rects, th, img = detect_rectangles(IMG_PATH)
    print("Detected rectangles:", len(rects))
    areas = [r[4] for r in rects]
    if len(areas) >= 64:
        areas = areas[:64]
    shell=[]
    for i in range(len(areas)-1):
        shell.append(max(0, areas[i] - areas[i+1]))
    if len(shell) < 32:
        shell = areas[:]
    print("Using shell length:", len(shell))
    transforms = try_basic_transforms(shell)
    target_prefix = "1cryptoGeCRi"
    found = []
    for name, bytes_list in transforms:
        if len(bytes_list) < 32: continue
        priv_hex = ''.join(f"{b:02x}" for b in bytes_list[:32])
        wif = wif_from_privkey(priv_hex)
        pub = pubkey_from_priv(priv_hex)
        addr = address_from_pub(pub)
        print(f"TRY {name} -> {addr}  hex-start={priv_hex[:16]}...")
        if addr.startswith(target_prefix) or addr == "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7":
            found.append((name, priv_hex, wif, addr))
    if found:
        print("Found matches:")
        for f in found: print(f)
    else:
        print("No matches. Saving debug images...")
        cv2.imwrite("thresh_debug.png", th)
        cv2.imwrite("detected_debug.png", img)
        print("Saved thresh_debug.png and detected_debug.png")

if __name__ == "__main__":
    main()
