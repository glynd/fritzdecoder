#!/usr/bin/env python3
"""
Decrypt the "$$$$..." secrets in a FRITZ!Box settings export (.export) file.

Usage:  python3 fritz_decode.py backup.export "export-password" [-a]

Prints the readable lines that contained secrets (SIP/phone/Wi-Fi etc.).
Use -a to write the whole file with every secret decrypted instead.
Needs:  pip install cryptography
Runs entirely locally; nothing is sent anywhere.
"""
import re, sys, hashlib, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"   # AVM's base32 digits (1-6, not 2-7)

def b32(s):
    std = s.translate(str.maketrans(ALPHA, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"))
    std += "=" * (-len(std) % 8)
    return base64.b32decode(std)

def decrypt(token, key16):
    raw = b32(token)
    iv, ct = raw[:16], raw[16:]
    ct = ct[: len(ct) // 16 * 16]            # drop the stray trailing byte
    key = key16.ljust(32, b"\0")             # 16-byte key zero-padded for AES-256
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    dec = d.update(ct) + d.finalize()
    if hashlib.md5(dec[4:]).digest()[:4] != dec[:4]:
        raise ValueError("check value mismatch (wrong password?)")
    size = int.from_bytes(dec[4:8], "big")
    val = dec[8:8 + size]
    return val[:-1] if val.endswith(b"\0") else val

def main():
    args = [a for a in sys.argv[1:] if a != "-a"]
    whole = "-a" in sys.argv
    if len(args) != 2:
        sys.exit(__doc__)
    text = open(args[0], "rb").read().decode("latin-1")
    pw = args[1].encode()

    m = re.search(r"^[ \t]*Password=\$\$\$\$([A-Z1-6]+)", text, re.M)
    if not m:
        sys.exit("No 'Password=$$$$...' header found - is this a FRITZ!Box export?")
    try:
        first = decrypt(m.group(1), hashlib.md5(pw).digest())
    except ValueError:
        sys.exit("Could not decrypt the header: wrong export password.")
    key = first[:16]                          # random key used for all values

    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("Password=$$$$"):
            if whole:
                out.append(line)
            continue
        def sub(mo):
            try:
                return decrypt(mo.group(1), key).decode("utf-8", "replace")
            except Exception:
                return mo.group(0)
        new = re.sub(r"\$\$\$\$([A-Z1-6]+)", sub, line)
        if whole or new != line:
            out.append(new)
    print("\n".join(out))

main()
