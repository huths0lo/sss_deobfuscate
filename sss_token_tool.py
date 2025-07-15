#!/usr/bin/env python3
"""
Encrypt / Decrypt sssd.conf‑style obfuscated passwords.

Usage examples
--------------

Encrypt a clear‑text password:

    ./sss_crypto.py encrypt

Decrypt an existing token:

    ./sss_crypto.py decrypt

The output of “encrypt” can be fed straight back into “decrypt”.
"""

import base64
import getpass
import os
import struct
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ──────────────────────────────────────────────────────────────────────────────
# Supported crypto mechanisms (only one at the moment)
crypto_mech_data = [
    {   # Method 0 – AES‑256‑CBC
        "algo": algorithms.AES,
        "mode": modes.CBC,
        "keylen": 32,   # 256‑bit key
        "bsize": 16,    # AES block size
    }
]

# ──────────────────────────────────────────────────────────────────────────────
def decrypt_token(token_b64: str) -> str:
    """Return the clear‑text password hidden in an sssd ‘obfuscated_password’."""
    tok_bin = base64.b64decode(token_b64)

    # Header: uint16 method, uint16 ciphertext_len
    method, ct_size = struct.unpack("HH", tok_bin[0:4])
    try:
        mech = crypto_mech_data[method]
    except (IndexError, KeyError):
        raise ValueError(f"Unknown encryption method: {method}")

    p = 4
    key = tok_bin[p : p + mech["keylen"]]
    p += mech["keylen"]
    iv = tok_bin[p : p + mech["bsize"]]
    p += mech["bsize"]
    cryptotext = tok_bin[p : p + ct_size]

    cipher = Cipher(mech["algo"](key), mech["mode"](iv), backend=default_backend())
    plaintext = cipher.decryptor().update(cryptotext) + cipher.decryptor().finalize()

    # The original implementation stored a NUL‑terminated C string padded with 0‑bytes
    return plaintext.split(b"\x00")[0].decode("ascii")


def encrypt_password(password: str, method: int = 0) -> str:
    """Return a Base‑64 token that sssd can later decrypt to *password*."""
    mech = crypto_mech_data[method]

    key = os.urandom(mech["keylen"])
    iv = os.urandom(mech["bsize"])

    # NUL‑terminate, then pad with NULs to a whole block
    buf = password.encode("ascii") + b"\x00"
    pad_len = (-len(buf)) % mech["bsize"]
    buf += b"\x00" * pad_len

    cipher = Cipher(mech["algo"](key), mech["mode"](iv), backend=default_backend())
    cryptotext = cipher.encryptor().update(buf) + cipher.encryptor().finalize()

    token_bin = (
        struct.pack("HH", method, len(cryptotext)) +
        key +
        iv +
        cryptotext
    )
    return base64.b64encode(token_bin).decode("ascii")


# ──────────────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} encrypt|decrypt")
        sys.exit(1)
    elif sys.argv[1].lower() not in ["encrypt", "decrypt"]:
        print(f"Usage: {sys.argv[0]} encrypt|decrypt")
        sys.exit(1)
    token = getpass.getpass("Enter the string to process: ")
    cmd = sys.argv[1]
    try:
        if cmd == "decrypt":
            print("Decoded password:", decrypt_token(token))
        else:  # encrypt
            print("Obfuscated token:", encrypt_password(token))
    except Exception as e:
        print("Error:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
