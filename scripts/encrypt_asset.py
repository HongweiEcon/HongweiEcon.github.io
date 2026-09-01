"""Encrypt a file for password-protected download on the static site.

The site is hosted on GitHub Pages and has no backend, so the file itself is
encrypted at rest.  Only the ciphertext is committed; the browser derives the
key from the visitor's password with PBKDF2 and decrypts with AES-256-GCM.

Container layout (all integers big-endian):

    magic   4 bytes   b"HWLK"
    version 1 byte    0x01
    iters   4 bytes   PBKDF2-HMAC-SHA256 iteration count
    salt   16 bytes
    iv     12 bytes
    body    rest      AES-256-GCM ciphertext followed by the 16-byte tag

Usage:
    uv run --no-project --with cryptography python scripts/encrypt_asset.py \
        private/slides_Hongwei.pdf static/files/slides-agent-loop.enc
"""

import argparse
import getpass
import os
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"HWLK"
VERSION = 1
ITERATIONS = 300_000
SALT_LEN = 16
IV_LEN = 12


def encrypt(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    ).derive(password.encode("utf-8"))
    body = AESGCM(key).encrypt(iv, plaintext, None)
    return MAGIC + struct.pack(">BI", VERSION, ITERATIONS) + salt + iv + body


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="plaintext file to protect")
    parser.add_argument("target", help="path of the .enc file to write")
    parser.add_argument(
        "--password",
        help="password (omit to be prompted, which keeps it out of shell history)",
    )
    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")
    if not password:
        print("error: empty password", file=sys.stderr)
        return 1

    with open(args.source, "rb") as handle:
        plaintext = handle.read()

    blob = encrypt(plaintext, password)
    os.makedirs(os.path.dirname(args.target) or ".", exist_ok=True)
    with open(args.target, "wb") as handle:
        handle.write(blob)

    print(f"{args.source} ({len(plaintext):,} bytes) -> {args.target} ({len(blob):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
