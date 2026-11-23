"""Semantic PR diff fixture: auditor-authz-intent (Cryptographic Doom / decrypt-before-MAC)."""
from __future__ import annotations

import hashlib
import hmac
import json
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def verify_and_decode_session(token_bytes: bytes, enc_key: bytes, mac_key: bytes) -> dict[str, object]:
    """Defect: decrypts and unpads untrusted AES-CBC ciphertext BEFORE verifying HMAC tag."""
    if len(token_bytes) < 48:
        raise ValueError("Truncated session token")

    iv = token_bytes[:16]
    ciphertext = token_bytes[16:-32]
    provided_mac = token_bytes[-32:]

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    expected_mac = hmac.new(mac_key, plaintext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, provided_mac):
        raise ValueError("Invalid session MAC")
    return json.loads(plaintext.decode("utf-8"))
