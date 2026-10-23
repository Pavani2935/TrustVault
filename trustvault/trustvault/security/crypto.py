"""Envelope encryption for file contents.

Each stored version gets its own random 256-bit data key (DEK). The file is encrypted
with AES-256-GCM under the DEK; the DEK is wrapped (also AES-256-GCM) under the master
key, which lives only in the environment, never in the database.

- Stealing the database alone yields ciphertext and wrapped keys: useless without the master key.
- Associated data binds each ciphertext to its version and document ID, so swapping blob
  rows between documents at the database level makes decryption fail rather than
  silently serving the wrong file.
- Purging a version deletes its wrapped DEK: the data is cryptographically shredded even
  if a backup of the blob survives somewhere.
"""
from __future__ import annotations

import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptionError(Exception):
    pass


def key_id(master_key: bytes) -> str:
    """Short fingerprint stored with each wrapped key, so a future rotation knows which KEK applies."""
    return hashlib.sha256(b"tv-kek-id" + master_key).hexdigest()[:16]


def encrypt_file(master_key: bytes, document_id: str, version_id: str, plaintext: bytes) -> tuple[bytes, bytes]:
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = nonce + AESGCM(dek).encrypt(nonce, plaintext, f"tv:blob:{document_id}:{version_id}".encode())
    wrap_nonce = os.urandom(12)
    wrapped = wrap_nonce + AESGCM(master_key).encrypt(wrap_nonce, dek, f"tv:dek:{document_id}:{version_id}".encode())
    return ciphertext, wrapped


def decrypt_file(master_key: bytes, document_id: str, version_id: str, wrapped: bytes, ciphertext: bytes) -> bytes:
    try:
        dek = AESGCM(master_key).decrypt(wrapped[:12], wrapped[12:], f"tv:dek:{document_id}:{version_id}".encode())
        return AESGCM(dek).decrypt(ciphertext[:12], ciphertext[12:], f"tv:blob:{document_id}:{version_id}".encode())
    except (InvalidTag, ValueError) as exc:
        raise DecryptionError("ciphertext failed integrity check") from exc
