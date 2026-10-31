"""Спільний контракт для cryptography та PyCryptodome без відкритого fallback."""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from Crypto.Cipher import AES, ChaCha20_Poly1305

from app.security.profiles import BACKENDS, TAG_BYTES, validate_profile


class CiphertextError(Exception):
    """Повідомлення не пройшло перевірку автентичності."""


def _check_backend(backend: str) -> None:
    if backend not in BACKENDS:
        raise ValueError("Unsupported backend")


def _pycryptodome_cipher(algorithm, key, nonce):
    # Новий об'єкт шифру на кожну операцію; тег завжди 16 байтів.
    if algorithm.startswith("AES-"):
        return AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_BYTES)
    return ChaCha20_Poly1305.new(key=key, nonce=nonce)


def seal_bytes(backend, algorithm, key, nonce, data, aad):
    """Повертає (ciphertext, tag); тег окремо, довжина 16 байтів."""
    validate_profile(algorithm, key, nonce)
    _check_backend(backend)
    if backend == "cryptography":
        factory = AESGCM if algorithm.startswith("AES-") else ChaCha20Poly1305
        combined = factory(key).encrypt(nonce, data, aad)
        return combined[:-TAG_BYTES], combined[-TAG_BYTES:]
    cipher = _pycryptodome_cipher(algorithm, key, nonce)
    cipher.update(aad)
    return cipher.encrypt_and_digest(data)


def open_bytes(backend, algorithm, key, nonce, ct, tag, aad):
    """Повертає початкові байти лише після успішної перевірки повного тега."""
    validate_profile(algorithm, key, nonce)
    _check_backend(backend)
    if len(tag) != TAG_BYTES:
        raise CiphertextError("Verification failed")
    try:
        if backend == "cryptography":
            factory = AESGCM if algorithm.startswith("AES-") else ChaCha20Poly1305
            return factory(key).decrypt(nonce, ct + tag, aad)
        cipher = _pycryptodome_cipher(algorithm, key, nonce)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)
    except (InvalidTag, ValueError) as exc:
        raise CiphertextError("Verification failed") from exc
