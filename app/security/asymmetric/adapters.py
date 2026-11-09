"""Криптографічні адаптери практичної роботи 3.

Тільки бібліотечні операції пакета cryptography (48.x):
RSA-OAEP, навчальний гібрид RSA-3072-OAEP + AES-256-GCM та HPKE Base.

generate_keypair повертає (private, public). encrypt/decrypt приймають
profile, об'єкт відповідного ключа, bytes і keyword-only context.
Контекст: label для OAEP, label та AAD для RSA/AES, info для HPKE.
RSA/AES envelope: wrapped_key[384] || nonce[12] || ct_with_tag.
HPKE envelope: повернений Suite.encrypt enc || ct без перекодування.
"""
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite

from app.security.asymmetric.profiles import (
    CONTEXT,
    KEY_PROFILES,
    PROFILES,
    oaep_max_bytes,
)

AES_KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
RSA_3072_BYTES = 384

_RSA_BITS = {"rsa-2048": 2048, "rsa-3072": 3072}
_HPKE_KEM = {"x25519": KEM.X25519, "p256": KEM.P256}
_HPKE_ENC_BYTES = {"x25519": 32, "p256": 65}


class DecryptionError(ValueError):
    """Єдина безпечна помилка відхилення криптографічного повідомлення."""


def generate_keypair(key_profile: str) -> tuple[object, object]:
    if key_profile not in KEY_PROFILES:
        raise ValueError("unsupported key profile")
    if key_profile in _RSA_BITS:
        private = rsa.generate_private_key(
            public_exponent=65537, key_size=_RSA_BITS[key_profile]
        )
    elif key_profile == "x25519":
        private = x25519.X25519PrivateKey.generate()
    else:
        private = ec.generate_private_key(ec.SECP256R1())
    return private, private.public_key()


def _oaep(label: bytes) -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=label,
    )


def _suite(key_profile: str) -> Suite:
    return Suite(_HPKE_KEM[key_profile], KDF.HKDF_SHA256, AEAD.AES_256_GCM)


def _check_rsa_key(key: object, bits: int, private: bool) -> None:
    expected = rsa.RSAPrivateKey if private else rsa.RSAPublicKey
    if not isinstance(key, expected) or key.key_size != bits:
        raise ValueError("key does not match the profile")


def _check_hpke_key(key: object, key_profile: str, private: bool) -> None:
    if key_profile == "x25519":
        expected = x25519.X25519PrivateKey if private else x25519.X25519PublicKey
        if not isinstance(key, expected):
            raise ValueError("key does not match the profile")
        return
    expected = ec.EllipticCurvePrivateKey if private else ec.EllipticCurvePublicKey
    if not isinstance(key, expected) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("key does not match the profile")


def encrypt(profile: str, public: object, message: bytes,
            *, context: bytes = CONTEXT) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")
    if not isinstance(message, (bytes, bytearray)) or not isinstance(context, bytes):
        raise ValueError("message and context must be bytes")
    spec = PROFILES[profile]
    if spec.group == "direct":
        bits = _RSA_BITS[spec.key_profile]
        _check_rsa_key(public, bits, private=False)
        if len(message) > oaep_max_bytes(bits):
            raise ValueError("message is too long for RSA-OAEP")
        return public.encrypt(bytes(message), _oaep(context))
    if profile == "rsa3072-oaep-aes256gcm":
        _check_rsa_key(public, 3072, private=False)
        # Свіжі ключ AES і nonce для кожного повідомлення.
        key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(NONCE_BYTES)
        wrapped = public.encrypt(key, _oaep(context))
        return wrapped + nonce + AESGCM(key).encrypt(nonce, bytes(message), context)
    _check_hpke_key(public, spec.key_profile, private=False)
    return _suite(spec.key_profile).encrypt(bytes(message), public, info=context)


def _decrypt(profile: str, private: object, envelope: bytes, context: bytes) -> bytes:
    if not isinstance(envelope, (bytes, bytearray)) or not isinstance(context, bytes):
        raise ValueError("envelope and context must be bytes")
    envelope = bytes(envelope)
    spec = PROFILES[profile]
    if spec.group == "direct":
        bits = _RSA_BITS[spec.key_profile]
        _check_rsa_key(private, bits, private=True)
        if len(envelope) != bits // 8:
            raise ValueError("invalid envelope length")
        return private.decrypt(envelope, _oaep(context))
    if profile == "rsa3072-oaep-aes256gcm":
        _check_rsa_key(private, 3072, private=True)
        if len(envelope) < RSA_3072_BYTES + NONCE_BYTES + TAG_BYTES:
            raise ValueError("invalid envelope length")
        wrapped = envelope[:RSA_3072_BYTES]
        nonce = envelope[RSA_3072_BYTES:RSA_3072_BYTES + NONCE_BYTES]
        body = envelope[RSA_3072_BYTES + NONCE_BYTES:]
        key = private.decrypt(wrapped, _oaep(context))
        if len(key) != AES_KEY_BYTES:
            raise ValueError("invalid wrapped key")
        return AESGCM(key).decrypt(nonce, body, context)
    _check_hpke_key(private, spec.key_profile, private=True)
    if len(envelope) < _HPKE_ENC_BYTES[spec.key_profile] + TAG_BYTES:
        raise ValueError("invalid envelope length")
    return _suite(spec.key_profile).decrypt(envelope, private, info=context)


def decrypt(profile: str, private: object, envelope: bytes,
            *, context: bytes = CONTEXT) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")
    try:
        return _decrypt(profile, private, envelope, context)
    except (InvalidTag, ValueError) as exc:
        raise DecryptionError("decryption rejected") from exc
