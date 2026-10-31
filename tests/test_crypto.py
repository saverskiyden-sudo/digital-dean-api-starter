"""Початкові тести приймання падають до реалізації; не пропускайте їх."""

from concurrent.futures import ThreadPoolExecutor
from secrets import token_bytes

import pytest

from app.security.adapters import CiphertextError, open_bytes, seal_bytes
from app.security.context import note_aad
from app.security.keys import create_process_key
from app.security.nonce import NonceSequence
from app.security.profiles import BACKENDS, KEY_BYTES, validate_profile

PROFILES = tuple(KEY_BYTES.items())


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("algorithm,key_size", PROFILES)
@pytest.mark.parametrize("message", (b"", b"demo", "Навчальна примітка  ".encode()))
def test_round_trip(backend, algorithm, key_size, message):
    # Новий незалежний ключ на тест; лише одне шифрування з nonce=0.
    key, nonce, aad = token_bytes(key_size), bytes(12), b"synthetic-context"
    ct, tag = seal_bytes(backend, algorithm, key, nonce, message, aad)
    assert len(ct) == len(message)
    assert len(tag) == 16
    assert open_bytes(backend, algorithm, key, nonce, ct, tag, aad) == message


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("algorithm,key_size", PROFILES)
@pytest.mark.parametrize("changed_part", ("ct", "tag", "aad", "key", "nonce"))
def test_tampering_is_rejected(backend, algorithm, key_size, changed_part):
    key, nonce, aad = token_bytes(key_size), bytes(12), b"synthetic-context"
    ct, tag = seal_bytes(backend, algorithm, key, nonce, b"demo", aad)
    if changed_part == "ct":
        ct = bytes([ct[0] ^ 1]) + ct[1:]
    elif changed_part == "tag":
        tag = bytes([tag[0] ^ 1]) + tag[1:]
    elif changed_part == "aad":
        aad = b"different-context"
    elif changed_part == "key":
        key = token_bytes(key_size)
    else:
        nonce = bytes([1]) + nonce[1:]
    with pytest.raises(CiphertextError):
        open_bytes(backend, algorithm, key, nonce, ct, tag, aad)


@pytest.mark.parametrize("algorithm,key_size", PROFILES)
@pytest.mark.parametrize("writer,reader", (BACKENDS, tuple(reversed(BACKENDS))))
def test_cross_library(algorithm, key_size, writer, reader):
    key, nonce, aad = token_bytes(key_size), bytes(12), b"synthetic-context"
    ct, tag = seal_bytes(writer, algorithm, key, nonce, b"demo", aad)
    assert open_bytes(reader, algorithm, key, nonce, ct, tag, aad) == b"demo"


@pytest.mark.parametrize("args", (
    ("unknown", bytes(32), bytes(12)),
    ("AES-256-GCM", bytes(16), bytes(12)),
    ("AES-128-GCM", bytes(16), bytes(11)),
))
def test_invalid_profile(args):
    with pytest.raises(ValueError):
        validate_profile(*args)


def test_counter_limit_and_concurrency():
    seq = NonceSequence(limit=1000)
    with ThreadPoolExecutor(max_workers=8) as executor:
        values = list(executor.map(lambda _: seq.next(), range(1000)))
    assert len(set(values)) == 1000
    assert all(len(value) == 12 for value in values)
    with pytest.raises(RuntimeError):
        seq.next()


def test_context_is_bound_to_expected_student():
    assert note_aad("a", "n", "AES-256-GCM", "k") != note_aad(
        "b", "n", "AES-256-GCM", "k"
    )


def test_process_key_has_no_secret_in_repr():
    value = create_process_key()
    assert len(value.key) == 32
    assert "key=" not in repr(value)
    assert "nonces=" not in repr(value)


# --- Доповнення студента ---------------------------------------------------
LARGE = bytes(range(256)) * 4096  # 1 МіБ двійкових даних


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("algorithm,key_size", PROFILES)
def test_round_trip_large_binary_message(backend, algorithm, key_size):
    key, nonce, aad = token_bytes(key_size), bytes(12), b"synthetic-context"
    ct, tag = seal_bytes(backend, algorithm, key, nonce, LARGE, aad)
    assert len(ct) == len(LARGE)
    assert open_bytes(backend, algorithm, key, nonce, ct, tag, aad) == LARGE


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("algorithm,key_size", PROFILES)
def test_different_nonce_is_rejected(backend, algorithm, key_size):
    # Таблиця 6, сценарій 6: інше 12-байтове значення.
    key, aad = token_bytes(key_size), b"synthetic-context"
    ct, tag = seal_bytes(backend, algorithm, key, bytes(12), b"demo", aad)
    other = (1).to_bytes(12, "big")
    with pytest.raises(CiphertextError):
        open_bytes(backend, algorithm, key, other, ct, tag, aad)


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("algorithm,key_size", PROFILES)
@pytest.mark.parametrize("tag_size", (0, 8, 15, 17))
def test_truncated_or_extended_tag_is_rejected(backend, algorithm, key_size, tag_size):
    key, nonce, aad = token_bytes(key_size), bytes(12), b"synthetic-context"
    ct, tag = seal_bytes(backend, algorithm, key, nonce, b"demo", aad)
    bad_tag = tag[:tag_size] if tag_size < 16 else tag + bytes(tag_size - 16)
    with pytest.raises(CiphertextError):
        open_bytes(backend, algorithm, key, nonce, ct, bad_tag, aad)


@pytest.mark.parametrize("algorithm,key_size", PROFILES)
def test_unknown_backend_is_rejected_without_fallback(algorithm, key_size):
    args = (algorithm, token_bytes(key_size), bytes(12))
    with pytest.raises(ValueError):
        seal_bytes("openssl-cli", *args, b"demo", b"aad")
    with pytest.raises(ValueError):
        open_bytes("openssl-cli", *args, b"x", bytes(16), b"aad")


@pytest.mark.parametrize("backend", BACKENDS)
def test_invalid_key_length_is_rejected_by_adapter(backend):
    with pytest.raises(ValueError):
        seal_bytes(backend, "AES-256-GCM", bytes(16), bytes(12), b"demo", b"aad")


def test_validate_profile_accepts_all_profiles():
    for algorithm, key_size in PROFILES:
        validate_profile(algorithm, bytes(key_size), bytes(12))


def test_nonce_sequence_is_monotonic_and_unique_sequentially():
    seq = NonceSequence(limit=500)
    values = [seq.next() for _ in range(500)]
    assert values == [i.to_bytes(12, "big") for i in range(500)]
    assert len(set(values)) == 500


@pytest.mark.parametrize("limit", (0, -1, 1_000_001, 1.5, True, "10", None))
def test_nonce_sequence_rejects_invalid_limit(limit):
    with pytest.raises(ValueError):
        NonceSequence(limit=limit)


def test_exhausted_counter_does_not_reset():
    seq = NonceSequence(limit=2)
    seq.next()
    seq.next()
    for _ in range(3):
        with pytest.raises(RuntimeError):
            seq.next()


def test_process_keys_are_independent():
    first, second = create_process_key(), create_process_key()
    assert first.key != second.key
    assert first.key_id != second.key_id
    assert first.nonces is not second.nonces


def test_note_aad_is_canonical_and_covers_every_field():
    base = ("s", "n", "AES-256-GCM", "k")
    reference = note_aad(*base, "general")
    assert reference == note_aad(*base, "general")
    assert reference == (
        b'{"algorithm":"AES-256-GCM","category":"general","key_id":"k",'
        b'"note_id":"n","student_id":"s","version":1}'
    )
    variants = [
        note_aad("x", "n", "AES-256-GCM", "k", "general"),
        note_aad("s", "x", "AES-256-GCM", "k", "general"),
        note_aad("s", "n", "AES-128-GCM", "k", "general"),
        note_aad("s", "n", "AES-256-GCM", "x", "general"),
        note_aad(*base, "academic"),
    ]
    assert all(value != reference for value in variants)
