"""Бібліотечне хешування через hashlib: без власних криптопримітивів.

Профілі й конструктори задано у profiles.py. Тут лише:
- prepare_operation: перевірка входу та підготовка незмінних блоків ПОЗА таймером;
  повертає операцію без аргументів, яка щоразу створює НОВИЙ стан;
- hash_bytes: одноразове обчислення хешу повідомлення (whole або chunked);
- hamming_bits: відстань Геммінга між двома хешами однакової довжини.
"""
from app.security.hashing import profiles
from app.security.hashing.profiles import CHUNK_BYTES, PROFILES

MODES = ("whole", "chunked")


def _validate(algorithm: object, data: object, mode: object) -> None:
    if type(algorithm) is not str or algorithm not in PROFILES:
        raise ValueError("unknown hash profile")
    if type(mode) is not str or mode not in MODES:
        raise ValueError("unknown hashing mode")
    # Лише точні bytes: str, bytearray чи memoryview треба явно перетворити до виклику.
    if type(data) is not bytes:
        raise TypeError("data must be bytes")


def prepare_operation(algorithm: str, data: bytes, mode: str = "whole"):
    """Готує повторювану повну операцію хешування одного повідомлення.

    Нарізання на блоки виконується тут один раз; повернена функція не
    захоплює змінного об'єкта хешування — кожен виклик створює новий стан,
    виконує update і повертає digest.
    """
    _validate(algorithm, data, mode)
    make_hasher = profiles.make_hasher
    if mode == "whole":
        def whole() -> bytes:
            state = make_hasher(algorithm)
            state.update(data)
            return state.digest()
        return whole

    chunks = tuple(data[i:i + CHUNK_BYTES] for i in range(0, len(data), CHUNK_BYTES))

    def chunked() -> bytes:
        state = make_hasher(algorithm)
        for chunk in chunks:
            state.update(chunk)
        return state.digest()
    return chunked


def hash_bytes(algorithm: str, data: bytes, mode: str = "whole") -> bytes:
    """Хеш точних байтів за профілем; новий стан на кожен виклик."""
    return prepare_operation(algorithm, data, mode)()


def hamming_bits(left: bytes, right: bytes) -> int:
    """Кількість відмінних бітів (не символів hex) двох непорожніх хешів."""
    if type(left) is not bytes or type(right) is not bytes:
        raise TypeError("hamming_bits expects bytes")
    if not left or len(left) != len(right):
        raise ValueError("hamming_bits expects nonempty values of equal length")
    return sum((a ^ b).bit_count() for a, b in zip(left, right))
