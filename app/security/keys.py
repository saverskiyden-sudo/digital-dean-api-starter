"""Матеріал ключа створюють один раз під час запуску процесу API."""

from dataclasses import dataclass, field
from secrets import token_bytes
from uuid import UUID, uuid4

from app.security.nonce import NonceSequence


@dataclass(frozen=True)
class ProcessKey:
    key_id: UUID
    key: bytes = field(repr=False)
    nonces: NonceSequence = field(repr=False)


def create_process_key(limit: int = 1_000_000) -> ProcessKey:
    """Викликайте при запуску, а не при кожному запиті чи читанні примітки."""
    return ProcessKey(uuid4(), token_bytes(32), NonceSequence(limit))


# Один ProcessKey на процес: маршрути запису й читання беруть його звідси.
# Ключ існує лише в пам'яті; не пишіть його у файли, JSON, Git чи відповіді API.
_current: ProcessKey = create_process_key()


def get_process_key() -> ProcessKey:
    return _current


def replace_process_key(value: ProcessKey) -> None:
    """Лише для тестів: підставляє новий ключ із власним лічильником."""
    global _current
    _current = value
