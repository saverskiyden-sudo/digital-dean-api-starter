"""Сховище зберігає конверт, не відкритий текст і не ключ."""

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class EncryptedNote:
    version: int
    student_id: UUID
    note_id: UUID
    algorithm: str
    backend: str
    key_id: UUID
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    # Індивідуальний варіант 1: категорія входить до конверта й до AAD.
    category: str = "general"


class SecureNoteRepository:
    def __init__(self):
        self._items: dict[UUID, EncryptedNote] = {}

    def add(self, note: EncryptedNote) -> None:
        """Зберігає конверт; повторний note_id не перезаписує наявний запис."""
        if note.note_id in self._items:
            raise ValueError("Duplicate note id")
        self._items[note.note_id] = note

    def get(self, student_id: UUID, note_id: UUID) -> EncryptedNote:
        """Повертає конверт лише для свого студента; інакше KeyError."""
        note = self._items.get(note_id)
        if note is None or note.student_id != student_id:
            raise KeyError(note_id)
        return note

    def clear(self) -> None:
        """Очищення записів не змінює ключ і не скидає його лічильник."""
        self._items.clear()


repository = SecureNoteRepository()

# Підміна _items допустима лише в тестах, не через окремий HTTP-маршрут.
