"""Моделі API відокремлені від внутрішнього криптографічного конверта."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

Algorithm = Literal["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"]
# Індивідуальний варіант 1 (номер 17 mod 4 = 1): категорія примітки.
Category = Literal["general", "academic", "administrative"]
CATEGORIES = ("general", "academic", "administrative")
MAX_TEXT_BYTES = 4096


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1, max_length=MAX_TEXT_BYTES)
    category: Category = "general"

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        """1–4096 байтів UTF-8, не лише пробіли; текст не обрізається."""
        if not value.strip():
            raise ValueError("Empty note")
        if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
            raise ValueError("Note exceeds 4096 bytes")
        return value


class NoteMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    student_id: UUID
    algorithm: Algorithm
    category: Category


class NoteRead(NoteMetadata):
    text: str
