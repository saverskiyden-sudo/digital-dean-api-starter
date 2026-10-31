"""Маршрути захищених приміток: шифрування AES-256-GCM (cryptography)."""

from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status

from app.repositories.secure_note_repository import EncryptedNote, repository
from app.repositories.student_repository import (
    StudentNotFoundError,
    student_repository,
)
from app.schemas.secure_note import CATEGORIES, NoteCreate, NoteMetadata, NoteRead
from app.security import keys
from app.security.adapters import CiphertextError, open_bytes, seal_bytes
from app.security.context import note_aad
from app.security.profiles import BACKENDS, KEY_BYTES, NONCE_BYTES, TAG_BYTES

router = APIRouter(prefix="/api/v1/students", tags=["secure-notes"])

STUDENT_NOT_FOUND = "Студента не знайдено"
NOTE_NOT_FOUND = "Примітку не знайдено"
UNAVAILABLE = "Protected note unavailable"

# Базовий контракт: клієнт не обирає ні бібліотеку, ні алгоритм.
NOTE_ALGORITHM = "AES-256-GCM"
NOTE_BACKEND = "cryptography"
ENVELOPE_VERSION = 1


def _require_student(student_id: UUID) -> None:
    try:
        student_repository.get(student_id)
    except StudentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=STUDENT_NOT_FOUND)


def _unavailable(code: int) -> HTTPException:
    return HTTPException(code, detail=UNAVAILABLE)


@router.post(
    "/{student_id}/secure-notes",
    response_model=NoteMetadata,
    status_code=status.HTTP_201_CREATED,
)
def create_secure_note(student_id: UUID, payload: NoteCreate) -> NoteMetadata:
    _require_student(student_id)

    process_key = keys.get_process_key()
    note_id = uuid4()
    try:
        # Значення резервується до шифрування і не повертається назад,
        # навіть якщо наступний крок завершиться помилкою.
        nonce = process_key.nonces.next()
    except RuntimeError:
        raise _unavailable(status.HTTP_503_SERVICE_UNAVAILABLE)

    aad = note_aad(
        student_id, note_id, NOTE_ALGORITHM, process_key.key_id, payload.category
    )
    try:
        ciphertext, tag = seal_bytes(
            NOTE_BACKEND,
            NOTE_ALGORITHM,
            process_key.key,
            nonce,
            payload.text.encode("utf-8"),
            aad,
        )
    except (ValueError, CiphertextError):
        raise _unavailable(status.HTTP_500_INTERNAL_SERVER_ERROR)

    repository.add(
        EncryptedNote(
            version=ENVELOPE_VERSION,
            student_id=student_id,
            note_id=note_id,
            algorithm=NOTE_ALGORITHM,
            backend=NOTE_BACKEND,
            key_id=process_key.key_id,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            category=payload.category,
        )
    )
    return NoteMetadata(
        id=note_id,
        student_id=student_id,
        algorithm=NOTE_ALGORITHM,
        category=payload.category,
    )


def _check_envelope(note: EncryptedNote, process_key: keys.ProcessKey) -> None:
    """Структурні перевірки до розшифрування; помилка → ValueError."""
    if note.version != ENVELOPE_VERSION:
        raise ValueError("Unsupported envelope version")
    if note.algorithm not in KEY_BYTES or note.backend not in BACKENDS:
        raise ValueError("Unsupported profile")
    if note.key_id != process_key.key_id:
        raise ValueError("Unknown key")
    if note.category not in CATEGORIES:
        raise ValueError("Unknown category")
    if len(note.nonce) != NONCE_BYTES or len(note.tag) != TAG_BYTES:
        raise ValueError("Invalid envelope sizes")


@router.get("/{student_id}/secure-notes/{note_id}", response_model=NoteRead)
def read_secure_note(student_id: UUID, note_id: UUID) -> NoteRead:
    _require_student(student_id)
    try:
        note = repository.get(student_id, note_id)
    except KeyError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=NOTE_NOT_FOUND)

    process_key = keys.get_process_key()
    try:
        _check_envelope(note, process_key)
        # Контекст будується з очікуваного ресурсу (URL) і серверного ключа,
        # а ідентифікатори конверта нічого не вирішують самі по собі.
        aad = note_aad(
            student_id, note_id, note.algorithm, process_key.key_id, note.category
        )
        plain = open_bytes(
            note.backend,
            note.algorithm,
            process_key.key,
            note.nonce,
            note.ciphertext,
            note.tag,
            aad,
        )
        text = plain.decode("utf-8")
    except (CiphertextError, ValueError):
        # UnicodeDecodeError є підкласом ValueError.
        raise _unavailable(status.HTTP_500_INTERNAL_SERVER_ERROR)

    return NoteRead(
        id=note_id,
        student_id=student_id,
        algorithm=note.algorithm,
        category=note.category,
        text=text,
    )
