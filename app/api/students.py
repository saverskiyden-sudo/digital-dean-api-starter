from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.config import settings
from app.repositories.student_repository import (
    DuplicateEmailError,
    StudentNotFoundError,
    student_repository,
)
from app.schemas.student import StudentCreate, StudentRead, StudentUpdate


router = APIRouter(prefix="/api/v1/students", tags=["students"])

NOT_FOUND = "Студента не знайдено"
DUPLICATE_EMAIL = "Студент з такою електронною адресою вже існує"


@router.post("", response_model=StudentRead, status_code=status.HTTP_201_CREATED)
def create_student(payload: StudentCreate) -> StudentRead:
    try:
        return student_repository.create(payload)
    except DuplicateEmailError:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=DUPLICATE_EMAIL)


@router.get("", response_model=list[StudentRead])
def list_students(
    enrollment_year: Annotated[
        int | None,
        Query(
            ge=settings.enrollment_year_min,
            le=settings.enrollment_year_max,
            description="Фільтр за роком вступу",
        ),
    ] = None,
) -> list[StudentRead]:
    return student_repository.list(enrollment_year=enrollment_year)


@router.get("/{student_id}", response_model=StudentRead)
def get_student(student_id: UUID) -> StudentRead:
    try:
        return student_repository.get(student_id)
    except StudentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)


@router.patch("/{student_id}", response_model=StudentRead)
def update_student(student_id: UUID, payload: StudentUpdate) -> StudentRead:
    try:
        return student_repository.update(student_id, payload)
    except StudentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)
    except DuplicateEmailError:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=DUPLICATE_EMAIL)
