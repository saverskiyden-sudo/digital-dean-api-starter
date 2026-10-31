from uuid import UUID, uuid4

from app.schemas.student import StudentCreate, StudentRead, StudentUpdate


class StudentNotFoundError(KeyError):
    """Запис студента не знайдено."""


class DuplicateEmailError(ValueError):
    """Електронна адреса вже використовується."""


class InMemoryStudentRepository:
    def __init__(self) -> None:
        self._students: dict[UUID, StudentRead] = {}

    def _email_taken(self, email: str, *, exclude_id: UUID | None = None) -> bool:
        """Порівнює адреси без урахування регістру; поточний запис можна виключити."""
        wanted = email.casefold()
        for student_id, student in self._students.items():
            if student_id == exclude_id:
                continue
            if student.email.casefold() == wanted:
                return True
        return False

    def create(self, payload: StudentCreate) -> StudentRead:
        if self._email_taken(payload.email):
            raise DuplicateEmailError(payload.email)
        student = StudentRead(id=uuid4(), **payload.model_dump())
        self._students[student.id] = student
        return student.model_copy()

    def list(self, *, enrollment_year: int | None = None) -> list[StudentRead]:
        students = list(self._students.values())
        if enrollment_year is not None:
            students = [s for s in students if s.enrollment_year == enrollment_year]
        return [s.model_copy() for s in students]

    def get(self, student_id: UUID) -> StudentRead:
        student = self._students.get(student_id)
        if student is None:
            raise StudentNotFoundError(student_id)
        return student.model_copy()

    def update(self, student_id: UUID, payload: StudentUpdate) -> StudentRead:
        current = self._students.get(student_id)
        if current is None:
            raise StudentNotFoundError(student_id)

        # Тільки поля, які клієнт явно передав.
        changes = payload.model_dump(exclude_unset=True)

        if "email" in changes and self._email_taken(
            changes["email"], exclude_id=student_id
        ):
            raise DuplicateEmailError(changes["email"])

        updated = current.model_copy(update=changes)
        self._students[student_id] = updated
        return updated.model_copy()

    def clear(self) -> None:
        self._students.clear()


student_repository = InMemoryStudentRepository()
