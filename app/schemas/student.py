from typing import Annotated
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    model_validator,
)
from pydantic_core import PydanticCustomError

from app.config import settings


class StrictModel(BaseModel):
    """Базова модель, яка не приймає невідомих полів."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# Після вилучення крайніх пробілів від 5 до 120 символів.
FullName = Annotated[str, Field(min_length=5, max_length=120)]

# Великі латинські або українські літери чи цифри, дефіс і дві цифри: КН-31.
GroupCode = Annotated[
    str,
    Field(pattern=r"^[A-ZАБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ0-9]+-[0-9]{2}$"),
]

# Індивідуальний варіант: рік вступу. Межі беруться з app/config.py.
EnrollmentYear = Annotated[
    int,
    Field(ge=settings.enrollment_year_min, le=settings.enrollment_year_max),
]


class StudentCreate(StrictModel):
    full_name: FullName
    email: EmailStr
    group_code: GroupCode
    # Необов'язкове, щоб базові запити без цього поля теж працювали.
    enrollment_year: EnrollmentYear | None = None


class StudentRead(StudentCreate):
    id: UUID


class StudentUpdate(StrictModel):
    """Дозвільний список полів для PATCH: id тут немає, тому змінити його не можна."""

    full_name: FullName | None = None
    email: EmailStr | None = None
    group_code: GroupCode | None = None
    enrollment_year: EnrollmentYear | None = None

    @model_validator(mode="after")
    def _check_update(self) -> "StudentUpdate":
        if not self.model_fields_set:
            raise PydanticCustomError(
                "empty_update", "Потрібно передати хоча б одне поле"
            )
        # null дозволений лише для enrollment_year (очистити значення).
        for name in ("full_name", "email", "group_code"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise PydanticCustomError(
                    "null_not_allowed", "Поле {field} не може бути null", {"field": name}
                )
        return self
