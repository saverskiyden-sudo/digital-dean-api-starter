"""Налаштування навчального API.

Межі року вступу задаються тут, а не «зашиті» числами в схемах.
Їх можна змінити змінними середовища без редагування коду:
    DEAN_ENROLLMENT_YEAR_MIN, DEAN_ENROLLMENT_YEAR_MAX
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    enrollment_year_min: int
    enrollment_year_max: int


def load_settings() -> Settings:
    return Settings(
        enrollment_year_min=int(os.getenv("DEAN_ENROLLMENT_YEAR_MIN", "2000")),
        enrollment_year_max=int(os.getenv("DEAN_ENROLLMENT_YEAR_MAX", "2030")),
    )


settings = load_settings()
