from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.repositories.student_repository import student_repository


client = TestClient(app)
URL = "/api/v1/students"


@pytest.fixture(autouse=True)
def clean_repository() -> None:
    """Кожен тест починається з порожнього сховища."""
    student_repository.clear()


def make_student(**overrides) -> dict:
    body = {
        "full_name": "Олена Коваль",
        "email": "olena.koval@example.com",
        "group_code": "КН-31",
        "enrollment_year": 2024,
    }
    body.update(overrides)
    return body


def create(**overrides) -> dict:
    response = client.post(URL, json=make_student(**overrides))
    assert response.status_code == 201
    return response.json()


# 2. Створення запису
def test_create_student() -> None:
    response = client.post(URL, json=make_student())

    assert response.status_code == 201
    body = response.json()
    assert isinstance(body["id"], str)
    assert body["full_name"] == "Олена Коваль"
    assert body["email"] == "olena.koval@example.com"
    assert body["group_code"] == "КН-31"
    assert body["enrollment_year"] == 2024


def test_create_without_enrollment_year() -> None:
    body = make_student()
    del body["enrollment_year"]

    response = client.post(URL, json=body)

    assert response.status_code == 201
    assert response.json()["enrollment_year"] is None


# 3. Некоректна електронна адреса
def test_create_invalid_email_is_rejected() -> None:
    response = client.post(URL, json=make_student(email="not-an-email"))

    assert response.status_code == 422
    assert client.get(URL).json() == []


# 4. Список записів
def test_list_students() -> None:
    first = create(email="a@example.com")
    second = create(email="b@example.com", full_name="Іван Петренко")

    response = client.get(URL)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert {item["id"] for item in body} == {first["id"], second["id"]}


# 5. Отримання наявного запису
def test_get_existing_student() -> None:
    created = create()

    response = client.get(f"{URL}/{created['id']}")

    assert response.status_code == 200
    assert response.json() == created


# 6. Отримання відсутнього запису
def test_get_missing_student_returns_404() -> None:
    response = client.get(f"{URL}/{uuid4()}")

    assert response.status_code == 404
    assert "detail" in response.json()
    assert "Traceback" not in response.text


def test_get_with_invalid_uuid_returns_422() -> None:
    response = client.get(f"{URL}/not-a-uuid")

    assert response.status_code == 422


# 7. Часткове оновлення
def test_patch_changes_only_given_field() -> None:
    created = create()

    response = client.patch(f"{URL}/{created['id']}", json={"group_code": "КН-32"})

    assert response.status_code == 200
    body = response.json()
    assert body["group_code"] == "КН-32"
    assert body["id"] == created["id"]
    assert body["full_name"] == created["full_name"]
    assert body["email"] == created["email"]
    assert body["enrollment_year"] == created["enrollment_year"]


def test_patch_empty_body_is_rejected() -> None:
    created = create()

    response = client.patch(f"{URL}/{created['id']}", json={})

    assert response.status_code == 422


def test_patch_missing_student_returns_404() -> None:
    response = client.patch(f"{URL}/{uuid4()}", json={"group_code": "КН-32"})

    assert response.status_code == 404


# 8. Невідоме поле
def test_patch_unknown_field_is_rejected() -> None:
    created = create()

    response = client.patch(f"{URL}/{created['id']}", json={"is_admin": True})

    assert response.status_code == 422
    assert client.get(f"{URL}/{created['id']}").json() == created


def test_patch_cannot_change_id() -> None:
    created = create()

    response = client.patch(f"{URL}/{created['id']}", json={"id": str(uuid4())})

    assert response.status_code == 422


def test_create_unknown_field_is_rejected() -> None:
    response = client.post(URL, json=make_student(is_admin=True))

    assert response.status_code == 422


def test_create_malformed_json_is_rejected() -> None:
    response = client.post(
        URL, content="{bad json", headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 422


# Конфлікт електронної адреси
def test_duplicate_email_returns_409_case_insensitive() -> None:
    create(email="olena.koval@example.com")

    response = client.post(URL, json=make_student(email="OLENA.Koval@example.com"))

    assert response.status_code == 409
    assert len(client.get(URL).json()) == 1


def test_patch_duplicate_email_returns_409() -> None:
    create(email="a@example.com")
    second = create(email="b@example.com")

    response = client.patch(f"{URL}/{second['id']}", json={"email": "a@example.com"})

    assert response.status_code == 409


def test_patch_same_email_on_same_record_is_allowed() -> None:
    created = create(email="a@example.com")

    response = client.patch(f"{URL}/{created['id']}", json={"email": "a@example.com"})

    assert response.status_code == 200


# 9. Фільтрація варіанта
def test_filter_by_enrollment_year() -> None:
    create(email="a@example.com", enrollment_year=2023)
    create(email="b@example.com", enrollment_year=2024)
    create(email="c@example.com", enrollment_year=2024)

    response = client.get(URL, params={"enrollment_year": 2024})

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert all(item["enrollment_year"] == 2024 for item in body)


def test_filter_out_of_range_is_rejected() -> None:
    response = client.get(
        URL, params={"enrollment_year": settings.enrollment_year_max + 1}
    )

    assert response.status_code == 422


# 10–11. Межові перевірки варіанта (межі беруться з конфігурації)
@pytest.mark.parametrize(
    "year", [settings.enrollment_year_min, settings.enrollment_year_max]
)
def test_enrollment_year_on_the_boundary_is_accepted(year: int) -> None:
    response = client.post(URL, json=make_student(enrollment_year=year))

    assert response.status_code == 201
    assert response.json()["enrollment_year"] == year


@pytest.mark.parametrize(
    "year",
    [settings.enrollment_year_min - 1, settings.enrollment_year_max + 1, "abc"],
)
def test_enrollment_year_outside_the_range_is_rejected(year) -> None:
    response = client.post(URL, json=make_student(enrollment_year=year))

    assert response.status_code == 422
    assert client.get(URL).json() == []


def test_patch_enrollment_year_out_of_range_is_rejected() -> None:
    created = create()

    response = client.patch(
        f"{URL}/{created['id']}",
        json={"enrollment_year": settings.enrollment_year_min - 1},
    )

    assert response.status_code == 422


def test_patch_enrollment_year() -> None:
    created = create(enrollment_year=2022)

    response = client.patch(f"{URL}/{created['id']}", json={"enrollment_year": 2023})

    assert response.status_code == 200
    assert response.json()["enrollment_year"] == 2023
    assert response.json()["group_code"] == created["group_code"]
