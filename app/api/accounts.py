"""Account API of practice 5, connected to the SAME existing app in app/main.py.

Local educational methods: delete_user and block_user have NO administrative
authorization yet and must not be exposed to external clients; login returns
only a JSON boolean and creates no session or token.
"""
from typing import Annotated
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Path, Response

from app.api.account_validation import SensitiveRoute
from app.db.connection import DB_PATH
from app.repositories.user_repository import (
    UserConflict, UserNotFound, UserReferenced, UserRepository,
)
from app.schemas.user_account import LoginRequest, UserCreate, UserPublic

router = APIRouter(tags=["accounts"], route_class=SensitiveRoute)


def get_user_repository() -> UserRepository:
    return UserRepository(DB_PATH)


Repository = Annotated[UserRepository, Depends(get_user_repository)]
UserId = Annotated[int, Path(gt=0, le=9_223_372_036_854_775_807)]


ERRORS = {
    "conflict": "user already exists",
    "not_found": "user not found",
    "referenced": "user has grade references",
    "database": "database unavailable",
}
_INVALID = {422: {"description": "invalid input (redacted, no input echo)"}}
_DB = {500: {"description": ERRORS["database"]}}
_MISSING = {404: {"description": ERRORS["not_found"]}}


def _database_error() -> HTTPException:
    # No exception text, SQL, file path, request body, hash or salt.
    return HTTPException(500, ERRORS["database"])


@router.post(
    "/api/v1/users", status_code=201, response_model=UserPublic,
    summary="register_user: створити обліковий запис (стандартно inactive)",
    responses={409: {"description": ERRORS["conflict"]}, **_INVALID, **_DB},
)
def register_user(data: UserCreate, repository: Repository) -> UserPublic:
    try:
        return repository.register_user(data)
    except UserConflict:
        raise HTTPException(409, ERRORS["conflict"]) from None
    except sqlite3.Error:
        raise _database_error() from None


@router.delete(
    "/api/v1/users/{user_id}", status_code=204, response_class=Response,
    summary="delete_user: фізично видалити запис без оцінок",
    responses={**_MISSING, 409: {"description": ERRORS["referenced"]}, **_INVALID, **_DB},
)
def delete_user(user_id: UserId, repository: Repository) -> Response:
    try:
        repository.delete_user(user_id)
    except UserNotFound:
        raise HTTPException(404, ERRORS["not_found"]) from None
    except UserReferenced:
        raise HTTPException(409, ERRORS["referenced"]) from None
    except sqlite3.Error:
        raise _database_error() from None
    return Response(status_code=204)          # empty body, not JSON null or {}


@router.patch(
    "/api/v1/users/{user_id}/block", response_model=UserPublic,
    summary="block_user: встановити status_id=2 (повтор безпечний)",
    responses={**_MISSING, **_INVALID, **_DB},
)
def block_user(user_id: UserId, repository: Repository) -> UserPublic:
    try:
        return repository.block_user(user_id)
    except UserNotFound:
        raise HTTPException(404, ERRORS["not_found"]) from None
    except sqlite3.Error:
        raise _database_error() from None


@router.post(
    "/api/v1/auth/login", response_model=bool,
    summary="login: true лише для правильного пароля і статусу active",
    responses={**_INVALID, **_DB},
)
def login(data: LoginRequest, repository: Repository) -> bool:
    try:
        return repository.login(data.login, data.password.get_secret_value())
    except sqlite3.Error:
        raise _database_error() from None
