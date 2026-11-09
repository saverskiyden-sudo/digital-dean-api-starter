"""Fixed educational PBKDF2 profile; do not reuse the fast hashes from lab 4."""
import hashlib
import hmac
import re
import secrets

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 600_000
SALT_BYTES = 16
DERIVED_BYTES = 32
MIN_PASSWORD_CHARS = 15
MAX_PASSWORD_CHARS = 128
MAX_PASSWORD_BYTES = 512
# Exact stored representation of the single supported profile.
RECORD_PREFIX = f"{ALGORITHM}${ITERATIONS}$"
RECORD_LENGTH = len(RECORD_PREFIX) + 2 * DERIVED_BYTES
_HEX_DIGEST = re.compile(rf"[0-9a-f]{{{2 * DERIVED_BYTES}}}")
_HEX_SALT = re.compile(rf"[0-9a-f]{{{2 * SALT_BYTES}}}")


def _derive(raw_password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", raw_password, salt, ITERATIONS,
                               dklen=DERIVED_BYTES)


def password_bytes(password: str, *, registration: bool = False) -> bytes:
    """Preserve whitespace/case; encode strict UTF-8, bounded before the KDF."""
    if not isinstance(password, str):
        raise ValueError("password must be text")
    minimum = MIN_PASSWORD_CHARS if registration else 1
    if not minimum <= len(password) <= MAX_PASSWORD_CHARS or "\x00" in password:
        raise ValueError("password length or characters invalid")
    try:
        raw = password.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("password encoding invalid") from exc
    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError("password byte length invalid")
    return raw


def make_password_record(password: str) -> tuple[str, str]:
    """Return (password_record, salt_hex), never the cleartext password.

    TODO: use a fresh secrets.token_bytes(SALT_BYTES), PBKDF2-HMAC-SHA256,
    and lowercase hex. Record format is pbkdf2_sha256$600000$<64 hex chars>.
    The salt is stored separately as exactly 32 lowercase hex characters.
    """
    raw = password_bytes(password, registration=True)
    salt = secrets.token_bytes(SALT_BYTES)        # fresh for every registration
    return RECORD_PREFIX + _derive(raw, salt).hex(), salt.hex()


def verify_password(password: str, record: str, salt_hex: str) -> bool:
    """TODO: bounded strict parsing, fixed supported profile, compare_digest.

    Return False for wrong passwords and malformed/unsupported stored values.
    Do not run the KDF with an arbitrary iteration count from the database.
    Do not trim or case-convert the password. Never log these arguments.
    """
    # 1. Bounded strict parsing BEFORE any KDF work: exact length and prefix,
    #    lowercase hex of exact size. Unknown algorithm or another iteration
    #    count from the database is rejected, never executed.
    if type(record) is not str or type(salt_hex) is not str:
        return False
    if len(record) != RECORD_LENGTH or len(salt_hex) != 2 * SALT_BYTES:
        return False
    if not record.startswith(RECORD_PREFIX):
        return False
    stored_hex = record[len(RECORD_PREFIX):]
    if not _HEX_DIGEST.fullmatch(stored_hex) or not _HEX_SALT.fullmatch(salt_hex):
        return False
    # 2. The candidate keeps spaces and case; only bounded strict UTF-8.
    try:
        raw = password_bytes(password)
    except ValueError:
        return False
    # 3. Same fixed profile and salt; constant-time comparison of bytes.
    candidate = _derive(raw, bytes.fromhex(salt_hex))
    return hmac.compare_digest(candidate, bytes.fromhex(stored_hex))
