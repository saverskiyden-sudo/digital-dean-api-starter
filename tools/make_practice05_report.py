"""Збирає docs/practice-05-report.md з фактичних результатів власного запуску.

    python tools/make_practice05_report.py --pytest-final "..." --git-log-file log.txt \
        --init-check "..." --hygiene "..."

Числа беруться з pytest, results/practice-05/live-check.json, робочої бази
(лише кількості рядків довідників) та Git; нічого не вигадується.
"""
import argparse
import json
import sqlite3
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.db.connection import DB_PATH, open_database  # noqa: E402
from app.db.schema import ROLE_ROWS, STATUS_ROWS  # noqa: E402
from app.security import passwords  # noqa: E402

FORK = "https://github.com/saverskiyden-sudo/digital-dean-api-starter"

SOURCES = [
    "Python 3.13, sqlite3 — DB-API 2.0 interface for SQLite databases. https://docs.python.org/3/library/sqlite3.html",
    "SQLite Foreign Key Support. https://www.sqlite.org/foreignkeys.html",
    "SQLite CREATE TABLE (constraints). https://www.sqlite.org/lang_createtable.html",
    "SQLite Datatypes (type affinity). https://www.sqlite.org/datatype3.html",
    "SQLite Transactions (BEGIN IMMEDIATE). https://www.sqlite.org/lang_transaction.html",
    "SQLite UPSERT (ON CONFLICT DO NOTHING). https://www.sqlite.org/lang_upsert.html",
    "SQLite ON CONFLICT clause / REPLACE. https://www.sqlite.org/lang_conflict.html",
    "Python 3.13, hashlib.pbkdf2_hmac. https://docs.python.org/3/library/hashlib.html#hashlib.pbkdf2_hmac",
    "Python 3.13, secrets. https://docs.python.org/3/library/secrets.html",
    "Python 3.13, hmac.compare_digest. https://docs.python.org/3/library/hmac.html#hmac.compare_digest",
    "OWASP Password Storage Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    "NIST SP 800-132 Recommendation for Password-Based Key Derivation. https://csrc.nist.gov/pubs/sp/800/132/final",
    "OWASP Authentication Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    "FastAPI, Response Model. https://fastapi.tiangolo.com/tutorial/response-model/",
    "FastAPI, Handling Errors. https://fastapi.tiangolo.com/tutorial/handling-errors/",
    "FastAPI, Custom Request and APIRoute class. https://fastapi.tiangolo.com/how-to/custom-request-and-route/",
    "FastAPI, Testing Dependencies with Overrides. https://fastapi.tiangolo.com/advanced/testing-dependencies/",
    "Pydantic, Types: SecretStr, EmailStr; Strict Mode. https://docs.pydantic.dev/latest/api/types/",
    "pytest, tmp_path fixture. https://docs.pytest.org/en/stable/how-to/tmp_path.html",
    "Postman, Write scripts to test API response data. https://learning.postman.com/docs/tests-and-scripts/write-scripts/test-scripts/",
    "Git, merge. https://git-scm.com/docs/git-merge",
    "Git, tag. https://git-scm.com/docs/git-tag",
    "GitHub, Fork a repository. https://docs.github.com/en/pull-requests/how-tos/work-with-forks/fork-a-repo",
]

GLOSSARY = [
    ("API", "Application Programming Interface; прикладний програмний інтерфейс — HTTP-маршрути того самого застосунку FastAPI."),
    ("BEGIN IMMEDIATE", "Початок транзакції SQLite з одразу захопленим правом запису; разом із COMMIT/ROLLBACK обрамлює багатокрокову зміну."),
    ("CASCADE", "Дія зовнішнього ключа: під час видалення батьківського запису видаляються залежні рядки (тут лише user_role)."),
    ("compare_digest", "Функція hmac для порівняння байтів без раннього виходу на першій відмінності."),
    ("DDL", "Data Definition Language; мова визначення структури бази (CREATE TABLE, CREATE INDEX)."),
    ("EmailStr", "Тип Pydantic для перевірки формату адреси електронної пошти."),
    ("FK", "Foreign Key; зовнішній ключ — посилання на первинний ключ іншої таблиці, яке перевіряє SQLite при PRAGMA foreign_keys=ON."),
    ("HMAC", "Hash-based Message Authentication Code; код автентифікації на основі хеш-функції, тут — псевдовипадкова функція всередині PBKDF2."),
    ("JSON", "JavaScript Object Notation; текстовий формат запитів і відповідей API."),
    ("KDF", "Key Derivation Function; функція виведення ключа, тут — витратне обчислення парольного запису."),
    ("OWASP", "Open Worldwide Application Security Project; джерело настанов щодо зберігання паролів."),
    ("PBKDF2", "Password-Based Key Derivation Function 2; функція виведення ключа з пароля з керованою кількістю ітерацій."),
    ("PRAGMA", "Службова команда SQLite для налаштування з'єднання, напр. foreign_keys."),
    ("RESTRICT", "Дія зовнішнього ключа, що забороняє видаляти батьківський запис, на який є посилання."),
    ("SecretStr", "Тип Pydantic, що приховує значення у звичайному поданні моделі; не шифрує його в пам'яті."),
    ("SQL", "Structured Query Language; мова запитів до реляційної бази."),
    ("SQLite", "Вбудована реляційна база даних в одному файлі; тут var/digital-dean.sqlite3."),
    ("UNIQUE", "Обмеження унікальності значення колонки (email, login)."),
    ("UTF-8", "Unicode Transformation Format 8 bit; явне кодування пароля в байти перед PBKDF2."),
    ("Автентифікація", "Підтвердження, що особа володіє заявленим логіном (перевірка пароля)."),
    ("Авторизація", "Рішення, які дії дозволені автентифікованій особі; у цій роботі ще не реалізована."),
    ("Відкат (rollback)", "Скасування всіх змін незавершеної транзакції."),
    ("Ідемпотентність", "Властивість операції давати той самий стан при повторі (повторне блокування)."),
    ("Параметризований запит", "SQL зі сталою структурою, куди значення передаються окремо через «?», а не вклеюються в текст."),
    ("Парольний запис", "Збережене значення pbkdf2_sha256$600000$<hex>, з якого не можна прочитати пароль."),
    ("Сіль", "Випадкові 16 байтів для кожного запису; робить однакові паролі різними записами, не є секретним ключем."),
    ("Статус", "Стан облікового запису: inactive, active, blocked."),
    ("Роль", "Категорія повноважень у довіднику role; наявність ролі ще не означає перевірки прав."),
    ("Транзакція", "Група змін, що виконується повністю або не виконується зовсім."),
]


def versions() -> list[tuple[str, str]]:
    def pkg(name):
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:
            return "не встановлено"
    return [("Python", sys.version.split()[0]), ("SQLite (бібліотека)", sqlite3.sqlite_version),
            ("FastAPI", pkg("fastapi")), ("Pydantic", pkg("pydantic")),
            ("email-validator", pkg("email-validator")), ("Uvicorn", pkg("uvicorn")),
            ("pytest", pkg("pytest"))]


def lookup_counts() -> str:
    with open_database(DB_PATH) as con:
        status = [tuple(r) for r in con.execute("SELECT id, name FROM status ORDER BY id")]
        role = [tuple(r) for r in con.execute("SELECT id, name FROM role ORDER BY id")]
    ok = status == list(STATUS_ROWS) and role == list(ROLE_ROWS)
    return f"status: {len(status)} рядки, role: {len(role)} рядки, збіг з фіксованими значеннями: {'так' if ok else 'НІ'}"


def salt_demo() -> str:
    first, salt1 = passwords.make_password_record("Learning only 05!")
    second, salt2 = passwords.make_password_record("Learning only 05!")
    return (f"для однакового синтетичного пароля сіль 1 починається з `{salt1[:6]}…`, сіль 2 — з "
            f"`{salt2[:6]}…`; записи різні: **{'так' if first != second else 'ні'}**; обидва перевіряються: "
            f"**{'так' if passwords.verify_password('Learning only 05!', first, salt1) and passwords.verify_password('Learning only 05!', second, salt2) else 'ні'}**")


def build(args) -> str:
    live = json.loads((ROOT / "results" / "practice-05" / "live-check.json").read_text(encoding="utf-8"))
    out = []
    w = out.append
    w("# Звіт до практичної роботи 5: зберігання користувачів і захист паролів у SQLite\n")
    w("## Мета та власний результат\n")
    w("- Студент: Саверський Денис Миколайович, група 233 (online), номер у списку 17.")
    w(f"- Форк: {FORK}; гілка `practice-05`; теги `practice-05-base` (імпорт каркаса) і `practice-05` (фінальний стан).")
    w("- Мета: додати до того самого API «Цифровий деканат» постійне сховище SQLite з шістьма таблицями та "
      "життєвий цикл облікового запису — реєстрацію, фізичне видалення, блокування й перевірку входу з "
      "паролем, захищеним PBKDF2. Версію API оновлено до 0.5.0; маршрути практичних 1–4 збережено.\n")
    w("| Файл | Власна зміна |\n|---|---|")
    w("| `app/db/initialize.py` | `initialize_database`: каталог `var/`, усі DDL окремо і параметризовані довідники в одній транзакції, звірка точних рядків, ValueError і відкат за невідповідності |")
    w("| `app/security/passwords.py` | `make_password_record`, `verify_password`: фіксований профіль, обмежений строгий розбір до KDF, `compare_digest` |")
    w("| `app/repositories/user_repository.py` | `register_user`, `delete_user`, `block_user`, `login` — окреме коротке з'єднання на операцію, параметризований SQL, транзакції |")
    w("| `app/api/accounts.py`, `app/main.py` | чотири маршрути з кодами й безпечними detail, підключення до наявного `app`, версія 0.5.0 |")
    w("| `var/.gitignore` | робоча база та її допоміжні файли не потрапляють у Git |")
    w("| `tests/test_practice05_own.py` | власні негативні, транзакційні, збій/зайнятість бази, перезапуск процесу, OpenAPI, регресії |")
    w("| `postman/…practice-05…`, `examples/practice_05_live_check.py` | колекція Postman і та сама послідовність для живого сервера з перезапусками |\n")

    w("## Середовище та база\n")
    w("| Компонент | Версія |\n|---|---|")
    for name, version in versions():
        w(f"| {name} | {version} |")
    w("")
    w("| Таблиця | Колонки | Ключі й обмеження |\n|---|---|---|")
    w("| status | id, name | PK id ∈ {0,1,2}; name NOT NULL UNIQUE |")
    w("| user | id, name, email, login, password, salt, status_id | PK id; email, login UNIQUE; login `[a-z][a-z0-9_.-]{2,31}`; status_id NOT NULL DEFAULT 0 → status ON DELETE RESTRICT |")
    w("| role | id, name | PK id > 0; name NOT NULL UNIQUE |")
    w("| user_role | user_id, role_id | PK (user_id, role_id); user_id → user ON DELETE CASCADE; role_id → role RESTRICT |")
    w("| course | id, name | PK id > 0; непорожня назва |")
    w("| grade | student_id, teacher_id, course_id, grade | PK (student_id, course_id); обидва user-посилання й course — RESTRICT; CHECK typeof=integer і 0..100 |\n")
    w("Довідники: status — 0 inactive, 1 active, 2 blocked; role — 1 admin, 2 manager, 3 teacher, 4 student. "
      "`PRAGMA foreign_keys=ON` вмикається й перевіряється на кожному з'єднанні до `BEGIN`.\n")
    w(f"Повторна ініціалізація робочої бази: {args.init_check}. Після цього — {lookup_counts()}. "
      "Наявні користувачі, ролі, курси й оцінки не видаляються (перевіряє також pytest на тимчасових базах). "
      "Файл бази до звіту не долучено.\n")

    w("## Захист паролів\n")
    w("Профіль: PBKDF2-HMAC-SHA256, 600000 ітерацій, 16 випадкових байтів солі (`secrets.token_bytes`), "
      "32 байти результату. Поле `password` — `pbkdf2_sha256$600000$<64 lowercase hex>`, поле `salt` — "
      "32 lowercase hex. Пароль кодується строго в UTF-8 без обрізання пробілів і зміни регістру; для "
      "реєстрації 15–128 символів, ≤ 512 байтів, без нульового символу.\n")
    w("`verify_password` спершу перевіряє точну довжину, префікс із назвою алгоритму й числом 600000 і "
      "lowercase hex результату та солі. Будь-який інший формат (інший алгоритм, 1 або 999999999999 ітерацій, "
      "неправильний hex чи довжина, надмірний рядок) дає `false` **до** запуску PBKDF2 — це перевіряє тест, "
      "що підміняє KDF на функцію з помилкою. Далі — той самий KDF і `hmac.compare_digest`. Для невідомого "
      "логіна виконується одна фіктивна перевірка, щоб час був ближчим до хибного пароля (це не повний захист "
      "від переліку логінів).\n")
    w(f"Демонстрація без дампу облікових даних: {salt_demo()}.\n")
    w("Межі: OWASP для нових систем насамперед рекомендує Argon2id; PBKDF2 тут — навчальний профіль стандартної "
      "бібліотеки. Сіль не захищає від добору пароля за викраденою базою, лише від спільного попереднього обчислення.\n")

    w("## Реалізація API\n")
    w("| Функція | Метод і шлях | Успіх | Відмови |\n|---|---|---|---|")
    w("| register_user | POST /api/v1/users | 201, UserPublic | 409 user already exists; 422; 500 database unavailable |")
    w("| delete_user | DELETE /api/v1/users/{user_id} | 204 без тіла | 404 user not found; 409 user has grade references; 422; 500 |")
    w("| block_user | PATCH /api/v1/users/{user_id}/block | 200, UserPublic зі status_id=2 | 404; 422; 500 |")
    w("| login | POST /api/v1/auth/login | 200, JSON true/false | 422; 500 |\n")
    w("UserPublic містить лише id, name, email, login, status_id. Помилки валідації нових маршрутів очищує "
      "`SensitiveRoute` (без input/ctx і пароля). `login` повертає true лише для правильного пароля **і** "
      "status_id = 1; невідомий логін, хибний пароль, inactive, blocked і пошкоджений запис — false. "
      "`delete_user` в одній транзакції перевіряє існування, посилання grade як студента або викладача і "
      "виконує DELETE; за оцінками — 409 і повний відкат, user_role зберігається. Без оцінок user_role "
      "видаляє CASCADE. Повторне блокування — 200 і той самий стан; інші поля не змінюються.\n")
    w("```python\nwith open_database(self.database_path) as con, write_transaction(con):\n"
      "    if con.execute('SELECT 1 FROM \"user\" WHERE id = ?', (user_id,)).fetchone() is None:\n"
      "        raise UserNotFound()\n"
      "    if con.execute(\"SELECT 1 FROM grade WHERE student_id = ? OR teacher_id = ? LIMIT 1\",\n"
      "                   (user_id, user_id)).fetchone() is not None:\n"
      "        raise UserReferenced()\n"
      "    con.execute('DELETE FROM \"user\" WHERE id = ?', (user_id,))\n```\n")

    w("## Перевірки\n")
    w(f"- `pytest` (усі тести, на тимчасових базах `tmp_path`, без зменшення ітерацій PBKDF2): `{args.pytest_final}`.")
    w("- Власні тести: повторна ініціалізація з курсами/оцінками/ролями, відкат синтетичного збою DDL, зайвий рядок довідника, "
      "обмеження user/user_role/grade без HTTP (у т.ч. спорідненість SQLite: текст \"90\" зберігається як INTEGER), "
      "різні солі в базі, пошкоджений запис без KDF, пробіли/регістр/Unicode пароля, усі статуси при реєстрації, "
      "додаткові 422 без input/ctx, блокування змінює лише статус, 409 для студента й викладача з повним збереженням, "
      "контрольовані 404, неправильна форма тіла login, SQL-подібні логіни, безпечний 500 за збою та за зайнятого "
      "сховища без часткового запису, сталість у новому процесі Python, OpenAPI без password/salt, регресії 1–4.")
    w(f"- Живий сервер (`examples/practice_05_live_check.py`, робоча база, 127.0.0.1:8765): "
      f"**{live['passed']}/{live['total']}** перевірок, {live['created_at']}.\n")
    w("| Перевірка | Результат |\n|---|---|")
    for c in live["checks"]:
        w(f"| {c['name']} | {'пройдено' if c['passed'] else 'НЕ пройдено'} |")
    w("")
    w("Кроки R1–R6 — сталість після перезапуску процесу сервера з тим самим файлом: login true після першого "
      "перезапуску, після блокування й другого перезапуску — false. Колекція Postman "
      "`postman/digital-dean-practice-05.postman_collection.json` містить ту саму послідовність 01–19 "
      "(перевіряє коди, булевий тип, сталі id і точний набір полів); у звіті наведено результат автоматичного "
      "прогону цієї послідовності скриптом, а не знімок Postman.\n")

    w("## Історія Git\n")
    w("Гілка `practice-05` створена від власного тегу `practice-04` (`git merge-base --is-ancestor practice-04 HEAD` успішна); "
      "baseline — `practice-05-base`. Власні коміти після baseline:\n")
    w("```text\n" + args.git_log_file.read_text(encoding="utf-8-sig").strip() + "\n```\n")
    w(f"Гігієна: {args.hygiene}\n")

    w("## Висновки та межі застосування\n")
    w("- Дані зберігаються між перезапусками, але база SQLite не шифрується: доступ до файлу й копій треба обмежувати.")
    w("- Відкритий пароль не зберігається; у базі лише версіонований запис PBKDF2 і сіль.")
    w("- Роль не дорівнює статусу; зовнішній ключ grade перевіряє існування користувача, але не його роль.")
    w("- Булевий login не створює сесії й не авторизує адміністративні методи; delete_user і block_user не мають "
      "авторизації, тому сервер лише локальний (127.0.0.1).")
    w("- Вибір status_id=1 клієнтом під час реєстрації — навчальне спрощення, непридатне для публічної реєстрації.\n")

    w("## Офіційні джерела\n")
    w("Дата звернення: 9 листопада 2026 року.\n")
    for i, s in enumerate(SOURCES, 1):
        w(f"[{i}] {s}  ")
    w("\n## Глосарій\n")
    for term, text in sorted(GLOSSARY, key=lambda x: (not x[0][0].isascii(), x[0].lower())):
        w(f"- **{term}.** {text}")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Practice 5 report")
    parser.add_argument("--pytest-final", required=True)
    parser.add_argument("--git-log-file", type=Path, required=True)
    parser.add_argument("--init-check", required=True)
    parser.add_argument("--hygiene", required=True)
    args = parser.parse_args(argv)
    target = ROOT / "docs" / "practice-05-report.md"
    target.write_text(build(args), encoding="utf-8")
    print("Звіт:", target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
