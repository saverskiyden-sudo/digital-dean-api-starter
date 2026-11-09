# Звіт до практичної роботи 5: зберігання користувачів і захист паролів у SQLite

## Мета та власний результат

- Студент: Саверський Денис Миколайович, група 233 (online), номер у списку 17.
- Форк: https://github.com/saverskiyden-sudo/digital-dean-api-starter; гілка `practice-05`; теги `practice-05-base` (імпорт каркаса) і `practice-05` (фінальний стан).
- Мета: додати до того самого API «Цифровий деканат» постійне сховище SQLite з шістьма таблицями та життєвий цикл облікового запису — реєстрацію, фізичне видалення, блокування й перевірку входу з паролем, захищеним PBKDF2. Версію API оновлено до 0.5.0; маршрути практичних 1–4 збережено.

| Файл | Власна зміна |
|---|---|
| `app/db/initialize.py` | `initialize_database`: каталог `var/`, усі DDL окремо і параметризовані довідники в одній транзакції, звірка точних рядків, ValueError і відкат за невідповідності |
| `app/security/passwords.py` | `make_password_record`, `verify_password`: фіксований профіль, обмежений строгий розбір до KDF, `compare_digest` |
| `app/repositories/user_repository.py` | `register_user`, `delete_user`, `block_user`, `login` — окреме коротке з'єднання на операцію, параметризований SQL, транзакції |
| `app/api/accounts.py`, `app/main.py` | чотири маршрути з кодами й безпечними detail, підключення до наявного `app`, версія 0.5.0 |
| `var/.gitignore` | робоча база та її допоміжні файли не потрапляють у Git |
| `tests/test_practice05_own.py` | власні негативні, транзакційні, збій/зайнятість бази, перезапуск процесу, OpenAPI, регресії |
| `postman/…practice-05…`, `examples/practice_05_live_check.py` | колекція Postman і та сама послідовність для живого сервера з перезапусками |

## Середовище та база

| Компонент | Версія |
|---|---|
| Python | 3.13.16 |
| SQLite (бібліотека) | 3.50.4 |
| FastAPI | 0.162.0 |
| Pydantic | 2.14.2 |
| email-validator | 2.3.0 |
| Uvicorn | 0.54.0 |
| pytest | 9.2.0 |

| Таблиця | Колонки | Ключі й обмеження |
|---|---|---|
| status | id, name | PK id ∈ {0,1,2}; name NOT NULL UNIQUE |
| user | id, name, email, login, password, salt, status_id | PK id; email, login UNIQUE; login `[a-z][a-z0-9_.-]{2,31}`; status_id NOT NULL DEFAULT 0 → status ON DELETE RESTRICT |
| role | id, name | PK id > 0; name NOT NULL UNIQUE |
| user_role | user_id, role_id | PK (user_id, role_id); user_id → user ON DELETE CASCADE; role_id → role RESTRICT |
| course | id, name | PK id > 0; непорожня назва |
| grade | student_id, teacher_id, course_id, grade | PK (student_id, course_id); обидва user-посилання й course — RESTRICT; CHECK typeof=integer і 0..100 |

Довідники: status — 0 inactive, 1 active, 2 blocked; role — 1 admin, 2 manager, 3 teacher, 4 student. `PRAGMA foreign_keys=ON` вмикається й перевіряється на кожному з'єднанні до `BEGIN`.

Повторна ініціалізація робочої бази: python -m app.db.initialize виконано двічі поспіль без помилок. Після цього — status: 3 рядки, role: 4 рядки, збіг з фіксованими значеннями: так. Наявні користувачі, ролі, курси й оцінки не видаляються (перевіряє також pytest на тимчасових базах). Файл бази до звіту не долучено.

## Захист паролів

Профіль: PBKDF2-HMAC-SHA256, 600000 ітерацій, 16 випадкових байтів солі (`secrets.token_bytes`), 32 байти результату. Поле `password` — `pbkdf2_sha256$600000$<64 lowercase hex>`, поле `salt` — 32 lowercase hex. Пароль кодується строго в UTF-8 без обрізання пробілів і зміни регістру; для реєстрації 15–128 символів, ≤ 512 байтів, без нульового символу.

`verify_password` спершу перевіряє точну довжину, префікс із назвою алгоритму й числом 600000 і lowercase hex результату та солі. Будь-який інший формат (інший алгоритм, 1 або 999999999999 ітерацій, неправильний hex чи довжина, надмірний рядок) дає `false` **до** запуску PBKDF2 — це перевіряє тест, що підміняє KDF на функцію з помилкою. Далі — той самий KDF і `hmac.compare_digest`. Для невідомого логіна виконується одна фіктивна перевірка, щоб час був ближчим до хибного пароля (це не повний захист від переліку логінів).

Демонстрація без дампу облікових даних: для однакового синтетичного пароля сіль 1 починається з `3d6533…`, сіль 2 — з `a66e55…`; записи різні: **так**; обидва перевіряються: **так**.

Межі: OWASP для нових систем насамперед рекомендує Argon2id; PBKDF2 тут — навчальний профіль стандартної бібліотеки. Сіль не захищає від добору пароля за викраденою базою, лише від спільного попереднього обчислення.

## Реалізація API

| Функція | Метод і шлях | Успіх | Відмови |
|---|---|---|---|
| register_user | POST /api/v1/users | 201, UserPublic | 409 user already exists; 422; 500 database unavailable |
| delete_user | DELETE /api/v1/users/{user_id} | 204 без тіла | 404 user not found; 409 user has grade references; 422; 500 |
| block_user | PATCH /api/v1/users/{user_id}/block | 200, UserPublic зі status_id=2 | 404; 422; 500 |
| login | POST /api/v1/auth/login | 200, JSON true/false | 422; 500 |

UserPublic містить лише id, name, email, login, status_id. Помилки валідації нових маршрутів очищує `SensitiveRoute` (без input/ctx і пароля). `login` повертає true лише для правильного пароля **і** status_id = 1; невідомий логін, хибний пароль, inactive, blocked і пошкоджений запис — false. `delete_user` в одній транзакції перевіряє існування, посилання grade як студента або викладача і виконує DELETE; за оцінками — 409 і повний відкат, user_role зберігається. Без оцінок user_role видаляє CASCADE. Повторне блокування — 200 і той самий стан; інші поля не змінюються.

```python
with open_database(self.database_path) as con, write_transaction(con):
    if con.execute('SELECT 1 FROM "user" WHERE id = ?', (user_id,)).fetchone() is None:
        raise UserNotFound()
    if con.execute("SELECT 1 FROM grade WHERE student_id = ? OR teacher_id = ? LIMIT 1",
                   (user_id, user_id)).fetchone() is not None:
        raise UserReferenced()
    con.execute('DELETE FROM "user" WHERE id = ?', (user_id,))
```

## Перевірки

- `pytest` (усі тести, на тимчасових базах `tmp_path`, без зменшення ітерацій PBKDF2): `619 passed, 0 failed, 0 skipped in 36.80s`.
- Власні тести: повторна ініціалізація з курсами/оцінками/ролями, відкат синтетичного збою DDL, зайвий рядок довідника, обмеження user/user_role/grade без HTTP (у т.ч. спорідненість SQLite: текст "90" зберігається як INTEGER), різні солі в базі, пошкоджений запис без KDF, пробіли/регістр/Unicode пароля, усі статуси при реєстрації, додаткові 422 без input/ctx, блокування змінює лише статус, 409 для студента й викладача з повним збереженням, контрольовані 404, неправильна форма тіла login, SQL-подібні логіни, безпечний 500 за збою та за зайнятого сховища без часткового запису, сталість у новому процесі Python, OpenAPI без password/salt, регресії 1–4.
- Живий сервер (`examples/practice_05_live_check.py`, робоча база, 127.0.0.1:8765): **25/25** перевірок, 2026-11-09T09:44:20+00:00.

| Перевірка | Результат |
|---|---|
| 01 health 200 | пройдено |
| 02 register default -> 201, inactive, public fields only | пройдено |
| 03 login inactive -> false | пройдено |
| 04 register active -> 201, integer id | пройдено |
| 05 login active -> true | пройдено |
| 06 wrong password -> false | пройдено |
| 07 unknown login -> false | пройдено |
| 08 duplicate login -> 409 | пройдено |
| 09 duplicate email (other case) -> 409 | пройдено |
| 10 extra field -> 422 without input echo | пройдено |
| 11 status_id as string -> 422 | пройдено |
| 12 block -> 200, status 2, same id | пройдено |
| 13 block -> 200, status 2, same id | пройдено |
| 14 login blocked -> false | пройдено |
| 15 delete -> 204 with empty body | пройдено |
| 16 login deleted -> false | пройдено |
| 17 repeat delete -> 404 | пройдено |
| 18 block deleted -> 404 | пройдено |
| 19 delete own inactive record -> 204 | пройдено |
| R1 register restart user (active) | пройдено |
| R2 login before restart -> true | пройдено |
| R3 after server restart: login -> true | пройдено |
| R4 block restart user -> 200 | пройдено |
| R5 after second restart: login -> false | пройдено |
| R6 cleanup: delete restart user -> 204 | пройдено |

Кроки R1–R6 — сталість після перезапуску процесу сервера з тим самим файлом: login true після першого перезапуску, після блокування й другого перезапуску — false. Колекція Postman `postman/digital-dean-practice-05.postman_collection.json` містить ту саму послідовність 01–19 (перевіряє коди, булевий тип, сталі id і точний набір полів); у звіті наведено результат автоматичного прогону цієї послідовності скриптом, а не знімок Postman.

## Історія Git

Гілка `practice-05` створена від власного тегу `practice-04` (`git merge-base --is-ancestor practice-04 HEAD` успішна); baseline — `practice-05-base`. Власні коміти після baseline:

```text
931efef Initialize six-table SQLite database atomically and repeatably
e331c86 Add PBKDF2 password records and persistent user repository
26fbbf9 Add account routes to the existing app and bump API to 0.5.0
f6b4c1a Add practice 5 tests, Postman collection, live check and report tool
```

Гігієна: git ls-files не містить файлів SQLite (*.sqlite3, -wal, -shm, -journal) чи .env; var/ версіонує лише .gitignore.

## Висновки та межі застосування

- Дані зберігаються між перезапусками, але база SQLite не шифрується: доступ до файлу й копій треба обмежувати.
- Відкритий пароль не зберігається; у базі лише версіонований запис PBKDF2 і сіль.
- Роль не дорівнює статусу; зовнішній ключ grade перевіряє існування користувача, але не його роль.
- Булевий login не створює сесії й не авторизує адміністративні методи; delete_user і block_user не мають авторизації, тому сервер лише локальний (127.0.0.1).
- Вибір status_id=1 клієнтом під час реєстрації — навчальне спрощення, непридатне для публічної реєстрації.

## Офіційні джерела

Дата звернення: 9 листопада 2026 року.

[1] Python 3.13, sqlite3 — DB-API 2.0 interface for SQLite databases. https://docs.python.org/3/library/sqlite3.html  
[2] SQLite Foreign Key Support. https://www.sqlite.org/foreignkeys.html  
[3] SQLite CREATE TABLE (constraints). https://www.sqlite.org/lang_createtable.html  
[4] SQLite Datatypes (type affinity). https://www.sqlite.org/datatype3.html  
[5] SQLite Transactions (BEGIN IMMEDIATE). https://www.sqlite.org/lang_transaction.html  
[6] SQLite UPSERT (ON CONFLICT DO NOTHING). https://www.sqlite.org/lang_upsert.html  
[7] SQLite ON CONFLICT clause / REPLACE. https://www.sqlite.org/lang_conflict.html  
[8] Python 3.13, hashlib.pbkdf2_hmac. https://docs.python.org/3/library/hashlib.html#hashlib.pbkdf2_hmac  
[9] Python 3.13, secrets. https://docs.python.org/3/library/secrets.html  
[10] Python 3.13, hmac.compare_digest. https://docs.python.org/3/library/hmac.html#hmac.compare_digest  
[11] OWASP Password Storage Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html  
[12] NIST SP 800-132 Recommendation for Password-Based Key Derivation. https://csrc.nist.gov/pubs/sp/800/132/final  
[13] OWASP Authentication Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html  
[14] FastAPI, Response Model. https://fastapi.tiangolo.com/tutorial/response-model/  
[15] FastAPI, Handling Errors. https://fastapi.tiangolo.com/tutorial/handling-errors/  
[16] FastAPI, Custom Request and APIRoute class. https://fastapi.tiangolo.com/how-to/custom-request-and-route/  
[17] FastAPI, Testing Dependencies with Overrides. https://fastapi.tiangolo.com/advanced/testing-dependencies/  
[18] Pydantic, Types: SecretStr, EmailStr; Strict Mode. https://docs.pydantic.dev/latest/api/types/  
[19] pytest, tmp_path fixture. https://docs.pytest.org/en/stable/how-to/tmp_path.html  
[20] Postman, Write scripts to test API response data. https://learning.postman.com/docs/tests-and-scripts/write-scripts/test-scripts/  
[21] Git, merge. https://git-scm.com/docs/git-merge  
[22] Git, tag. https://git-scm.com/docs/git-tag  
[23] GitHub, Fork a repository. https://docs.github.com/en/pull-requests/how-tos/work-with-forks/fork-a-repo  

## Глосарій

- **API.** Application Programming Interface; прикладний програмний інтерфейс — HTTP-маршрути того самого застосунку FastAPI.
- **BEGIN IMMEDIATE.** Початок транзакції SQLite з одразу захопленим правом запису; разом із COMMIT/ROLLBACK обрамлює багатокрокову зміну.
- **CASCADE.** Дія зовнішнього ключа: під час видалення батьківського запису видаляються залежні рядки (тут лише user_role).
- **compare_digest.** Функція hmac для порівняння байтів без раннього виходу на першій відмінності.
- **DDL.** Data Definition Language; мова визначення структури бази (CREATE TABLE, CREATE INDEX).
- **EmailStr.** Тип Pydantic для перевірки формату адреси електронної пошти.
- **FK.** Foreign Key; зовнішній ключ — посилання на первинний ключ іншої таблиці, яке перевіряє SQLite при PRAGMA foreign_keys=ON.
- **HMAC.** Hash-based Message Authentication Code; код автентифікації на основі хеш-функції, тут — псевдовипадкова функція всередині PBKDF2.
- **JSON.** JavaScript Object Notation; текстовий формат запитів і відповідей API.
- **KDF.** Key Derivation Function; функція виведення ключа, тут — витратне обчислення парольного запису.
- **OWASP.** Open Worldwide Application Security Project; джерело настанов щодо зберігання паролів.
- **PBKDF2.** Password-Based Key Derivation Function 2; функція виведення ключа з пароля з керованою кількістю ітерацій.
- **PRAGMA.** Службова команда SQLite для налаштування з'єднання, напр. foreign_keys.
- **RESTRICT.** Дія зовнішнього ключа, що забороняє видаляти батьківський запис, на який є посилання.
- **SecretStr.** Тип Pydantic, що приховує значення у звичайному поданні моделі; не шифрує його в пам'яті.
- **SQL.** Structured Query Language; мова запитів до реляційної бази.
- **SQLite.** Вбудована реляційна база даних в одному файлі; тут var/digital-dean.sqlite3.
- **UNIQUE.** Обмеження унікальності значення колонки (email, login).
- **UTF-8.** Unicode Transformation Format 8 bit; явне кодування пароля в байти перед PBKDF2.
- **Автентифікація.** Підтвердження, що особа володіє заявленим логіном (перевірка пароля).
- **Авторизація.** Рішення, які дії дозволені автентифікованій особі; у цій роботі ще не реалізована.
- **Відкат (rollback).** Скасування всіх змін незавершеної транзакції.
- **Параметризований запит.** SQL зі сталою структурою, куди значення передаються окремо через «?», а не вклеюються в текст.
- **Парольний запис.** Збережене значення pbkdf2_sha256$600000$<hex>, з якого не можна прочитати пароль.
- **Роль.** Категорія повноважень у довіднику role; наявність ролі ще не означає перевірки прав.
- **Статус.** Стан облікового запису: inactive, active, blocked.
- **Сіль.** Випадкові 16 байтів для кожного запису; робить однакові паролі різними записами, не є секретним ключем.
- **Транзакція.** Група змін, що виконується повністю або не виконується зовсім.
- **Ідемпотентність.** Властивість операції давати той самий стан при повторі (повторне блокування).
