"""Збирає docs/practice-03-report.md з report.json і відомостей про Git.

    python -m benchmarks.make_asymmetric_report --pytest-final "..." ...

Числа й висновки про швидкість обчислюються з results/practice-03/report.json;
жодних вимірювань у тексті не вигадано.
"""
import argparse
import json
from pathlib import Path

from app.schemas.asymmetric_report import validate_complete_report
from app.security.asymmetric.profiles import PROFILES
from benchmarks.make_asymmetric_charts import KEY_LABELS, LABELS, SIZE_LABEL, summary_markdown

SOURCES = [
    "RFC 8017 PKCS 1 v2.2, розділ 7.1 RSAES-OAEP. https://www.rfc-editor.org/rfc/rfc8017.html",
    "RFC 9180 Hybrid Public Key Encryption, розділи 4, 5, 7, 9. https://www.rfc-editor.org/rfc/rfc9180.html",
    "RFC 7748 Elliptic Curves for Security. https://www.rfc-editor.org/rfc/rfc7748.html",
    "RFC 5869 HKDF. https://www.rfc-editor.org/rfc/rfc5869.html",
    "cryptography 48, RSA. https://cryptography.io/en/48.0.0/hazmat/primitives/asymmetric/rsa/",
    "cryptography 48, Hybrid Public Key Encryption. https://cryptography.io/en/48.0.0/hazmat/primitives/hpke/",
    "cryptography 48, Authenticated encryption. https://cryptography.io/en/48.0.0/hazmat/primitives/aead/",
    "cryptography 48, Elliptic curve cryptography. https://cryptography.io/en/48.0.0/hazmat/primitives/asymmetric/ec/",
    "cryptography 48, X25519. https://cryptography.io/en/48.0.0/hazmat/primitives/asymmetric/x25519/",
    "Python 3.12, time.perf_counter_ns. https://docs.python.org/3.12/library/time.html#time.perf_counter_ns",
    "Python 3.12, statistics. https://docs.python.org/3.12/library/statistics.html",
    "Python 3.12, json. https://docs.python.org/3.12/library/json.html",
    "Pydantic, Models. https://docs.pydantic.dev/latest/concepts/models/",
    "FastAPI, Response Model. https://fastapi.tiangolo.com/tutorial/response-model/",
    "FastAPI, Handling Errors. https://fastapi.tiangolo.com/tutorial/handling-errors/",
    "FastAPI, Testing. https://fastapi.tiangolo.com/tutorial/testing/",
    "Postman, test scripts. https://learning.postman.com/docs/tests-and-scripts/write-scripts/test-scripts/",
    "Git, merge. https://git-scm.com/docs/git-merge",
    "Git, tag. https://git-scm.com/docs/git-tag",
    "GitHub, Fork a repository. https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo",
    "cryptography 48, Serialization. https://cryptography.io/en/48.0.0/hazmat/primitives/asymmetric/serialization/",
    "Python 3.12, secrets. https://docs.python.org/3.12/library/secrets.html",
]

GLOSSARY = [
    ("AAD", "Additional Authenticated Data; додаткові автентифіковані дані: перевіряються на цілісність разом із шифротекстом, але не шифруються."),
    ("AEAD", "Authenticated Encryption with Associated Data; автентифіковане шифрування з асоційованими даними."),
    ("AES", "Advanced Encryption Standard; розширений стандарт шифрування, симетричний блоковий шифр."),
    ("API", "Application Programming Interface; прикладний програмний інтерфейс, тут HTTP-маршрути FastAPI."),
    ("Base mode", "Базовий режим HPKE без автентифікації відправника."),
    ("CSV", "Comma Separated Values; текстовий табличний формат значень, розділених комами."),
    ("DER", "Distinguished Encoding Rules; канонічне двійкове кодування ASN.1."),
    ("DHKEM", "Diffie–Hellman Key Encapsulation Mechanism; інкапсуляція ключа на основі Діффі–Геллмана."),
    ("enc", "Дані інкапсуляції ключа в HPKE: серіалізований ефемерний відкритий ключ."),
    ("GCM", "Galois/Counter Mode; режим автентифікованого шифрування, додає 16-байтовий тег."),
    ("HKDF", "HMAC-based Extract-and-Expand Key Derivation Function; функція виведення ключів на основі HMAC."),
    ("HPKE", "Hybrid Public Key Encryption; гібридне шифрування з відкритим ключем (RFC 9180): KEM + KDF + AEAD."),
    ("info", "Контекстний параметр HPKE, що входить до побудови ключового контексту."),
    ("IQR", "Interquartile Range; міжквартильний розмах Q3−Q1, міра розкиду п'яти значень."),
    ("KDF", "Key Derivation Function; функція виведення ключів."),
    ("KEM", "Key Encapsulation Mechanism; механізм інкапсуляції ключа."),
    ("label", "Мітка OAEP: контекстні байти, які мають збігатися при шифруванні та розшифруванні."),
    ("MGF1", "Mask Generation Function 1; функція генерації маски в OAEP."),
    ("MiB/s", "Мебібайти за секунду (2^20 байтів), а не десяткові мегабайти."),
    ("nonce", "Number used once; одноразове значення, у AES-GCM 12 байтів, яке не повторюється з тим самим ключем."),
    ("OAEP", "Optimal Asymmetric Encryption Padding; випадкове доповнення для RSA-шифрування."),
    ("P-256", "Еліптична крива secp256r1; у роботі застосовується всередині DHKEM HPKE."),
    ("RSA", "Rivest–Shamir–Adleman; асиметричний алгоритм; тут RSAES-OAEP для коротких даних або ключа AES."),
    ("SHA-256", "Secure Hash Algorithm; хеш-функція з 256-бітовим результатом."),
    ("SPKI", "SubjectPublicKeyInfo; структура відкритого ключа, довжину якої вимірювали у DER."),
    ("Suite", "Об'єкт набору алгоритмів HPKE в cryptography (KEM, KDF, AEAD)."),
    ("UTC", "Coordinated Universal Time; всесвітній координований час."),
    ("X25519", "Функція узгодження ключів на Curve25519 (RFC 7748); у роботі використовується всередині HPKE."),
    ("Асиметричне шифрування", "Шифрування відкритим ключем одержувача й розшифрування його приватним ключем; не тотожне цифровому підпису."),
    ("Гібридне шифрування", "Асиметричний захист ключового матеріалу разом із симетричним шифруванням самого повідомлення."),
    ("Двійковий конверт", "Послідовність байтів результату шифрування; довжину вимірюють без JSON чи Base64."),
    ("Медіана", "Центральне значення впорядкованої вибірки; тут медіана п'яти середніх часів серій."),
    ("Прогрів", "Попередні операції для стабілізації середовища; не входять у сирі вимірювання."),
    ("Синтетичні дані", "Штучні повідомлення без реальних персональних даних."),
    ("Тег автентифікації", "16 байтів AEAD для виявлення неправильного ключа чи змін у даних."),
    ("Шифротекст", "Результат шифрування відкритого тексту."),
]


def _by(report):
    return {(r.profile, r.operation, r.payload_bytes): r for r in report.results}


def _us(ns: float) -> float:
    return ns / 1000.0


def findings(report) -> list[str]:
    """Спостереження, обчислені з даних; кожне формулювання перевіряється кодом."""
    out = []
    keys = {k.key_profile: k for k in report.key_generation}
    out.append(
        f"Генерація RSA-2048 тривала {_us(keys['rsa-2048'].median_ns):.1f} мкс, RSA-3072 — "
        f"{_us(keys['rsa-3072'].median_ns):.1f} мкс, X25519 — {_us(keys['x25519'].median_ns):.1f} мкс, "
        f"P-256 — {_us(keys['p256'].median_ns):.1f} мкс (медіани п'яти незалежних вимірювань). "
        f"RSA-3072 генерується приблизно у {keys['rsa-3072'].median_ns / keys['rsa-2048'].median_ns:.1f} раза "
        f"довше за RSA-2048; найшвидша з чотирьох операцій — "
        f"{KEY_LABELS[min(keys, key=lambda k: keys[k].median_ns)]}."
    )
    table = _by(report)
    for profile in ("rsa2048-oaep", "rsa3072-oaep"):
        enc, dec = table[(profile, "encrypt", 64)], table[(profile, "decrypt", 64)]
        direction = "довше" if dec.median_ns > enc.median_ns else "коротше"
        out.append(
            f"{LABELS[profile]}, 64 байти: шифрування {_us(enc.median_ns):.1f} мкс, розшифрування "
            f"{_us(dec.median_ns):.1f} мкс; розшифрування триває {direction} у "
            f"{max(dec.median_ns, enc.median_ns) / min(dec.median_ns, enc.median_ns):.1f} раза."
        )
    hybrid = [p for p, spec in PROFILES.items() if spec.group == "hybrid"]
    for operation in ("encrypt", "decrypt"):
        for size in (1024, 65536, 1048576):
            ranked = sorted(hybrid, key=lambda p: table[(p, operation, size)].median_ns)
            best, second = table[(ranked[0], operation, size)], table[(ranked[1], operation, size)]
            overlap = (second.median_ns - best.median_ns) <= (best.iqr_ns + second.iqr_ns) / 2
            note = ("різниця з наступним профілем не перевищує розкиду серій, тому перевагу не стверджуємо"
                    if overlap else
                    f"наступний профіль повільніший приблизно у {second.median_ns / best.median_ns:.2f} раза")
            out.append(
                f"{operation}, {SIZE_LABEL[size]}: найменша медіана у профілю {LABELS[ranked[0]]} "
                f"({_us(best.median_ns):.1f} мкс); {note}."
            )
    return out


def render(report, args) -> str:
    created = report.experiment.created_at_utc
    env = report.environment
    sample = filter_example(report)
    sources = "\n".join(f"[{i}] {text}" for i, text in enumerate(SOURCES, start=1))
    glossary = "\n".join(f"- **{term}.** {text}" for term, text in sorted(GLOSSARY, key=lambda t: t[0].lower()))
    notes = "\n".join(f"- {line}" for line in findings(report))
    failed = [c for c in report.checks if not c.passed]
    commits = args.commits.strip() or "(немає)"
    return f"""# Звіт практичної роботи 3: асиметричне та гібридне шифрування

## Титульні відомості

- Студент: Саверський Денис Миколайович, група 233 (online), номер у списку 17.
- Індивідуальний варіант: 17 mod 4 = **1** («Необов'язковий `payload_bytes`»).
- Дата: {args.date}.
- Форк: {args.remote}; гілка `practice-03`; теги `practice-03-base` і `practice-03`.
- SHA останньої фіксації коду й тестів: `{args.final_sha}`; SHA коду під час експерименту: `{report.experiment.source_commit}`. Тег `practice-03` позначає фінальний коміт, який додає результати експерименту й цей звіт.

## Мета та продовження API

Це продовження того самого API «Цифровий деканат» (маршрути практичних 1 і 2 збережено). Гілка `practice-03` створена від тега `practice-02`, до неї злито `upstream/practice-03-starter` (базовий стан позначає тег `practice-03-base`).

- Тести перед імпортом (практична 2): `{args.pytest_before}`.
- Тести практичних 1 і 2 одразу після імпорту стартера: `{args.pytest_after_import}`.
- Повний набір після реалізації: `{args.pytest_final}`.

Змінені модулі: `app/security/asymmetric` (профілі, адаптери), `app/schemas/asymmetric_report.py` (семантична перевірка й фільтр), `app/api/asymmetric_lab.py` (новий маршрут), `app/main.py` (підключення, версія 0.3.0), `benchmarks/asymmetric_benchmark.py`, `benchmarks/make_asymmetric_charts.py`, `benchmarks/make_asymmetric_report.py`, тести, колекція Postman. Новий маршрут `GET /api/v1/lab/crypto/asymmetric-benchmark-results` лише читає збережений звіт і перевіряє його; експеримент із HTTP не запускається.

## Середовище та методика

| Параметр | Значення |
|---|---|
| Python | {env.python} |
| cryptography | {env.cryptography} |
| OpenSSL бібліотеки | {env.openssl} |
| ОС | {env.os} |
| CPU | {env.cpu} |
| Час створення звіту (UTC) | {created} |
| Код під час запуску | `{report.experiment.source_commit}` |

Усі вимірювання виконано на одному комп'ютері в одному процесі; профіль часу: 10 прогрівальних операцій, 5 серій по 20 операцій, 5 незалежних вимірювань генерації кожного типу ключа. Ключі одержувача створюються поза таймером. Перед кожною серією порядок 22 комбінацій циклічно зсувається на одну позицію (базовий порядок: профілі за таблицею 1, для кожного операція encrypt, потім decrypt, розміри за зростанням). Усередині таймера: для шифрування — виклик `encrypt` (у гібриді це свіжий ключ AES, nonce, OAEP-шифрування ключа й AES-GCM; у HPKE увесь `Suite.encrypt`); для розшифрування — тільки 20 викликів `decrypt` над заздалегідь підготовленими коректними конвертами. Перевірка відновлених даних, серіалізація DER, запис файлів і JSON — поза таймером. Годинник `time.perf_counter_ns`.

Статистика: час однієї операції в серії `t_r = Δt_r / N`, N = 20; `median_ns` — медіана п'яти `t_r`; IQR = Q3−Q1 методом `statistics.quantiles(..., method="inclusive")`; пропускна здатність гібридних профілів `v = S · 10^9 / (2^20 · t_m)` МіБ/с, для прямих RSA не обчислюється.

## Коректність і параметри

Профілі: `rsa2048-oaep`, `rsa3072-oaep` (SHA-256 в OAEP і MGF1, e = 65537, 64 байти), навчальний `rsa3072-oaep-aes256gcm` та два профілі HPKE Base (`DHKEM(X25519, HKDF-SHA256)` і `DHKEM(P-256, HKDF-SHA256)`, HKDF-SHA256, AES-256-GCM) для 1024, 65536 і 1048576 байтів. Використано тільки бібліотечні операції: власних примітивів, raw RSA, PKCS#1 v1.5 чи власного KDF немає.

Межа OAEP: `m_max = k − 2·hLen − 2` дає 190 байтів для RSA-2048 і 318 байтів для RSA-3072; перевірка `oaep_boundary` підтверджує успіх на `m_max` і відмову на `m_max + 1`.

Ключові фрагменти адаптера (навчальний гібрид; свіжі ключ AES і nonce для кожного повідомлення):

```python
key = AESGCM.generate_key(bit_length=256)
nonce = secrets.token_bytes(12)
wrapped = public.encrypt(key, _oaep(context))
return wrapped + nonce + AESGCM(key).encrypt(nonce, message, context)
```

Конверт: `wrapped_key[384] || nonce[12] || ciphertext_with_tag`. Для HPKE: `Suite(KEM.X25519 або KEM.P256, KDF.HKDF_SHA256, AEAD.AES_256_GCM).encrypt(message, public, info=context)`; результат `enc || ct` не перекодується. Розшифрування будь-якої відмови (невірний тег, ключ, контекст, довжина) повертає єдину помилку `DecryptionError` без часткового відкритого тексту.

Контекст `b"digital-dean:practice-03:report-v1"` передається по-різному: OAEP `label` (прямий RSA), OAEP `label` і AAD AES-GCM (гібрид), HPKE `info`. Це різні механізми, хоч значення збігаються. HPKE Base не автентифікує відправника: кожен, хто знає відкритий ключ, може створити повідомлення; те саме стосується RSA-профілів.

Перевірок коректності {len(report.checks)}: `roundtrip`, `wrong_key`, `tamper`, `wrong_context` для п'яти профілів і `oaep_boundary` для двох прямих RSA. Пройдено {len(report.checks) - len(failed)}, невдалих {len(failed)}{"." if not failed else ": " + ", ".join(f"{c.profile}/{c.name}" for c in failed) + "."}

## Результати

Файли: `results/practice-03/raw.csv` (130 рядків без заголовка: 20 генерацій ключа + 110 серій), `results/practice-03/report.json` (4 генерації, 22 результати, 22 перевірки), `results/practice-03/summary.md`.

{_shift_headings(summary_markdown(report))}
Графіки (джерело чисел — `report.json`; одиниці: мкс; відрізок — IQR):

![Гібридні профілі](../results/practice-03/time_hybrid.svg)

![Прямий RSA-OAEP](../results/practice-03/time_rsa_direct.svg)

![Генерація ключів і розмір відкритого ключа](../results/practice-03/key_generation.svg)

Спостереження (обчислено з даних; порівнюються лише однакові розміри й операції):

{notes}

Накладні витрати двійкового конверта сталі й не залежать від швидкості: RSA-3072 + AES-GCM — S + 412 байтів, HPKE X25519 — S + 48, HPKE P-256 — S + 81; прямі RSA дають 256 і 384 байти. Розмір відкритого ключа в DER: RSA-2048 — 294 байти, RSA-3072 — 422, X25519 — 44, P-256 — 91.

## API та індивідуальний варіант

Контракт: `200` повний валідний звіт (4 `key_generation`, 22 `results`, 22 `checks`); `404` `{{"detail": "benchmark report not found"}}`; `500` `{{"detail": "benchmark report invalid"}}` без шляху й стека; `422` для непідтримуваного `payload_bytes`. Модель відповіді `BenchmarkResponse`; повний файл спочатку проходить `validate_complete_report`, потім фільтруються лише `results`.

Варіант 1: необов'язковий параметр `payload_bytes` (тип `int`, явна перевірка переліку 64, 1024, 65536, 1048576). Для 64 повертається 4 результати, для кожного з інших значень по 6; `key_generation` і `checks` лишаються повними; інші значення дають `422`. Приклад відповіді `?payload_bytes=1024` (початок, із власного звіту):

```json
{sample}
```

HTTP-маршрут не імпортує й не викликає експеримент, не приймає шлях файлу чи алгоритм від клієнта (шлях `REPORT_PATH` задає лише сервер) і не повертає ключів, відкритих текстів, конвертів чи локальних шляхів.

## Перевірки

- `pytest`: `{args.pytest_final}`; власні тести: схема й семантика звіту (дублікати, покриття, довжини, формула пропускної здатності, NaN/Inf, типи, UTC, SHA), адаптери (довжини, підміна кожної області байтів, контекст, неправильні типи ключів, свіжість матеріалу), експеримент (параметри, зсув порядку, запис файлів, відсутність секретів), API (200/404/500/422, варіант, `false` у перевірках, відсутність запуску експерименту), регресії практичних 1 і 2.
- Postman: колекція `postman/digital-dean-practice-03.postman_collection.json`, змінна `variant` = 1; запити 01, 02, 03B, 04B виконуються, інші варіанти пропускаються; кроки 404/500 виконуються вручну на тимчасових файлах.
- Негативні результати не приховуються: `passed=false` зберігається у звіті й повертається API.

## Git

Віддалений репозиторій: `{args.remote}`. Власні коміти після `practice-03-base`:

```text
{commits}
```

Коміти імпорту та викладача не враховано. `practice-02` є предком `HEAD`; теги `practice-03-base` і `practice-03` опубліковано.

## Висновки та межі

- Швидкість, накладні витрати й коректність розглядаються окремо. Час у цьому експерименті є властивістю конкретної реалізації, версій бібліотеки та OpenSSL, процесора й навантаження; інший комп'ютер дасть інші числа.
- Прямий RSA-OAEP придатний лише для коротких даних (до 190 і 318 байтів); для довших повідомлень використовують гібридну схему, у якій асиметрична операція захищає лише ключ.
- HPKE Base — стандартизована композиція KEM, KDF й AEAD, яку реалізує бібліотечний `Suite`; навчальний RSA/AES-гібрид не є HPKE і має власний фіксований формат конверта.
- Ніякий профіль не названо «найкращим» чи криптографічно сильнішим лише за часом або довжиною ключа: довжини ключів RSA, AES і кривих мають різний зміст.
- Обмеження: один запуск на одному комп'ютері; HPKE Base і RSA не автентифікують відправника; відмова після пошкодження не замінює підпису чи автентифікації користувача; цифрові підписи, постквантові алгоритми, побічні канали й сертифікація реалізації не досліджувались; сервер навчальний, локальний, без автентифікації, TLS і керування ключами, тому його не можна відкривати назовні.

## Використані джерела

Перелік складено за списком джерел із завдання практичної роботи (дата звернення в завданні: 7 жовтня 2026 року).

{sources}

## Алфавітний глосарій

{glossary}
"""


def _shift_headings(text: str) -> str:
    return text.replace("### ", "#### ")


def filter_example(report) -> str:
    from app.schemas.asymmetric_report import filter_report

    body = json.loads(filter_report(report, 1024).model_dump_json())
    short = {
        "schema_version": body["schema_version"],
        "key_generation": ["... (4)"],
        "results": body["results"][:1] + ["... (ще 5)"],
        "checks": ["... (22)"],
    }
    return json.dumps(short, ensure_ascii=False, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Practice 3 report builder")
    parser.add_argument("--results-dir", type=Path, default=Path("results/practice-03"))
    parser.add_argument("--output", type=Path, default=Path("docs/practice-03-report.md"))
    parser.add_argument("--date", required=True)
    parser.add_argument("--remote", required=True)
    parser.add_argument("--final-sha", default="(буде вказано після фінальної фіксації)")
    parser.add_argument("--pytest-before", required=True)
    parser.add_argument("--pytest-after-import", required=True)
    parser.add_argument("--pytest-final", required=True)
    parser.add_argument("--commits-file", type=Path, default=None)
    args = parser.parse_args()
    data = json.loads((args.results_dir / "report.json").read_text(encoding="utf-8"))
    report = validate_complete_report(data)
    args.commits = args.commits_file.read_text(encoding="utf-8-sig") if args.commits_file else ""
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(report, args), encoding="utf-8")
    print("Звіт записано:", args.output)


if __name__ == "__main__":
    main()
