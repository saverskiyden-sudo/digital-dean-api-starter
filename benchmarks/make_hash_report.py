"""Збирає docs/practice-04-report.md із власного results/practice-04 і Git.

    python -m benchmarks.make_hash_report --pytest-final "..." --git-log-file log.txt

Усі числа обчислюються з report.json, raw.csv та avalanche.csv;
жодних вимірювань у тексті не вигадано.
"""
import argparse
import csv
import json
from pathlib import Path
from statistics import median

from app.schemas.hash_report import filter_by_payload, validate_report
from app.security.hashing.profiles import PAYLOAD_SIZES, PROFILES
from benchmarks.make_hash_charts import LABELS, SIZE_LABEL

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "practice-04"
OUTPUT = ROOT / "docs" / "practice-04-report.md"
FORK = "https://github.com/saverskiyden-sudo/digital-dean-api-starter"

SOURCES = [
    "Python 3.12, hashlib. https://docs.python.org/3.12/library/hashlib.html",
    "NIST FIPS 180-4 Secure Hash Standard. https://csrc.nist.gov/pubs/fips/180-4/upd1/final",
    "NIST FIPS 202 SHA-3 Standard. https://csrc.nist.gov/pubs/fips/202/final",
    "RFC 7693 BLAKE2. https://www.rfc-editor.org/rfc/rfc7693.html",
    "NIST Hash Functions. https://csrc.nist.gov/projects/hash-functions",
    "RFC 6151 Updated Security Considerations for MD5. https://www.rfc-editor.org/rfc/rfc6151.html",
    "Python 3.12, time.perf_counter_ns. https://docs.python.org/3.12/library/time.html#time.perf_counter_ns",
    "Python 3.12, statistics. https://docs.python.org/3.12/library/statistics.html",
    "Python 3.12, json. https://docs.python.org/3.12/library/json.html",
    "FastAPI, Response Model. https://fastapi.tiangolo.com/tutorial/response-model/",
    "FastAPI, Handling Errors. https://fastapi.tiangolo.com/tutorial/handling-errors/",
    "FastAPI, Testing. https://fastapi.tiangolo.com/tutorial/testing/",
    "Pydantic, Strict Mode. https://pydantic.dev/docs/validation/latest/concepts/strict_mode/",
    "Git, merge. https://git-scm.com/docs/git-merge",
    "Git, tag. https://git-scm.com/docs/git-tag",
    "GitHub, Fork a repository. https://docs.github.com/en/pull-requests/how-tos/work-with-forks/fork-a-repo",
    "Postman, Write scripts to test API response data. https://learning.postman.com/docs/tests-and-scripts/write-scripts/test-scripts/",
    "OWASP Password Storage Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    "Python 3.12, ssl.OPENSSL_VERSION. https://docs.python.org/3.12/library/ssl.html#ssl.OPENSSL_VERSION",
    "PyCryptodome, BLAKE2b. https://pycryptodome.readthedocs.io/en/latest/src/hash/blake2b.html",
    "PyCryptodome, BLAKE2s. https://pycryptodome.readthedocs.io/en/latest/src/hash/blake2s.html",
    "RFC 1321 The MD5 Message-Digest Algorithm (test suite). https://www.rfc-editor.org/rfc/rfc1321.html",
    "RFC 6234 US Secure Hash Algorithms (reference code and tests). https://www.rfc-editor.org/rfc/rfc6234.html",
]

GLOSSARY = [
    ("API", "Application Programming Interface; прикладний програмний інтерфейс — тут HTTP-маршрути того самого застосунку FastAPI."),
    ("BLAKE2b / BLAKE2s", "Сімейство хеш-функцій BLAKE2 (RFC 7693); у роботі з явно заданим digest_size=32, а не обрізанням довшого результату."),
    ("chunked", "Поблоковий спосіб: послідовні update блоками до 16384 байтів і один digest."),
    ("CSV", "Comma Separated Values; значення, розділені комами — формат сирих даних raw.csv та avalanche.csv."),
    ("digest", "Дайджест, контрольне значення — байти результату хешування для точного профілю й повідомлення."),
    ("FIPS", "Federal Information Processing Standards; федеральні стандарти обробки інформації США (FIPS 180-4, FIPS 202)."),
    ("hashlib", "Стандартний модуль Python із конструкторами хеш-функцій."),
    ("HMAC", "Hash-based Message Authentication Code; код автентифікації повідомлення з секретним ключем — у роботу не входить."),
    ("IQR", "Interquartile Range; міжквартильний розмах Q3−Q1 п'яти середніх часів серій (метод inclusive)."),
    ("JSON", "JavaScript Object Notation; текстовий формат звіту й відповіді API."),
    ("MD5", "Message Digest Algorithm 5; 128-бітовий застарілий профіль, лише для навчального порівняння."),
    ("MiB/s", "Мебібайти за секунду; 1 МіБ = 1048576 байтів."),
    ("NIST", "National Institute of Standards and Technology; Національний інститут стандартів і технологій США."),
    ("OpenSSL", "Криптографічна бібліотека; openssl_ssl у звіті — версія бібліотеки модуля ssl Python."),
    ("OWASP", "Open Worldwide Application Security Project; джерело настанов щодо зберігання паролів."),
    ("RFC", "Request for Comments; серія технічних публікацій Інтернету."),
    ("SHA", "Secure Hash Algorithm; алгоритм безпечного хешування — сімейства SHA-1, SHA-2, SHA-3."),
    ("source_commit", "SHA зафіксованого коду перед експериментом; предок фінального тегу practice-04."),
    ("UTC", "Coordinated Universal Time; всесвітній координований час — основа created_at."),
    ("UTF-8", "Unicode Transformation Format 8 bit; явне кодування тексту в байти перед хешуванням."),
    ("whole", "Цілісний спосіб: новий стан, один update усіма байтами та digest."),
    ("XOR", "Exclusive OR; виключне АБО — побітова операція для підрахунку відмінних бітів."),
    ("Відстань Геммінга", "Кількість відмінних бітів двох рівнодовгих хешів, а не відмінних символів hex."),
    ("Колізія", "Збіг хешів двох різних повідомлень; існування збігів не означає практичної легкості їх знаходження."),
    ("Лавинний ефект", "Значна зміна бітів результату після малої зміни входу; спостереження не доводить стійкості."),
    ("Медіана", "Центральне значення впорядкованої вибірки; тут третє з п'яти середніх часів серій."),
    ("Прогрів", "10 повних операцій перед серіями; не входять у сирі вимірювання."),
    ("Прообраз", "Повідомлення, що дає заданий хеш; другий прообраз — інше повідомлення з хешем заданого."),
    ("Серія", "Окреме вимірювання 1000 (або 100 для 1 МіБ) повторів; середній час серії — одне спостереження."),
    ("Синтетичні дані", "Штучні публічні байти без реальних відомостей і персональних даних."),
    ("Стан хешування", "Об'єкт обробки одного повідомлення; для кожного повідомлення створюється новий."),
]


def _rows(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _us(ns: float) -> str:
    return f"{ns / 1000:.2f}"


def build(report: dict, raw: list[dict], avalanche_rows: list[dict],
          pytest_final: str, git_log: str) -> str:
    env, par = report["environment"], report["parameters"]
    available = [a for a in report["algorithms"] if a["available"]]
    unavailable = [a for a in report["algorithms"] if not a["available"]]
    a = len(available)
    failed = [c for c in report["checks"] if not c["passed"]]
    res = {(r["algorithm"], r["mode"], r["payload_bytes"]): r for r in report["results"]}

    # Узгодженість сирих даних і агрегатів (перевіряється під час генерації).
    for (alg, mode, size), r in res.items():
        series = sorted(float(x["ns_per_op"]) for x in raw
                        if (x["algorithm"], x["mode"], int(x["payload_bytes"])) == (alg, mode, size))
        if len(series) != 5 or abs(median(series) - r["median_ns"]) > 1e-6 * r["median_ns"]:
            raise RuntimeError(f"raw.csv does not match report.json for {alg}/{mode}/{size}")
    for x in raw:
        if abs(int(x["elapsed_ns"]) / int(x["repeats"]) - float(x["ns_per_op"])) > 1e-6 * float(x["ns_per_op"]):
            raise RuntimeError("raw.csv arithmetic mismatch")

    out = []
    w = out.append
    w("# Звіт із практичної роботи 4: дослідження алгоритмів хешування\n")
    w("## Відомості\n")
    w("- Студент: Саверський Денис Миколайович, група 233 (online), номер у списку 17.")
    w("- Індивідуальний варіант: 17 mod 4 = **1** — параметр `payload_bytes`.")
    w(f"- Дата експерименту (UTC): {report['created_at']}.")
    w(f"- Форк: {FORK}; гілка `practice-04`; теги `practice-04-base` і `practice-04`.")
    w(f"- `source_commit`: `{report['source_commit']}` (зафіксований код до запуску; предок тегу `practice-04`).\n")

    w("## Мета і реалізовані зміни\n")
    w("Мета — дослідити швидкодію, коректність і лавинний ефект семи профілів хешування "
      "та повернути перевірений звіт новим методом того самого API «Цифровий деканат». "
      "Гілка `practice-04` продовжує тег `practice-03`; до неї злито `upstream/practice-04-starter` "
      "(baseline — тег `practice-04-base`). Маршрути практичних 1–3 збережено, версію API оновлено до 0.4.0.\n")
    w("| Модуль | Зміна |\n|---|---|")
    w("| `app/security/hashing/adapters.py` | `prepare_operation` (перевірка входу й нарізання блоків поза таймером, новий стан на кожен виклик), `hash_bytes` (whole/chunked), `hamming_bits` |")
    w("| `app/schemas/hash_report.py` | `validate_report`: покриття матриці, унікальність, статуси недоступності, UTC-дата, довжини, повтори, формула пропускної здатності, межі лавинного досліду, перевірки; `filter_by_payload` для варіанта |")
    w("| `app/api/hash_lab.py` | новий `GET /api/v1/lab/crypto/hash-benchmark-results` з `response_model=HashResponse` і параметром `payload_bytes` |")
    w("| `app/main.py`, `pyproject.toml` | підключення маршрутизатора до наявного застосунку, версія 0.4.0 |")
    w("| `benchmarks/hash_benchmark.py` | експеримент: прогрів, 5 серій, raw.csv, 6 перевірок, лавинний дослід, avalanche.csv, report.json |")
    w("| `benchmarks/make_hash_charts.py`, `make_hash_report.py` | графіки й цей звіт з власних даних |")
    w("| `tests/test_hash_variant.py`, Postman | власні тести варіанта, звіту, сирих даних, HTTP і регресій; змінна `variant`=1 |\n")
    w("**Індивідуальний варіант 1.** Необов'язковий параметр запиту `payload_bytes` (тип `int`) "
      "з явною перевіркою переліку 64, 1024, 65536, 1048576. Без параметра повертаються всі "
      f"{8 * a} результатів; з параметром — по {2 * a} (усі доступні профілі × whole/chunked). "
      "Значення 65, 0, від'ємні, 1048577 та нечислові дають 422. Спочатку весь файл перевіряється як "
      "`HashReport`, потім фільтрується лише `results`; `algorithms`, `avalanche` і `checks` лишаються повними.\n")
    w("```python\nif payload_bytes is not None and payload_bytes not in PAYLOAD_SIZES:\n"
      "    raise HTTPException(422, \"unsupported payload_bytes\")\n"
      "return filter_by_payload(load_report(), payload_bytes)\n```\n")

    w("## Середовище і методика\n")
    w("| Параметр | Значення |\n|---|---|")
    for key, label in (("python", "Python"), ("os", "ОС"), ("cpu", "Процесор"),
                       ("architecture", "Архітектура"), ("openssl_ssl", "OpenSSL модуля ssl")):
        w(f"| {label} | {env[key]} |")
    w("")
    w("| Профіль | Конструктор | Довжина, байтів | Доступність | Реалізація |\n|---|---|---|---|---|")
    ctor = {"sha256": "sha256()", "sha512": "sha512()", "sha3-256": "sha3_256()",
            "blake2b-256": "blake2b(digest_size=32)", "blake2s-256": "blake2s(digest_size=32)",
            "md5": "md5(usedforsecurity=False)", "sha1": "sha1(usedforsecurity=False)"}
    for s in report["algorithms"]:
        state = "доступний" if s["available"] else f"недоступний ({s['reason']})"
        w(f"| {s['algorithm']} | `{ctor[s['algorithm']]}` | {PROFILES[s['algorithm']].digest_bytes} | "
          f"{state} | `{s['implementation']}` |")
    w("")
    if unavailable:
        w("Недоступні профілі збережено зі статусом без вимірювань і перевірок.\n")
    w(f"Розміри: {', '.join(str(x) for x in par['sizes'])} байтів; способи whole та chunked "
      f"(блоки {par['chunk_bytes']} байтів); прогрів {par['warmup']} операцій на поєднання; "
      f"{par['series']} серій по {par['repeats_small']} повторів (по {par['repeats_large']} для 1 МіБ). "
      "Серії чергуються між усіма поєднаннями, щоб розподілити вплив фонового навантаження. "
      "У таймер входять створення нового об'єкта, `update`, `digest` і цикл повторів; генерація "
      "синтетичних байтів, нарізання блоків, прогрів, перевірки, hex, JSON і файли — поза таймером. "
      "Годинник `time.perf_counter_ns`. Медіана й IQR — для п'яти середніх часів серій "
      "(`statistics.quantiles(..., method=\"inclusive\")`), пропускна здатність "
      "v = S·10⁹ / (2²⁰·t_m) МіБ/с. Вимір містить накладні витрати Python, тому для малих "
      "повідомлень він показує передусім вартість виклику, а не криптопримітиву.\n")
    w("Лавинний дослід: ті самі 1024 синтетичні байти для всіх профілів; у досліді i (i = 0..99) "
      "у новій копії оригіналу змінюється біт i (байт i//8, маска 1<<(i%8)); відстань Геммінга "
      "рахується між бітами хешів, частка a = d/n.\n")

    w("## Результати\n")
    w(f"Файли: `results/practice-04/raw.csv` ({len(raw)} рядків без заголовка), "
      f"`results/practice-04/avalanche.csv` ({len(avalanche_rows)} рядків), `results/practice-04/report.json` "
      f"({len(report['results'])} агрегатів, {len(report['avalanche'])} лавинних агрегатів, "
      f"{len(report['checks'])} перевірок). Узгодженість raw.csv з медіанами report.json і "
      "арифметику elapsed_ns/repeats перевірено під час створення цього звіту.\n")
    w("#### Медіана часу однієї операції, мкс (IQR), спосіб whole\n")
    w("| Профіль | " + " | ".join(SIZE_LABEL[s] for s in PAYLOAD_SIZES) + " |")
    w("|---|" + "---|" * len(PAYLOAD_SIZES))
    for s in available:
        alg = s["algorithm"]
        w(f"| {LABELS[alg]} | " + " | ".join(
            f"{_us(res[(alg, 'whole', z)]['median_ns'])} ({_us(res[(alg, 'whole', z)]['iqr_ns'])})"
            for z in PAYLOAD_SIZES) + " |")
    w("\n#### Пропускна здатність, МіБ/с (whole / chunked)\n")
    w("| Профіль | " + " | ".join(SIZE_LABEL[s] for s in PAYLOAD_SIZES) + " |")
    w("|---|" + "---|" * len(PAYLOAD_SIZES))
    for s in available:
        alg = s["algorithm"]
        w(f"| {LABELS[alg]} | " + " | ".join(
            f"{res[(alg, 'whole', z)]['throughput_mib_s']:.1f} / {res[(alg, 'chunked', z)]['throughput_mib_s']:.1f}"
            for z in PAYLOAD_SIZES) + " |")
    w("\n#### Лавинний дослід (1024 байти, 100 одиничних змін)\n")
    w("| Профіль | Біт хешу | Мін | Макс | Середнє | Середня частка |\n|---|---|---|---|---|---|")
    for x in report["avalanche"]:
        w(f"| {LABELS[x['algorithm']]} | {x['digest_bits']} | {x['min_flipped_bits']} | "
          f"{x['max_flipped_bits']} | {x['mean_flipped_bits']:.2f} | {x['mean_fraction']:.4f} |")
    w("\nГрафіки (джерело — report.json):\n")
    w("![Пропускна здатність](../results/practice-04/throughput.svg)\n")
    w("![Відношення chunked / whole](../results/practice-04/chunked_vs_whole.svg)\n")
    w("![Лавинний дослід](../results/practice-04/avalanche.svg)\n")

    w("Спостереження (обчислено з даних цього запуску):\n")
    for size in (64, 1048576):
        ranked = sorted(available, key=lambda s: res[(s["algorithm"], "whole", size)]["median_ns"])
        best, worst = ranked[0]["algorithm"], ranked[-1]["algorithm"]
        ratio = res[(worst, "whole", size)]["median_ns"] / res[(best, "whole", size)]["median_ns"]
        w(f"- {SIZE_LABEL[size]}, whole: найменша медіана у {LABELS[best]} "
          f"({_us(res[(best, 'whole', size)]['median_ns'])} мкс), найбільша у {LABELS[worst]} "
          f"({_us(res[(worst, 'whole', size)]['median_ns'])} мкс), різниця ≈ {ratio:.2f} раза.")
    ratios = [res[(s["algorithm"], "chunked", z)]["median_ns"] / res[(s["algorithm"], "whole", z)]["median_ns"]
              for s in available for z in PAYLOAD_SIZES]
    w(f"- Відношення chunked/whole лежить у межах {min(ratios):.2f}–{max(ratios):.2f}: "
      "поблокова обробка дає той самий хеш (перевірка stream-equivalence), а різниця в часі — "
      "це накладні витрати додаткових викликів `update` і шум вимірювання.")
    small = {s["algorithm"]: res[(s["algorithm"], "whole", 64)]["throughput_mib_s"] for s in available}
    large = {s["algorithm"]: res[(s["algorithm"], "whole", 1048576)]["throughput_mib_s"] for s in available}
    w(f"- Пропускна здатність на 64 байтах ({min(small.values()):.0f}–{max(small.values()):.0f} МіБ/с) "
      f"значно нижча, ніж на 1 МіБ ({min(large.values()):.0f}–{max(large.values()):.0f} МіБ/с): "
      "для коротких повідомлень домінує стала вартість створення об'єкта й викликів Python.")
    fr = [x["mean_fraction"] for x in report["avalanche"]]
    w(f"- Середня частка змінених бітів для всіх профілів {min(fr):.3f}–{max(fr):.3f}, тобто близько половини, "
      "зокрема й для MD5/SHA-1. Це спостереження не є доказом стійкості до колізій.\n")
    w("Ранжування стосується лише цього комп'ютера, цих версій Python/OpenSSL і розмірів; "
      "на іншій машині порядок може змінитися.\n")

    w("## API та перевірки\n")
    w("Контракт `GET /api/v1/lab/crypto/hash-benchmark-results`: `200` — перевірений `HashResponse` "
      "(діагностичні `passed=false` не приховуються); `404` — `{\"detail\": \"hash report not found\"}`; "
      "`500` — `{\"detail\": \"hash report invalid\"}` без шляхів і трасування; `422` — неприйнятний "
      "`payload_bytes`. Читання обмежене 1 МіБ + 1 байт, повторні ключі JSON, NaN та Infinity відхиляються. "
      "Маршрут не запускає вимірювань, не приймає шляхів, документів чи паролів.\n")
    sample = filter_by_payload(validate_report(report), 1024).model_dump()
    sample = {"schema_version": sample["schema_version"], "created_at": sample["created_at"],
              "source_commit": sample["source_commit"],
              "algorithms": [f"... ({len(sample['algorithms'])})"],
              "results": sample["results"][:1] + [f"... (ще {len(sample['results']) - 1})"],
              "avalanche": [f"... ({len(sample['avalanche'])})"],
              "checks": [f"... ({len(sample['checks'])})"], "summary": sample["summary"]}
    w("Приклад відповіді `?payload_bytes=1024` (початок, з власного звіту):\n")
    w("```json\n" + json.dumps(sample, ensure_ascii=False, indent=2) + "\n```\n")
    w(f"- `pytest`: `{pytest_final}`.")
    w("- Власні тести (`tests/test_hash_variant.py`): варіант (усі чотири розміри, 65/0/від'ємні/1048577/нечислові → 422, "
      "повна перевірка до фільтра, збереження `passed=false`), дата UTC (+00:00/Z, інший пояс, неіснуюча дата, майбутнє), "
      "пропущені й зайві записи, непослідовні статуси недоступності, NaN/Infinity/рядкові числа/bool, точні bytes, "
      "BLAKE2 не є обрізаним BLAKE2b-512, арифметика raw.csv і avalanche.csv, відсутність локальних шляхів у JSON, "
      "відмова експерименту на незафіксованому коді, відсутність імпорту `benchmarks` у маршруті, регресії практичних 1–3.")
    w("- Postman: `postman/digital-dean-practice-04.postman_collection.json`, `variant` = 1; виконуються 01, 02, 03B, 04B, "
      "до 03B додано власну перевірку повноти `algorithms/avalanche/checks`; ручні стани `missing`/`invalid` — окремо.")
    w(f"- Перевірки коректності: {len(report['checks'])}, невдалих {len(failed)}"
      + ("." if not failed else ": " + ", ".join(f"{c['algorithm']}/{c['name']}" for c in failed) + ".") + "\n")

    w("## Історія Git\n")
    w("Гілка `practice-04` створена від тега `practice-03` (`git merge-base --is-ancestor practice-03 HEAD` успішна), "
      "baseline — `practice-04-base`. Власні коміти після baseline:\n")
    w("```text\n" + git_log.strip() + "\n```\n")
    w("`source_commit` зі звіту є предком фінального тегу `practice-04`; результати додано окремим комітом.\n")

    w("## Висновки та межі\n")
    w("- Швидкість, правильність і криптографічні властивості розглянуто окремо. Числа часу — властивість цього "
      "комп'ютера, реалізацій hashlib/OpenSSL і накладних витрат Python, а не алгоритмів узагалі.")
    w("- Усі доступні профілі пройшли відомі вектори, Unicode, детермінованість, довжину й еквівалентність whole/chunked."
      if not failed else "- Частина перевірок не пройшла; звіт збережено для діагностики.")
    w("- Лавинний дослід охоплює лише 100 позицій одного повідомлення; частка близько 0,5 не доводить стійкості. "
      "MD5 і SHA-1 мають відомі практичні колізійні атаки (RFC 6151, NIST) і використані лише навчально.")
    w("- Хеш підтверджує збіг точних байтів з еталоном лише тоді, коли сам еталон отримано довіреним каналом; "
      "інакше порушник може замінити і файл, і контрольне значення.")
    w("- Швидкий хеш (навіть із сіллю) не є достатнім захистом паролів: для них потрібні спеціальні повільні схеми (OWASP).")
    w("- Обмеження: один запуск на одному комп'ютері; HMAC, підписи й паролі не досліджувались; API навчальний, локальний, без автентифікації.\n")

    w("## Використані джерела\n")
    w("Дата звернення: 23 жовтня 2026 року (за переліком завдання).\n")
    for i, s in enumerate(SOURCES, 1):
        w(f"[{i}] {s}  ")
    w("\n## Алфавітний глосарій\n")
    for term, text in GLOSSARY:
        w(f"- **{term}.** {text}")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Practice 4 report")
    parser.add_argument("--pytest-final", required=True)
    parser.add_argument("--git-log-file", type=Path, required=True)
    parser.add_argument("--results-dir", type=Path, default=RESULTS)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    report = json.loads((args.results_dir / "report.json").read_text(encoding="utf-8"))
    validate_report(report)
    text = build(report, _rows(args.results_dir / "raw.csv"),
                 _rows(args.results_dir / "avalanche.csv"), args.pytest_final,
                 args.git_log_file.read_text(encoding="utf-8-sig"))
    args.output.write_text(text, encoding="utf-8")
    print("Звіт:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
