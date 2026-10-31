# Digital Dean API — стартовий проєкт

Цей репозиторій є стартовою кодовою базою наскрізного навчального проєкту «Цифровий деканат». Не створюйте окремий застосунок для наступної практичної роботи: розвивайте власний форк цього репозиторію і зберігайте сумісність реалізованих маршрутів.

## Отримання власного репозиторію

1. Відкрийте базовий репозиторій: <https://github.com/serhii-ch-eu/digital-dean-api-starter>.
2. Увійдіть у GitHub і натисніть **Fork**, щоб створити пов’язану копію у власному обліковому записі.
3. Клонуйте саме власний форк, замінивши `<login>` своїм логіном GitHub:

```bash
git clone https://github.com/<login>/digital-dean-api-starter.git digital-dean-api
cd digital-dean-api
```

4. Додайте базовий репозиторій як `upstream` і створіть робочу гілку:

```bash
git remote add upstream https://github.com/serhii-ch-eu/digital-dean-api-starter.git
git remote -v
git switch -c practice-01
```

Після цих команд `origin` має вказувати на ваш форк, а `upstream` — на базовий репозиторій викладача. Не надсилайте зміни безпосередньо до базового репозиторію.

## Підготовка середовища

```bash
python -m venv .venv
```

Активація в macOS або Linux:

```bash
source .venv/bin/activate
```

Активація в Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Інсталяція залежностей:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Запуск

```bash
python -m uvicorn app.main:app --reload
```

Перевірте:

- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/openapi.json`

## Тести

```bash
python -m pytest
```

На старті проходить лише перевірка `/health`. Реалізуйте схеми, репозиторій, маршрути та решту тестів відповідно до документа практичної роботи.

## Фіксація та публікація змін

Створіть щонайменше три змістові фіксації: окремо для каркаса моделей, маршрутів і перевірок. Додавайте до кожної фіксації лише пов’язані завершені зміни. Наприклад:

```bash
git add app/schemas tests
git commit -m "Implement student data models"

git add app/api app/repositories
git commit -m "Implement student API routes"

git add tests postman
git commit -m "Add API verification scenarios"
```

Після успішного виконання тестів опублікуйте гілку та фінальний тег у власному форку:

```bash
git push -u origin practice-01
git tag practice-01
git push origin tag practice-01
```

Для наступних практичних робіт продовжуйте розвивати цей самий форк та історію Git; не створюйте непов’язаний репозиторій.

## Правила роботи з даними

Використовуйте тільки вигадані записи. Не додавайте паролі, токени, приватні ключі, файли `.env` або реальні персональні дані до репозиторію.

## Практична робота 2: симетричне шифрування приміток

API доповнено захищеними службовими примітками студентів (AES-256-GCM, бібліотека `cryptography`) і дослідом продуктивності шести комбінацій «бібліотека × алгоритм» (`cryptography` та `pycryptodome`; AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305). Версія застосунку й пакета — `0.2.0`.

**Індивідуальний варіант 1 (номер 17, 17 mod 4 = 1): категорія примітки.** Поле `category` ∈ `general` (за замовчуванням), `academic`, `administrative` є в запиті, відповіді, внутрішньому конверті й автентифікованому контексті (AAD). Невідома категорія дає `422`; зміна збереженої категорії ламає перевірку тега, і читання повертає `500` без тексту.

### Нові маршрути (префікс `/api/v1`)

| Метод | Шлях | Успіх | Помилки |
|---|---|---|---|
| POST | `/students/{student_id}/secure-notes` | 201: `id`, `student_id`, `algorithm`, `category` | 404, 422, 503 |
| GET | `/students/{student_id}/secure-notes/{note_id}` | 200: те саме + перевірений `text` | 404, 422, 500 |
| GET | `/lab/crypto/benchmark-results` | 200: звіт `report.json` | 404, 500 |

Тіло POST: `{"text": "...", "category": "academic"}`; `category` необов'язкове. Клієнт не передає ключ, алгоритм, nonce чи тег. Помилки захисту: `500` і `503` мають тіло `{"detail": "Protected note unavailable"}`; звіт — `{"detail": "Benchmark results unavailable"}`.

Ключ і лічильник одноразових значень створюються один раз на процес і живуть лише в пам'яті; після перезапуску старі примітки недоступні. Запускайте **один** процес (без `--workers`) і не відкривайте API назовні: автентифікації немає.

### Встановлення, запуск і тести

```powershell
python -m pip install -e ".[dev]"
python -m uvicorn app.main:app --host 127.0.0.1
python -m pytest
```

Версії залежностей (`cryptography==48.0.1`, `pycryptodome==3.24.0`) задано в `pyproject.toml` і `requirements-practice-02.txt`.

### Вимірювання продуктивності

```powershell
python -m benchmarks.crypto_benchmark --output-dir results/practice-02
python -m benchmarks.make_charts --results-dir results/practice-02
```

Перша команда створює `raw.csv` (180 серій) і `report.json` (36 агрегатів) з описом середовища; друга будує `throughput_encrypt.svg`, `throughput_decrypt.svg` і `summary.md`. Під час вимірювання не запускайте інших важких програм. Звіт читається маршрутом `GET /api/v1/lab/crypto/benchmark-results`.

### Postman

Колекція `postman/digital-dean-practice-02.postman_collection.json` (15 запитів, `base_url` = `http://127.0.0.1:8000`): запустіть сервер, потім Runner. Крок 10 потребує локально створеного `report.json`.
