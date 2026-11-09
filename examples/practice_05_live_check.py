"""Локальна перевірка живого сервера практичної 5 (та сама послідовність, що в Postman)
та перевірка сталості після перезапуску процесу сервера.

    python -m app.db.initialize
    python examples/practice_05_live_check.py

Скрипт сам запускає uvicorn на 127.0.0.1:8765 з робочою базою
var/digital-dean.sqlite3, виконує запити, зупиняє й знову запускає сервер.
Облікові дані синтетичні й одноразові; хеші, солі та паролі не друкуються й не
записуються. Результат: results/practice-05/live-check.json.
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
OUT = ROOT / "results" / "practice-05" / "live-check.json"
PASSWORD = "Learning only 05!"
PUBLIC_KEYS = ["email", "id", "login", "name", "status_id"]


def request(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


class Server:
    def __enter__(self):
        self.process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
             "--port", str(PORT), "--log-level", "warning"],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                if request("GET", "/health")[0] == 200:
                    return self
            except OSError:
                pass
            time.sleep(0.2)
        self.process.kill()
        raise RuntimeError("server did not start")

    def __exit__(self, *exc):
        self.process.terminate()
        try:
            self.process.wait(10)
        except subprocess.TimeoutExpired:
            self.process.kill()


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    inactive_login, active_login = f"pm_inactive_{stamp}", f"pm_active_{stamp}"
    restart_login = f"pm_restart_{stamp}"
    checks = []

    def check(name, ok):
        checks.append({"name": name, "passed": bool(ok)})
        print(("OK   " if ok else "FAIL ") + name)

    def user(login, **extra):
        return {"name": "Навчальний користувач", "email": f"{login}@example.com",
                "login": login, "password": PASSWORD, **extra}

    def login(login_name, password=PASSWORD):
        status, raw = request("POST", "/api/v1/auth/login",
                              {"login": login_name, "password": password})
        return status, raw.decode("utf-8")

    with Server():
        status, raw = request("GET", "/health")
        check("01 health 200", status == 200)
        status, raw = request("POST", "/api/v1/users", user(inactive_login))
        inactive = json.loads(raw)
        check("02 register default -> 201, inactive, public fields only",
              status == 201 and sorted(inactive) == PUBLIC_KEYS and inactive["status_id"] == 0)
        check("03 login inactive -> false", login(inactive_login) == (200, "false"))
        status, raw = request("POST", "/api/v1/users", user(active_login, status_id=1))
        active = json.loads(raw)
        check("04 register active -> 201, integer id",
              status == 201 and type(active["id"]) is int and active["id"] > 0
              and sorted(active) == PUBLIC_KEYS)
        check("05 login active -> true", login(active_login) == (200, "true"))
        check("06 wrong password -> false", login(active_login, "Wrong password 05!") == (200, "false"))
        check("07 unknown login -> false", login(f"pm_unknown_{stamp}") == (200, "false"))
        status, _ = request("POST", "/api/v1/users", user(active_login, email=f"x{stamp}@example.com"))
        check("08 duplicate login -> 409", status == 409)
        status, _ = request("POST", "/api/v1/users",
                            user(f"pm_other_{stamp}", email=f"{active_login.upper()}@EXAMPLE.COM"))
        check("09 duplicate email (other case) -> 409", status == 409)
        status, raw = request("POST", "/api/v1/users", user(f"pm_extra_{stamp}", salt="client"))
        check("10 extra field -> 422 without input echo",
              status == 422 and b"client" not in raw and PASSWORD.encode() not in raw)
        status, _ = request("POST", "/api/v1/users", user(f"pm_bad_{stamp}", status_id="1"))
        check("11 status_id as string -> 422", status == 422)
        for attempt in ("12", "13"):
            status, raw = request("PATCH", f"/api/v1/users/{active['id']}/block")
            body = json.loads(raw)
            check(f"{attempt} block -> 200, status 2, same id",
                  status == 200 and body == {**active, "status_id": 2})
        check("14 login blocked -> false", login(active_login) == (200, "false"))
        status, raw = request("DELETE", f"/api/v1/users/{active['id']}")
        check("15 delete -> 204 with empty body", status == 204 and raw == b"")
        check("16 login deleted -> false", login(active_login) == (200, "false"))
        status, _ = request("DELETE", f"/api/v1/users/{active['id']}")
        check("17 repeat delete -> 404", status == 404)
        status, _ = request("PATCH", f"/api/v1/users/{active['id']}/block")
        check("18 block deleted -> 404", status == 404)
        status, raw = request("DELETE", f"/api/v1/users/{inactive['id']}")
        check("19 delete own inactive record -> 204", status == 204 and raw == b"")

        status, raw = request("POST", "/api/v1/users", user(restart_login, status_id=1))
        restart_user = json.loads(raw)
        check("R1 register restart user (active)", status == 201)
        check("R2 login before restart -> true", login(restart_login) == (200, "true"))
    with Server():
        check("R3 after server restart: login -> true", login(restart_login) == (200, "true"))
        status, _ = request("PATCH", f"/api/v1/users/{restart_user['id']}/block")
        check("R4 block restart user -> 200", status == 200)
    with Server():
        check("R5 after second restart: login -> false", login(restart_login) == (200, "false"))
        status, raw = request("DELETE", f"/api/v1/users/{restart_user['id']}")
        check("R6 cleanup: delete restart user -> 204", status == 204)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    passed = sum(c["passed"] for c in checks)
    OUT.write_text(json.dumps({
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "base_url": BASE, "database": "var/digital-dean.sqlite3 (not versioned)",
        "passed": passed, "total": len(checks), "checks": checks,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Live check: {passed}/{len(checks)} passed -> {OUT.relative_to(ROOT)}")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
