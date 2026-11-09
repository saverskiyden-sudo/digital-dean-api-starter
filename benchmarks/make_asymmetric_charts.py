"""Графіки та таблиця з report.json практичної 3 без сторонніх бібліотек (SVG).

    python -m benchmarks.make_asymmetric_charts --results-dir results/practice-03

Створює time_hybrid.svg, time_rsa_direct.svg, key_generation.svg і summary.md.
Числа беруться лише з report.json; нічого не вигадується.
"""
import argparse
import json
import math
from html import escape
from pathlib import Path

from app.schemas.asymmetric_report import validate_complete_report

HYBRID_COLORS = {
    "rsa3072-oaep-aes256gcm": "#d62728",
    "hpke-x25519-aes256gcm": "#1f77b4",
    "hpke-p256-aes256gcm": "#2ca02c",
}
LABELS = {
    "rsa2048-oaep": "RSA-2048 OAEP",
    "rsa3072-oaep": "RSA-3072 OAEP",
    "rsa3072-oaep-aes256gcm": "RSA-3072 OAEP + AES-256-GCM",
    "hpke-x25519-aes256gcm": "HPKE X25519 / HKDF-SHA256 / AES-256-GCM",
    "hpke-p256-aes256gcm": "HPKE P-256 / HKDF-SHA256 / AES-256-GCM",
}
KEY_LABELS = {"rsa-2048": "RSA-2048", "rsa-3072": "RSA-3072", "x25519": "X25519", "p256": "P-256"}
OPERATION_TITLE = {"encrypt": "Шифрування", "decrypt": "Розшифрування"}
SIZE_LABEL = {64: "64 Б", 1024: "1 КіБ", 65536: "64 КіБ", 1048576: "1 МіБ"}
FONT = "font-family='Arial, Helvetica, sans-serif'"


def _us(ns: float) -> float:
    return ns / 1000.0


def _text(x, y, content, size=12, anchor="middle", weight="normal", fill="#222", rotate=None):
    transform = f" transform='rotate({rotate} {x} {y})'" if rotate else ""
    return (f"<text x='{x:.1f}' y='{y:.1f}' font-size='{size}' text-anchor='{anchor}' "
            f"font-weight='{weight}' fill='{fill}' {FONT}{transform}>{escape(str(content))}</text>")


def _log_range(values: list[float]) -> tuple[float, float]:
    low = 10 ** math.floor(math.log10(min(values)))
    high = 10 ** math.ceil(math.log10(max(values)))
    return (low, high * 10) if low == high else (low, high)


def _format(value: float) -> str:
    if value >= 1000:
        return f"{value:,.0f}".replace(",", " ")
    return f"{value:g}"


class _Panel:
    """Область побудови з логарифмічною віссю Y."""

    def __init__(self, x0, y0, w, h, low, high):
        self.x0, self.y0, self.w, self.h = x0, y0, w, h
        self.low, self.high = low, high

    def y(self, value: float) -> float:
        span = math.log10(self.high) - math.log10(self.low)
        return self.y0 + self.h - (math.log10(max(value, self.low)) - math.log10(self.low)) / span * self.h

    def frame(self, y_title: str | None) -> list[str]:
        parts = [f"<rect x='{self.x0}' y='{self.y0}' width='{self.w}' height='{self.h}' fill='none' stroke='#888'/>"]
        decade = self.low
        while decade <= self.high * 1.0001:
            y = self.y(decade)
            parts.append(f"<line x1='{self.x0}' y1='{y:.1f}' x2='{self.x0 + self.w}' y2='{y:.1f}' stroke='#e3e3e3'/>")
            parts.append(_text(self.x0 - 6, y + 4, _format(decade), 11, "end"))
            decade *= 10
        if y_title:
            parts.append(_text(self.x0 - 52, self.y0 + self.h / 2, y_title, 12, rotate=-90))
        return parts


def _svg(width, height, body: list[str], title: str, source: str) -> str:
    head = (f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' "
            f"viewBox='0 0 {width} {height}' role='img' aria-label='{escape(title)}'>"
            f"<rect width='{width}' height='{height}' fill='white'/>")
    foot = _text(12, height - 10, source, 10, "start", fill="#555")
    return head + "".join(body) + foot + "</svg>"


def _iqr_bar(x, panel: _Panel, median_us: float, iqr_us: float, color: str) -> str:
    low, high = max(median_us - iqr_us / 2, panel.low), median_us + iqr_us / 2
    return (f"<line x1='{x:.1f}' y1='{panel.y(low):.1f}' x2='{x:.1f}' y2='{panel.y(high):.1f}' "
            f"stroke='{color}' stroke-width='2'/>")


def chart_hybrid(report) -> str:
    rows = [r for r in report.results if r.group == "hybrid"]
    sizes = sorted({r.payload_bytes for r in rows})
    medians = [_us(r.median_ns) for r in rows]
    low, high = _log_range(medians)
    width, height = 940, 505
    body = [_text(width / 2, 24, "Час гібридних профілів залежно від розміру повідомлення", 15, weight="bold")]
    for index, operation in enumerate(("encrypt", "decrypt")):
        panel = _Panel(80 + index * 420, 60, 360, 300, low, high)
        body += panel.frame("Медіана часу однієї операції, мкс (лог. шкала)" if index == 0 else None)
        body.append(_text(panel.x0 + panel.w / 2, panel.y0 - 8, OPERATION_TITLE[operation], 13, weight="bold"))
        for i, size in enumerate(sizes):
            x = panel.x0 + panel.w * (i + 0.5) / len(sizes)
            body.append(_text(x, panel.y0 + panel.h + 18, SIZE_LABEL[size], 12))
        body.append(_text(panel.x0 + panel.w / 2, panel.y0 + panel.h + 38, "Розмір відкритого повідомлення", 12))
        for profile, color in HYBRID_COLORS.items():
            points = []
            for i, size in enumerate(sizes):
                item = next(r for r in rows if r.profile == profile and r.operation == operation and r.payload_bytes == size)
                x = panel.x0 + panel.w * (i + 0.5) / len(sizes)
                points.append((x, panel.y(_us(item.median_ns)), _us(item.median_ns), _us(item.iqr_ns)))
            body.append("<polyline fill='none' stroke='{}' stroke-width='1.5' points='{}'/>".format(
                color, " ".join(f"{x:.1f},{y:.1f}" for x, y, *_ in points)))
            for x, y, med, iqr in points:
                body.append(_iqr_bar(x, panel, med, iqr, color))
                body.append(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4' fill='{color}'/>")
    legend_y = 432
    for i, (profile, color) in enumerate(HYBRID_COLORS.items()):
        y = legend_y + i * 17
        body.append(f"<line x1='80' y1='{y}' x2='108' y2='{y}' stroke='{color}' stroke-width='2'/>")
        body.append(f"<circle cx='94' cy='{y}' r='4' fill='{color}'/>")
        body.append(_text(116, y + 4, LABELS[profile], 12, "start"))
    body.append(_text(560, legend_y + 4, "Точка — медіана п'яти середніх серій;", 11, "start", fill="#444"))
    body.append(_text(560, legend_y + 20, "відрізок — IQR (довжина = IQR, центр на медіані).", 11, "start", fill="#444"))
    return _svg(width, height, body, "Час гібридних профілів", _source(report))


def chart_direct(report) -> str:
    rows = [r for r in report.results if r.group == "direct"]
    profiles = ("rsa2048-oaep", "rsa3072-oaep")
    colors = {"encrypt": "#1f77b4", "decrypt": "#ff7f0e"}
    low, high = _log_range([_us(r.median_ns) for r in rows])
    width, height = 720, 440
    panel = _Panel(90, 60, 580, 280, low, high)
    body = [_text(width / 2, 24, "Прямий RSA-OAEP: повідомлення 64 байти", 15, weight="bold")]
    body += panel.frame("Медіана часу однієї операції, мкс (лог. шкала)")
    group_w = panel.w / len(profiles)
    for gi, profile in enumerate(profiles):
        center = panel.x0 + group_w * (gi + 0.5)
        body.append(_text(center, panel.y0 + panel.h + 20, LABELS[profile], 12))
        for oi, operation in enumerate(("encrypt", "decrypt")):
            item = next(r for r in rows if r.profile == profile and r.operation == operation)
            bar_w, x = 60, center + (oi - 1) * 70 + 5
            top = panel.y(_us(item.median_ns))
            body.append(f"<rect x='{x:.1f}' y='{top:.1f}' width='{bar_w}' height='{panel.y0 + panel.h - top:.1f}' fill='{colors[operation]}'/>")
            body.append(_iqr_bar(x + bar_w / 2, panel, _us(item.median_ns), _us(item.iqr_ns), "#111"))
            body.append(_text(x + bar_w / 2, top - 6, _format(round(_us(item.median_ns), 1)), 11))
    for i, operation in enumerate(("encrypt", "decrypt")):
        x = 100 + i * 150
        body.append(f"<rect x='{x}' y='392' width='14' height='14' fill='{colors[operation]}'/>")
        body.append(_text(x + 20, 404, OPERATION_TITLE[operation], 12, "start"))
    body.append(_text(420, 404, "Чорний відрізок — IQR (довжина = IQR, центр на медіані).", 11, "start", fill="#444"))
    return _svg(width, height, body, "Прямий RSA-OAEP", _source(report))


def chart_keygen(report) -> str:
    keys = {item.key_profile: item for item in report.key_generation}
    order = ("rsa-2048", "rsa-3072", "x25519", "p256")
    low, high = _log_range([_us(keys[k].median_ns) for k in order])
    width, height = 940, 440
    left = _Panel(80, 60, 380, 280, low, high)
    body = [_text(width / 2, 24, "Генерація ключової пари та розмір відкритого ключа", 15, weight="bold")]
    body += left.frame("Медіана часу генерації, мкс (лог. шкала)")
    body.append(_text(left.x0 + left.w / 2, left.y0 - 8, "Час генерації (5 незалежних вимірювань)", 13, weight="bold"))
    for i, name in enumerate(order):
        x = left.x0 + left.w * (i + 0.5) / len(order)
        item = keys[name]
        top = left.y(_us(item.median_ns))
        body.append(f"<rect x='{x - 30:.1f}' y='{top:.1f}' width='60' height='{left.y0 + left.h - top:.1f}' fill='#1f77b4'/>")
        body.append(_iqr_bar(x, left, _us(item.median_ns), _us(item.iqr_ns), "#111"))
        body.append(_text(x, top - 6, _format(round(_us(item.median_ns), 1)), 11))
        body.append(_text(x, left.y0 + left.h + 18, KEY_LABELS[name], 12))
    x0, y0, w, h = 540, 60, 360, 280
    body.append(f"<rect x='{x0}' y='{y0}' width='{w}' height='{h}' fill='none' stroke='#888'/>")
    body.append(_text(x0 + w / 2, y0 - 8, "Відкритий ключ у DER (SubjectPublicKeyInfo)", 13, weight="bold"))
    top_value = math.ceil(max(item.public_key_der_bytes for item in keys.values()) * 1.1 / 100) * 100
    for step in range(0, 6):
        value = top_value * step / 5
        y = y0 + h - h * step / 5
        body.append(f"<line x1='{x0}' y1='{y:.1f}' x2='{x0 + w}' y2='{y:.1f}' stroke='#e3e3e3'/>")
        body.append(_text(x0 - 6, y + 4, f"{value:.0f}", 11, "end"))
    body.append(_text(x0 - 52, y0 + h / 2, "Розмір, байти (лінійна шкала)", 12, rotate=-90))
    for i, name in enumerate(order):
        x = x0 + w * (i + 0.5) / len(order)
        size = keys[name].public_key_der_bytes
        top = y0 + h - h * size / top_value
        body.append(f"<rect x='{x - 30:.1f}' y='{top:.1f}' width='60' height='{y0 + h - top:.1f}' fill='#2ca02c'/>")
        body.append(_text(x, top - 6, size, 11))
        body.append(_text(x, y0 + h + 18, KEY_LABELS[name], 12))
    body.append(_text(80, 400, "Чорний відрізок — IQR (довжина = IQR, центр на медіані). Час і розмір — різні величини, спільного рейтингу немає.", 11, "start", fill="#444"))
    return _svg(width, height, body, "Генерація ключів і розмір відкритого ключа", _source(report))


def _source(report) -> str:
    return (f"Джерело: results/practice-03/report.json, створено {report.experiment.created_at_utc}, "
            f"код {report.experiment.source_commit[:10]}")


def _fmt_us(ns: float) -> str:
    return f"{ns / 1000:.2f}"


def summary_markdown(report) -> str:
    lines = [
        f"Звіт створено {report.experiment.created_at_utc}, код `{report.experiment.source_commit}`.",
        "Час — мкс на одну операцію (медіана п'яти середніх серій по 20 операцій), IQR — Q3−Q1 (inclusive).",
        "Швидкість — МіБ/с за байтами початкового повідомлення; для прямих RSA не обчислюється.",
        "",
        "### Генерація ключової пари",
        "",
        "| Ключ | Медіана, мкс | IQR, мкс | Відкритий ключ DER, байтів |",
        "|---|---|---|---|",
    ]
    for item in report.key_generation:
        lines.append(f"| {KEY_LABELS[item.key_profile]} | {_fmt_us(item.median_ns)} | {_fmt_us(item.iqr_ns)} | {item.public_key_der_bytes} |")
    lines += ["", "### Шифрування й розшифрування", "",
              "| Профіль | Операція | Розмір | Медіана, мкс | IQR, мкс | МіБ/с | Двійковий результат, байтів |",
              "|---|---|---|---|---|---|---|"]
    order = {name: i for i, name in enumerate(LABELS)}
    for item in sorted(report.results, key=lambda r: (order[r.profile], r.operation, r.payload_bytes)):
        speed = "—" if item.throughput_mib_s is None else f"{item.throughput_mib_s:.1f}"
        lines.append(f"| {LABELS[item.profile]} | {item.operation} | {SIZE_LABEL[item.payload_bytes]} | "
                     f"{_fmt_us(item.median_ns)} | {_fmt_us(item.iqr_ns)} | {speed} | {item.ciphertext_bytes} |")
    failed = [c for c in report.checks if not c.passed]
    lines += ["", "### Перевірки коректності", "",
              f"Усього {len(report.checks)}, пройдено {len(report.checks) - len(failed)}, невдалих {len(failed)}."]
    for item in failed:
        lines.append(f"- НЕ ПРОЙДЕНО: {item.profile} / {item.name}")
    return "\n".join(lines) + "\n"


def build_all(results_dir: Path) -> None:
    results_dir = Path(results_dir)
    data = json.loads((results_dir / "report.json").read_text(encoding="utf-8"))
    report = validate_complete_report(data)
    outputs = {
        "time_hybrid.svg": chart_hybrid(report),
        "time_rsa_direct.svg": chart_direct(report),
        "key_generation.svg": chart_keygen(report),
        "summary.md": summary_markdown(report),
    }
    for name, content in outputs.items():
        (results_dir / name).write_text(content, encoding="utf-8")
    print("Створено:", ", ".join(outputs), "->", results_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Practice 3 charts")
    parser.add_argument("--results-dir", type=Path, default=Path("results/practice-03"))
    build_all(parser.parse_args().results_dir)


if __name__ == "__main__":
    main()
