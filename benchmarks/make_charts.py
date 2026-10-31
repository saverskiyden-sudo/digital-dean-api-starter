"""Будує графіки з report.json без сторонніх бібліотек (чистий SVG).

    python -m benchmarks.make_charts --results-dir results/practice-02

Створює throughput_encrypt.svg, throughput_decrypt.svg і summary.md
(таблиця порівняння: медіана, IQR, МіБ/с для кожної комбінації).
"""

import argparse
import json
import math
from html import escape
from pathlib import Path

COLORS = {
    ("cryptography", "AES-128-GCM"): "#1f77b4",
    ("cryptography", "AES-256-GCM"): "#2ca02c",
    ("cryptography", "ChaCha20-Poly1305"): "#9467bd",
    ("pycryptodome", "AES-128-GCM"): "#ff7f0e",
    ("pycryptodome", "AES-256-GCM"): "#d62728",
    ("pycryptodome", "ChaCha20-Poly1305"): "#8c564b",
}
DASH = {"cryptography": "", "pycryptodome": "6 4"}
OP_TITLE = {"encrypt": "Шифрування", "decrypt": "Перевірене розшифрування"}


def _kib(size: int) -> str:
    return f"{size // 1024} КіБ"


def build_chart(report: dict, operation: str) -> str:
    rows = [r for r in report["results"] if r["operation"] == operation]
    sizes = sorted({r["size_bytes"] for r in rows})
    combos = sorted({(r["backend"], r["algorithm"]) for r in rows})
    index = {(r["backend"], r["algorithm"], r["size_bytes"]): r for r in rows}

    def bounds(r):
        # Розкид: мін–макс п'яти серій, переведений у МіБ/с (швидше = менший час).
        times = r["series_mean_ns"]
        to_v = lambda t: r["size_bytes"] * 1e9 / (2**20 * t)
        return to_v(max(times)), to_v(min(times))

    all_values = []
    for r in rows:
        lo, hi = bounds(r)
        all_values += [lo, hi]
    vmin, vmax = min(all_values), max(all_values)
    y_lo = 10 ** math.floor(math.log10(vmin))
    y_hi = 10 ** math.ceil(math.log10(vmax))
    if y_lo == y_hi:
        y_hi = y_lo * 10

    width, height = 860, 520
    left, right, top, bottom = 80, 250, 50, 70
    plot_w, plot_h = width - left - right, height - top - bottom

    def x_pos(size):
        i = sizes.index(size)
        return left + plot_w * (i + 0.5) / len(sizes)

    def y_pos(v):
        t = (math.log10(v) - math.log10(y_lo)) / (math.log10(y_hi) - math.log10(y_lo))
        return top + plot_h * (1 - t)

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="Arial, sans-serif" font-size="12">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="{left}" y="28" font-size="16" font-weight="bold">'
        f'{escape(OP_TITLE[operation])}: пропускна здатність за розміром повідомлення</text>',
    ]
    decade = y_lo
    while decade <= y_hi * 1.0001:
        y = y_pos(decade)
        out.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" stroke="#dddddd"/>')
        out.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{decade:g}</text>')
        decade *= 10
    for size in sizes:
        x = x_pos(size)
        out.append(f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{top + plot_h}" stroke="#eeeeee"/>')
        out.append(f'<text x="{x:.1f}" y="{top + plot_h + 20}" text-anchor="middle">{_kib(size)}</text>')
    out.append(f'<rect x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" fill="none" stroke="#444444"/>')
    out.append(f'<text x="{left + plot_w / 2}" y="{height - 18}" text-anchor="middle">Розмір початкового повідомлення</text>')
    out.append(f'<text transform="translate(20 {top + plot_h / 2}) rotate(-90)" text-anchor="middle">МіБ/с (логарифмічна шкала)</text>')

    for combo in combos:
        color, dash = COLORS.get(combo, "#000000"), DASH[combo[0]]
        points = []
        for size in sizes:
            r = index[(combo[0], combo[1], size)]
            lo, hi = bounds(r)
            x = x_pos(size) + (combos.index(combo) - (len(combos) - 1) / 2) * 5
            points.append((x, y_pos(r["throughput_mib_s"])))
            out.append(f'<line x1="{x:.1f}" y1="{y_pos(hi):.1f}" x2="{x:.1f}" y2="{y_pos(lo):.1f}" stroke="{color}" stroke-width="1.5"/>')
            out.append(f'<line x1="{x - 3:.1f}" y1="{y_pos(hi):.1f}" x2="{x + 3:.1f}" y2="{y_pos(hi):.1f}" stroke="{color}"/>')
            out.append(f'<line x1="{x - 3:.1f}" y1="{y_pos(lo):.1f}" x2="{x + 3:.1f}" y2="{y_pos(lo):.1f}" stroke="{color}"/>')
        path = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        out.append(f'<polyline points="{path}" fill="none" stroke="{color}" stroke-width="2"' + (f' stroke-dasharray="{dash}"' if dash else "") + "/>")
        for x, y in points:
            out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="{color}"/>')

    lx, ly = left + plot_w + 20, top + 10
    for i, combo in enumerate(combos):
        y = ly + i * 24
        color, dash = COLORS.get(combo, "#000000"), DASH[combo[0]]
        out.append(f'<line x1="{lx}" y1="{y}" x2="{lx + 28}" y2="{y}" stroke="{color}" stroke-width="2"' + (f' stroke-dasharray="{dash}"' if dash else "") + "/>")
        out.append(f'<circle cx="{lx + 14}" cy="{y}" r="3.5" fill="{color}"/>')
        out.append(f'<text x="{lx + 36}" y="{y + 4}">{escape(combo[0])}, {escape(combo[1])}</text>')
    note_y = ly + len(combos) * 24 + 14
    for j, line in enumerate((
        "Точка — медіана 5 середніх часів серій;",
        "відрізок — розкид мін–макс п'яти серій",
        "(пропускна здатність за початковими",
        "байтами, без тега).",
    )):
        out.append(f'<text x="{lx}" y="{note_y + j * 15}" font-size="11" fill="#444444">{escape(line)}</text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"


def build_summary(report: dict) -> str:
    lines = [
        f"Прогін `{report['run_id']}`. Медіана та IQR — у мікросекундах на операцію; швидкість — МіБ/с.",
        "",
        "| Комбінація | Операція | Розмір | Медіана, мкс | IQR, мкс | МіБ/с |",
        "|---|---|---|---|---|---|",
    ]
    rows = sorted(
        report["results"],
        key=lambda r: (r["backend"], r["algorithm"], r["operation"], r["size_bytes"]),
    )
    for r in rows:
        lines.append(
            f"| {r['backend']} {r['algorithm']} | {r['operation']} | {_kib(r['size_bytes'])} "
            f"| {r['median_ns'] / 1000:.2f} | {r['iqr_ns'] / 1000:.2f} | {r['throughput_mib_s']:.1f} |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Practice 2 charts")
    parser.add_argument("--results-dir", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads((args.results_dir / "report.json").read_text(encoding="utf-8"))
    for operation in ("encrypt", "decrypt"):
        path = args.results_dir / f"throughput_{operation}.svg"
        path.write_text(build_chart(report, operation), encoding="utf-8")
        print("Створено", path)
    summary = args.results_dir / "summary.md"
    summary.write_text(build_summary(report), encoding="utf-8")
    print("Створено", summary)


if __name__ == "__main__":
    main()
