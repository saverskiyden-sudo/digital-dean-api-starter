"""Графіки практичної 4 з власного report.json (без сторонніх бібліотек).

    python -m benchmarks.make_hash_charts

Створює results/practice-04/throughput.svg, chunked_vs_whole.svg, avalanche.svg.
Числа беруться лише з перевіреного report.json; нічого не вигадується.
"""
import argparse
import json
import math
from html import escape
from pathlib import Path

from app.schemas.hash_report import validate_report
from app.security.hashing.profiles import PAYLOAD_SIZES

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = ROOT / "results" / "practice-04"
COLORS = {
    "sha256": "#1f77b4", "sha512": "#ff7f0e", "sha3-256": "#2ca02c",
    "blake2b-256": "#d62728", "blake2s-256": "#9467bd",
    "md5": "#8c564b", "sha1": "#7f7f7f",
}
LABELS = {
    "sha256": "SHA-256", "sha512": "SHA-512", "sha3-256": "SHA3-256",
    "blake2b-256": "BLAKE2b-256", "blake2s-256": "BLAKE2s-256",
    "md5": "MD5 (навч.)", "sha1": "SHA-1 (навч.)",
}
SIZE_LABEL = {64: "64 Б", 1024: "1 КіБ", 65536: "64 КіБ", 1048576: "1 МіБ"}
FONT = "font-family='Arial, Helvetica, sans-serif'"


def _t(x, y, s, size=12, anchor="middle", weight="normal", fill="#222", rotate=None):
    tr = f" transform='rotate({rotate} {x:.1f} {y:.1f})'" if rotate else ""
    return (f"<text x='{x:.1f}' y='{y:.1f}' font-size='{size}' text-anchor='{anchor}' "
            f"font-weight='{weight}' fill='{fill}' {FONT}{tr}>{escape(str(s))}</text>")


def _svg(width, height, body):
    return (f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' "
            f"viewBox='0 0 {width} {height}'><rect width='100%' height='100%' fill='white'/>"
            + "".join(body) + "</svg>\n")


def _fmt(v):
    return f"{v:,.0f}".replace(",", " ") if v >= 1000 else f"{v:g}"


def throughput_chart(report: dict, caption: str) -> str:
    """Пропускна здатність (whole) залежно від розміру; логарифмічна вісь Y."""
    W, H, L, R, T, B = 820, 500, 80, 200, 60, 70
    rows = [r for r in report["results"] if r["mode"] == "whole"]
    values = [r["throughput_mib_s"] for r in rows]
    lo = 10 ** math.floor(math.log10(min(values)))
    hi = 10 ** math.ceil(math.log10(max(values)))
    pw, ph = W - L - R, H - T - B

    def x(i):
        return L + pw * i / (len(PAYLOAD_SIZES) - 1)

    def y(v):
        return T + ph * (1 - (math.log10(v) - math.log10(lo)) /
                         (math.log10(hi) - math.log10(lo)))

    body = [_t(W / 2, 28, "Пропускна здатність (спосіб whole), МіБ/с — медіана 5 серій",
               15, weight="bold")]
    p = lo
    while p <= hi * 1.0001:
        body.append(f"<line x1='{L}' x2='{L + pw}' y1='{y(p):.1f}' y2='{y(p):.1f}' stroke='#ddd'/>")
        body.append(_t(L - 8, y(p) + 4, _fmt(p), 11, "end"))
        p *= 10
    for i, s in enumerate(PAYLOAD_SIZES):
        body.append(f"<line x1='{x(i):.1f}' x2='{x(i):.1f}' y1='{T}' y2='{T + ph}' stroke='#eee'/>")
        body.append(_t(x(i), T + ph + 20, SIZE_LABEL[s], 12))
    body.append(_t(L + pw / 2, H - 22, "Розмір повідомлення (логарифмічна шкала розмірів)", 12))
    body.append(_t(22, T + ph / 2, "МіБ/с (лог. шкала)", 12, rotate=-90))
    algorithms = [a["algorithm"] for a in report["algorithms"] if a["available"]]
    for k, alg in enumerate(algorithms):
        pts = sorted((PAYLOAD_SIZES.index(r["payload_bytes"]), r["throughput_mib_s"])
                     for r in rows if r["algorithm"] == alg)
        path = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in pts)
        dash = " stroke-dasharray='6 4'" if alg in ("md5", "sha1") else ""
        body.append(f"<polyline points='{path}' fill='none' stroke='{COLORS[alg]}' stroke-width='2.2'{dash}/>")
        for i, v in pts:
            body.append(f"<circle cx='{x(i):.1f}' cy='{y(v):.1f}' r='3.5' fill='{COLORS[alg]}'/>")
        ly = T + 10 + 22 * k
        body.append(f"<line x1='{L + pw + 20}' x2='{L + pw + 44}' y1='{ly}' y2='{ly}' stroke='{COLORS[alg]}' stroke-width='3'{dash}/>")
        body.append(_t(L + pw + 50, ly + 4, LABELS[alg], 12, "start"))
    body.append(_t(W / 2, H - 4, caption, 10, fill="#666"))
    return _svg(W, H, body)


def chunked_chart(report: dict, caption: str) -> str:
    """Відношення медіан chunked/whole для кожного профілю і розміру."""
    W, H, L, R, T, B = 820, 460, 80, 30, 60, 90
    algorithms = [a["algorithm"] for a in report["algorithms"] if a["available"]]
    med = {(r["algorithm"], r["mode"], r["payload_bytes"]): r["median_ns"]
           for r in report["results"]}
    ratios = {(a, s): med[(a, "chunked", s)] / med[(a, "whole", s)]
              for a in algorithms for s in PAYLOAD_SIZES}
    top = max(1.2, max(ratios.values()) * 1.1)
    pw, ph = W - L - R, H - T - B
    group = pw / len(PAYLOAD_SIZES)
    bw = group * 0.8 / len(algorithms)

    def y(v):
        return T + ph * (1 - v / top)

    body = [_t(W / 2, 28, "Відношення часу chunked / whole (медіани); 1 = однаково", 15, weight="bold")]
    step = 0.2 if top <= 2 else 0.5
    v = 0.0
    while v <= top + 1e-9:
        body.append(f"<line x1='{L}' x2='{L + pw}' y1='{y(v):.1f}' y2='{y(v):.1f}' stroke='#eee'/>")
        body.append(_t(L - 8, y(v) + 4, f"{v:.1f}", 11, "end"))
        v += step
    body.append(f"<line x1='{L}' x2='{L + pw}' y1='{y(1):.1f}' y2='{y(1):.1f}' stroke='#c00' stroke-dasharray='5 4'/>")
    for gi, s in enumerate(PAYLOAD_SIZES):
        gx = L + group * gi + group * 0.1
        for k, alg in enumerate(algorithms):
            val = ratios[(alg, s)]
            bx = gx + bw * k
            body.append(f"<rect x='{bx:.1f}' y='{y(val):.1f}' width='{bw - 1:.1f}' height='{y(0) - y(val):.1f}' fill='{COLORS[alg]}'/>")
        body.append(_t(L + group * gi + group / 2, T + ph + 18, SIZE_LABEL[s], 12))
    for k, alg in enumerate(algorithms):
        lx = L + (pw / len(algorithms)) * k
        body.append(f"<rect x='{lx:.1f}' y='{H - 48}' width='12' height='12' fill='{COLORS[alg]}'/>")
        body.append(_t(lx + 16, H - 38, LABELS[alg], 11, "start"))
    body.append(_t(22, T + ph / 2, "chunked / whole", 12, rotate=-90))
    body.append(_t(W / 2, H - 6, caption, 10, fill="#666"))
    return _svg(W, H, body)


def avalanche_chart(report: dict, caption: str) -> str:
    """Частка змінених бітів: мін–макс (відрізок) і середнє (точка) для 100 дослідів."""
    W, H, L, R, T, B = 820, 440, 80, 30, 60, 80
    rows = report["avalanche"]
    pw, ph = W - L - R, H - T - B
    slot = pw / len(rows)

    def y(v):
        return T + ph * (1 - v)

    body = [_t(W / 2, 28, "Лавинний дослід: частка змінених бітів хешу (100 одиничних змін, 1024 Б)",
               14, weight="bold")]
    for v in (0, 0.25, 0.5, 0.75, 1.0):
        stroke = "#c00' stroke-dasharray='5 4" if v == 0.5 else "#eee"
        body.append(f"<line x1='{L}' x2='{L + pw}' y1='{y(v):.1f}' y2='{y(v):.1f}' stroke='{stroke}'/>")
        body.append(_t(L - 8, y(v) + 4, f"{v:.2f}", 11, "end"))
    for k, a in enumerate(rows):
        cx = L + slot * (k + 0.5)
        lo = a["min_flipped_bits"] / a["digest_bits"]
        hi = a["max_flipped_bits"] / a["digest_bits"]
        color = COLORS[a["algorithm"]]
        body.append(f"<line x1='{cx:.1f}' x2='{cx:.1f}' y1='{y(hi):.1f}' y2='{y(lo):.1f}' stroke='{color}' stroke-width='6' stroke-linecap='round' opacity='0.45'/>")
        body.append(f"<circle cx='{cx:.1f}' cy='{y(a['mean_fraction']):.1f}' r='6' fill='{color}'/>")
        body.append(_t(cx, y(a["mean_fraction"]) - 10, f"{a['mean_fraction']:.3f}", 11))
        body.append(_t(cx, T + ph + 18, LABELS[a["algorithm"]], 11))
        body.append(_t(cx, T + ph + 33, f"n = {a['digest_bits']} біт", 10, fill="#666"))
    body.append(_t(22, T + ph / 2, "частка змінених бітів", 12, rotate=-90))
    body.append(_t(W / 2, H - 20, "Відрізок — мін–макс, точка — середнє; вибірка не є оцінкою стійкості",
                   10, fill="#666"))
    body.append(_t(W / 2, H - 6, caption, 10, fill="#666"))
    return _svg(W, H, body)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Practice 4 charts")
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_DIR)
    args = parser.parse_args(argv)
    raw = json.loads((args.results_dir / "report.json").read_text(encoding="utf-8"))
    validate_report(raw)
    env = raw["environment"]
    caption = (f"Джерело: report.json, {raw['created_at']}, коміт {raw['source_commit'][:7]}; "
               f"{env['cpu']}, Python {env['python']}")
    charts = {
        "throughput.svg": throughput_chart(raw, caption),
        "chunked_vs_whole.svg": chunked_chart(raw, caption),
        "avalanche.svg": avalanche_chart(raw, caption),
    }
    for name, svg in charts.items():
        (args.results_dir / name).write_text(svg, encoding="utf-8")
    print("Графіки:", ", ".join(charts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
