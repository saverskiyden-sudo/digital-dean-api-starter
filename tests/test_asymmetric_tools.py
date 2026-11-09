"""Графіки, таблиця й звіт будуються лише з перевіреного report.json."""
import json
import types
import xml.etree.ElementTree as ET

import pytest

from benchmarks import make_asymmetric_charts as charts
from benchmarks import make_asymmetric_report as report_tool
from tests.report_factory import make_report


@pytest.fixture
def results_dir(tmp_path):
    (tmp_path / "report.json").write_text(json.dumps(make_report()), encoding="utf-8")
    return tmp_path


def test_charts_are_valid_svg_with_units_and_source(results_dir):
    charts.build_all(results_dir)
    for name in ("time_hybrid.svg", "time_rsa_direct.svg", "key_generation.svg"):
        root = ET.parse(results_dir / name).getroot()
        text = "".join(root.itertext())
        assert "мкс" in text and "Джерело: results/practice-03/report.json" in text
        assert "IQR" in text


def test_summary_has_every_measured_row(results_dir):
    charts.build_all(results_dir)
    summary = (results_dir / "summary.md").read_text(encoding="utf-8")
    assert summary.count("| encrypt |") + summary.count("| decrypt |") == 22
    assert "Усього 22, пройдено 22, невдалих 0" in summary


def test_summary_reports_failed_checks_openly(results_dir):
    data = make_report()
    data["checks"][0]["passed"] = False
    (results_dir / "report.json").write_text(json.dumps(data), encoding="utf-8")
    charts.build_all(results_dir)
    summary = (results_dir / "summary.md").read_text(encoding="utf-8")
    assert "невдалих 1" in summary and "НЕ ПРОЙДЕНО" in summary


def test_charts_refuse_an_invalid_report(results_dir):
    data = make_report()
    data["results"][0]["median_ns"] = -1
    (results_dir / "report.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        charts.build_all(results_dir)


def test_report_document_is_complete_and_free_of_placeholders(results_dir):
    from app.schemas.asymmetric_report import validate_complete_report

    args = types.SimpleNamespace(
        date="01.11.2026", remote="https://github.com/example/fork",
        final_sha="f" * 40, pytest_before="1 passed", pytest_after_import="2 passed",
        pytest_final="3 passed", commits="aaaaaaa First\nbbbbbbb Second",
    )
    charts.build_all(results_dir)
    text = report_tool.render(validate_complete_report(make_report()), args)
    for heading in ("## Титульні відомості", "## Середовище та методика", "## Результати",
                    "## API та індивідуальний варіант", "## Git", "## Алфавітний глосарій",
                    "## Використані джерела"):
        assert heading in text
    for leftover in ("{{", "}}{", "None", "TODO", "nan"):
        assert leftover not in text
    assert "payload_bytes" in text and "17 mod 4 = **1**" in text
    assert "PRIVATE KEY" not in text


def test_findings_do_not_claim_a_winner_inside_the_spread():
    from app.schemas.asymmetric_report import validate_complete_report

    data = make_report()
    for item in data["results"]:
        if item["group"] == "hybrid":
            item["median_ns"] = 100000.0
            item["iqr_ns"] = 50000.0
            item["throughput_mib_s"] = item["payload_bytes"] * 1e9 / (2**20 * 100000.0)
    lines = report_tool.findings(validate_complete_report(data))
    assert any("перевагу не стверджуємо" in line for line in lines)
