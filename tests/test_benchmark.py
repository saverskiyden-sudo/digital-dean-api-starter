"""Перевірки модуля вимірювань і генератора графіків (без повного прогону)."""

import csv
import json
import xml.etree.ElementTree as ET

import pytest

from app.api.crypto_lab import load_benchmark_report
from benchmarks import crypto_benchmark as bench
from benchmarks import make_charts


def test_parameters_match_the_assignment():
    assert bench.SIZES_BYTES == (1024, 65536, 1048576)
    assert (bench.WARMUP, bench.SERIES, bench.OPERATIONS_PER_SERIES) == (10, 5, 100)
    assert len(bench.BENCHMARK_AAD) == 64


def test_summarize_uses_median_inclusive_iqr_and_original_bytes():
    result = bench.summarize([100.0, 200.0, 300.0, 400.0, 500.0], 1_048_576)
    assert result["median_ns"] == 300.0
    assert result["iqr_ns"] == 200.0
    assert result["throughput_mib_s"] == pytest.approx(1e9 / 300.0)


def test_summarize_rejects_wrong_series_count_and_nonpositive_time():
    with pytest.raises(ValueError):
        bench.summarize([1.0] * 4, 1024)
    with pytest.raises(ValueError):
        bench.summarize([0.0] * 5, 1024)


def test_measure_batch_calls_every_item_and_returns_mean():
    calls = []
    mean = bench.measure_batch(lambda *a: calls.append(a), [(1,), (2,), (3,)])
    assert calls == [(1,), (2,), (3,)]
    assert mean > 0


def test_measure_batch_rejects_empty_batch_and_zero_time(monkeypatch):
    with pytest.raises(ValueError):
        bench.measure_batch(lambda: None, [])
    monkeypatch.setattr(bench, "perf_counter_ns", lambda: 5)
    with pytest.raises(RuntimeError):
        bench.measure_batch(lambda *a: None, [()])


@pytest.fixture(scope="module")
def small_run(tmp_path_factory):
    directory = tmp_path_factory.mktemp("bench")
    bench.run_benchmark(
        directory, sizes=(16, 32, 64), warmup=1, operations_per_series=3
    )
    return directory


def test_run_writes_raw_rows_and_report(small_run):
    with open(small_run / "raw.csv", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert tuple(rows[0]) == bench.CSV_COLUMNS
    assert len(rows) == 180
    assert {row["operations"] for row in rows} == {"3"}
    assert all(float(row["mean_ns"]) > 0 for row in rows)

    report = load_benchmark_report(small_run / "report.json")
    assert report["schema_version"] == 1
    assert len(report["results"]) == 36
    assert report["parameters"]["series"] == 5
    assert report["parameters"]["context_bytes"] == 64
    assert report["parameters"]["includes_cipher_object_creation"] is True
    for name in ("cpu_model", "os", "architecture", "python", "cryptography",
                 "pycryptodome", "cryptography_openssl", "timer_resolution_s"):
        assert name in report["environment"]


def test_result_files_contain_no_secrets_or_messages(small_run):
    text = (small_run / "report.json").read_text(encoding="utf-8")
    text += (small_run / "raw.csv").read_text(encoding="utf-8")
    for forbidden in ("ciphertext", "plaintext", '"key"', "nonce", '"tag"'):
        assert forbidden not in text


def test_charts_are_valid_svg_and_summary_lists_all_rows(small_run):
    report = json.loads((small_run / "report.json").read_text(encoding="utf-8"))
    for operation in bench.OPERATIONS:
        svg = make_charts.build_chart(report, operation)
        root = ET.fromstring(svg)
        assert root.tag.endswith("svg")
        assert svg.count("<polyline") == 6
    summary = make_charts.build_summary(report)
    assert len([l for l in summary.splitlines() if l.startswith("| ")]) == 1 + 36
