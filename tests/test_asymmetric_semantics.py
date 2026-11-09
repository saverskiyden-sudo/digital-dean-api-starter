"""Власні перевірки практичної 3: схема, семантика звіту, адаптери, експеримент."""
import copy
import csv
import json
import secrets

import pytest
from pydantic import ValidationError

from app.schemas.asymmetric_report import (
    ALLOWED_PAYLOAD_BYTES,
    EXPECTED_CHECKS,
    filter_report,
    validate_complete_report,
)
from app.security.asymmetric import adapters
from app.security.asymmetric.adapters import (
    DecryptionError,
    decrypt,
    encrypt,
    generate_keypair,
)
from app.security.asymmetric.profiles import (
    CONTEXT,
    PROFILES,
    expected_ciphertext_bytes,
    oaep_max_bytes,
)
from benchmarks import asymmetric_benchmark as bench
from tests.report_factory import make_report


# --- Семантичний валідатор ---------------------------------------------------
def test_valid_report_passes():
    report = validate_complete_report(make_report())
    assert (len(report.key_generation), len(report.results), len(report.checks)) == (4, 22, 22)


def test_failed_check_is_kept_not_hidden():
    data = make_report()
    data["checks"][3]["passed"] = False
    report = validate_complete_report(data)
    assert [c.passed for c in report.checks].count(False) == 1


def test_duplicate_result_tuple_rejected():
    data = make_report()
    data["results"][1] = copy.deepcopy(data["results"][0])
    with pytest.raises(ValueError):
        validate_complete_report(data)


def test_missing_coverage_rejected():
    data = make_report()
    # Двадцять два записи, але одну комбінацію замінено неприпустимим розміром.
    data["results"][5]["payload_bytes"] = 4096
    with pytest.raises(ValueError):
        validate_complete_report(data)


def test_wrong_ciphertext_length_rejected():
    data = make_report()
    hybrid = next(r for r in data["results"] if r["group"] == "hybrid")
    hybrid["ciphertext_bytes"] += 1
    with pytest.raises(ValueError):
        validate_complete_report(data)


def test_wrong_throughput_formula_rejected():
    data = make_report()
    hybrid = next(r for r in data["results"] if r["group"] == "hybrid")
    hybrid["throughput_mib_s"] *= 1.5
    with pytest.raises(ValueError):
        validate_complete_report(data)


def test_direct_profile_must_not_have_throughput():
    data = make_report()
    direct = next(r for r in data["results"] if r["group"] == "direct")
    direct["throughput_mib_s"] = 1.0
    with pytest.raises(ValueError):
        validate_complete_report(data)


def test_hybrid_profile_requires_throughput():
    data = make_report()
    hybrid = next(r for r in data["results"] if r["group"] == "hybrid")
    hybrid["throughput_mib_s"] = None
    with pytest.raises(ValueError):
        validate_complete_report(data)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 0.0, -1.0])
def test_non_finite_or_non_positive_time_rejected(value):
    data = make_report()
    data["results"][0]["median_ns"] = value
    with pytest.raises(ValueError):
        validate_complete_report(data)


def test_negative_iqr_rejected():
    data = make_report()
    data["results"][0]["iqr_ns"] = -1.0
    with pytest.raises(ValueError):
        validate_complete_report(data)


def test_extra_and_wrongly_typed_fields_rejected():
    data = make_report()
    data["results"][0]["note"] = "extra"
    with pytest.raises(ValidationError):
        validate_complete_report(data)
    data = make_report()
    data["results"][0]["payload_bytes"] = True
    with pytest.raises(ValueError):
        validate_complete_report(data)
    data = make_report()
    data["checks"][0]["passed"] = "yes"
    with pytest.raises(ValidationError):
        validate_complete_report(data)


@pytest.mark.parametrize("stamp", [
    "not-a-date-at-all-here", "2026-11-01T12:00:00+02:00", "2026-11-01T12:00:00",
])
def test_created_at_must_be_utc_iso8601(stamp):
    data = make_report()
    data["experiment"]["created_at_utc"] = stamp
    with pytest.raises(ValueError):
        validate_complete_report(data)


@pytest.mark.parametrize("commit", ["abc", "A" * 40, "g" * 40, "a" * 41])
def test_source_commit_must_be_lowercase_sha(commit):
    data = make_report()
    data["experiment"]["source_commit"] = commit
    with pytest.raises(ValidationError):
        validate_complete_report(data)


def test_hybrid_sizes_must_match_assignment():
    data = make_report()
    data["experiment"]["hybrid_sizes_bytes"] = [1024, 65536]
    with pytest.raises(ValueError):
        validate_complete_report(data)


def test_key_generation_coverage_and_der_size():
    data = make_report()
    data["key_generation"][1] = copy.deepcopy(data["key_generation"][0])
    with pytest.raises(ValueError):
        validate_complete_report(data)
    data = make_report()
    data["key_generation"][0]["public_key_der_bytes"] += 1
    with pytest.raises(ValueError):
        validate_complete_report(data)


def test_check_coverage_must_be_exact():
    data = make_report()
    data["checks"][1] = copy.deepcopy(data["checks"][0])
    with pytest.raises(ValueError):
        validate_complete_report(data)
    assert len(EXPECTED_CHECKS) == 22


def test_wrong_cryptography_version_rejected():
    data = make_report()
    data["environment"]["cryptography"] = "47.0.0"
    with pytest.raises(ValidationError):
        validate_complete_report(data)


# --- Фільтр варіанта 1 (payload_bytes) --------------------------------------
@pytest.mark.parametrize("size,count", [(64, 4), (1024, 6), (65536, 6), (1048576, 6)])
def test_filter_by_payload_bytes(size, count):
    report = validate_complete_report(make_report())
    response = filter_report(report, size)
    assert len(response.results) == count
    assert {r.payload_bytes for r in response.results} == {size}
    assert len(response.key_generation) == 4 and len(response.checks) == 22


def test_filter_without_value_returns_full_report():
    report = validate_complete_report(make_report())
    assert len(filter_report(report, None).results) == 22
    assert ALLOWED_PAYLOAD_BYTES == (64, 1024, 65536, 1048576)


def test_empty_filter_result_is_valid_and_complete_arrays_stay():
    report = validate_complete_report(make_report())
    response = filter_report(report, 123)
    assert response.results == []
    assert len(response.checks) == 22 and len(response.key_generation) == 4


def test_filter_keeps_false_checks():
    data = make_report()
    data["checks"][0]["passed"] = False
    response = filter_report(validate_complete_report(data), 64)
    assert any(not c.passed for c in response.checks)


# --- Адаптери: додаткові властивості ----------------------------------------
def test_envelope_layout_of_rsa_aes_hybrid():
    private, public = generate_keypair("rsa-3072")
    message = secrets.token_bytes(100)
    envelope = encrypt("rsa3072-oaep-aes256gcm", public, message)
    assert len(envelope) == 384 + 12 + len(message) + 16
    assert decrypt("rsa3072-oaep-aes256gcm", private, envelope) == message


@pytest.mark.parametrize("profile", [
    "rsa3072-oaep-aes256gcm", "hpke-x25519-aes256gcm", "hpke-p256-aes256gcm",
])
def test_fresh_material_for_every_message(profile):
    _, public = generate_keypair(PROFILES[profile].key_profile)
    first = encrypt(profile, public, b"same message")
    second = encrypt(profile, public, b"same message")
    assert first != second


def test_hybrid_nonce_and_wrapped_key_do_not_repeat():
    _, public = generate_keypair("rsa-3072")
    envelopes = [encrypt("rsa3072-oaep-aes256gcm", public, b"x") for _ in range(8)]
    assert len({e[:384] for e in envelopes}) == 8
    assert len({e[384:396] for e in envelopes}) == 8


def test_oaep_is_randomized():
    _, public = generate_keypair("rsa-2048")
    assert encrypt("rsa2048-oaep", public, b"x") != encrypt("rsa2048-oaep", public, b"x")


@pytest.mark.parametrize("bits", [2048, 3072])
def test_oaep_limit_formula(bits):
    assert oaep_max_bytes(bits) == (190 if bits == 2048 else 318)
    with pytest.raises(ValueError):
        oaep_max_bytes(4096)


@pytest.mark.parametrize("profile", list(PROFILES))
def test_truncated_and_empty_envelopes_rejected(profile):
    private, public = generate_keypair(PROFILES[profile].key_profile)
    envelope = encrypt(profile, public, b"synthetic-record")
    for broken in (b"", envelope[:1], envelope[: len(envelope) // 2], envelope[:-1]):
        with pytest.raises(DecryptionError):
            decrypt(profile, private, broken)


@pytest.mark.parametrize("profile", list(PROFILES))
def test_extended_envelope_rejected(profile):
    private, public = generate_keypair(PROFILES[profile].key_profile)
    envelope = encrypt(profile, public, b"synthetic-record")
    with pytest.raises(DecryptionError):
        decrypt(profile, private, envelope + b"\x00")


@pytest.mark.parametrize("profile", list(PROFILES))
def test_every_byte_region_is_protected(profile):
    private, public = generate_keypair(PROFILES[profile].key_profile)
    envelope = encrypt(profile, public, b"synthetic-record-0123456789")
    for position in (0, len(envelope) // 2, len(envelope) - 1):
        changed = bytearray(envelope)
        changed[position] ^= 0x01
        with pytest.raises(DecryptionError):
            decrypt(profile, private, bytes(changed))


def test_context_is_bound_separately_for_each_scheme():
    for profile in ("rsa2048-oaep", "rsa3072-oaep-aes256gcm", "hpke-x25519-aes256gcm"):
        private, public = generate_keypair(PROFILES[profile].key_profile)
        envelope = encrypt(profile, public, b"x", context=b"context-a")
        assert decrypt(profile, private, envelope, context=b"context-a") == b"x"
        with pytest.raises(DecryptionError):
            decrypt(profile, private, envelope, context=b"context-b")
        with pytest.raises(DecryptionError):
            decrypt(profile, private, envelope)  # контекст за замовчуванням CONTEXT
    assert CONTEXT == b"digital-dean:practice-03:report-v1"


def test_key_type_must_match_profile():
    rsa_private, rsa_public = generate_keypair("rsa-2048")
    x_private, x_public = generate_keypair("x25519")
    p_private, p_public = generate_keypair("p256")
    with pytest.raises(ValueError):
        encrypt("rsa3072-oaep", rsa_public, b"x")  # ключ 2048 для профілю 3072
    with pytest.raises(ValueError):
        encrypt("hpke-x25519-aes256gcm", p_public, b"x")
    with pytest.raises(ValueError):
        encrypt("hpke-p256-aes256gcm", x_public, b"x")
    envelope = encrypt("hpke-x25519-aes256gcm", x_public, b"x")
    with pytest.raises(DecryptionError):
        decrypt("hpke-x25519-aes256gcm", p_private, envelope)
    with pytest.raises(DecryptionError):
        decrypt("hpke-x25519-aes256gcm", rsa_private, envelope)


def test_message_too_long_for_direct_rsa_rejected():
    _, public = generate_keypair("rsa-3072")
    with pytest.raises(ValueError):
        encrypt("rsa3072-oaep", public, b"d" * (oaep_max_bytes(3072) + 1))


def test_non_bytes_input_rejected():
    _, public = generate_keypair("x25519")
    with pytest.raises(ValueError):
        encrypt("hpke-x25519-aes256gcm", public, "text")  # type: ignore[arg-type]


def test_unknown_profiles_rejected_everywhere():
    with pytest.raises(ValueError):
        decrypt("unknown", None, b"x")
    with pytest.raises(ValueError):
        generate_keypair("rsa-1024")


def test_keypair_types_and_sizes():
    for bits in (2048, 3072):
        private, public = generate_keypair(f"rsa-{bits}")
        assert private.key_size == bits and public.key_size == bits
        assert public.public_numbers().e == 65537


@pytest.mark.parametrize("profile", list(PROFILES))
def test_failure_reveals_no_plaintext(profile):
    private, public = generate_keypair(PROFILES[profile].key_profile)
    envelope = encrypt(profile, public, b"secret-synthetic-marker")
    changed = envelope[:-1] + bytes([envelope[-1] ^ 1])
    with pytest.raises(DecryptionError) as error:
        decrypt(profile, private, changed)
    assert "secret-synthetic-marker" not in str(error.value)
    assert str(error.value) == "decryption rejected"


def test_adapter_module_uses_only_library_primitives():
    source = open(adapters.__file__, encoding="utf-8").read()
    for forbidden in ("PKCS1v15", "hashlib", "random.", "from Crypto"):
        assert forbidden not in source


# --- Експеримент ------------------------------------------------------------
def test_experiment_parameters_match_the_assignment():
    assert (bench.SERIES, bench.OPERATIONS, bench.WARMUP, bench.KEYGEN_RUNS) == (5, 20, 10, 5)
    assert len(bench.combinations()) == 22


def test_summarize_median_and_inclusive_iqr():
    assert bench.summarize([1.0, 2.0, 3.0, 4.0, 5.0]) == (3.0, 2.0)
    with pytest.raises(ValueError):
        bench.summarize([1.0, 2.0])


def test_measure_batch_counts_calls_and_rejects_zero():
    calls = []
    elapsed, per_operation = bench.measure_batch(lambda: calls.append(1), 20)
    assert len(calls) == 20 and elapsed > 0 and per_operation == elapsed / 20
    with pytest.raises(ValueError):
        bench.measure_batch(lambda: None, 0)


def test_profile_order_rotates_between_series():
    base = bench.combinations()
    orders = [bench.rotate(base, i) for i in range(5)]
    assert all(sorted(order) == sorted(base) for order in orders)
    assert len({tuple(order) for order in orders}) == 5
    assert orders[0] == base


def test_source_commit_refuses_dirty_tree(monkeypatch):
    answers = {("rev-parse", "HEAD"): "b" * 40,
               ("status", "--porcelain", "--", "app", "benchmarks"): " M app/x.py"}
    monkeypatch.setattr(bench, "_git", lambda *args: answers[args])
    with pytest.raises(RuntimeError):
        bench.source_commit()
    assert bench.source_commit(allow_dirty=True) == "b" * 40


def test_full_experiment_writes_valid_files_without_secrets(tmp_path, monkeypatch):
    monkeypatch.setattr(
        bench, "collect_environment",
        lambda: {**make_report()["environment"], "cryptography": "48.0.1"},
    )
    report = bench.run_experiment(tmp_path, commit="c" * 40)
    rows = list(csv.DictReader((tmp_path / "raw.csv").open(encoding="utf-8")))
    assert len(rows) == 130
    assert tuple(rows[0]) == bench.CSV_COLUMNS
    assert sum(1 for r in rows if r["group"] == "key_generation") == 20
    saved = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    validate_complete_report(saved)
    assert saved == json.loads(json.dumps(report))
    text = (tmp_path / "report.json").read_text(encoding="utf-8") + (tmp_path / "raw.csv").read_text(encoding="utf-8")
    for marker in ("PRIVATE KEY", "BEGIN", "token", "password"):
        assert marker not in text
    assert all(c["passed"] for c in saved["checks"])
    assert not list(tmp_path.glob("*.tmp"))
