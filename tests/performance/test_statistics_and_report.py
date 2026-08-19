from copy import deepcopy

import pytest

from benchmarks.performance.benchmark import (
    MAX_CONCURRENCY,
    MAX_MEASURED_REQUESTS_PER_ENDPOINT,
    MAX_TIMEOUT_SECONDS,
    MAX_WARMUP_REQUESTS_PER_ENDPOINT,
    BenchmarkConfig,
    BenchmarkConfigurationError,
    BenchmarkTarget,
    RequestObservation,
    compute_report_hash,
    nearest_rank_percentile,
    summarize_observations,
    validate_base_url,
)


def test_nearest_rank_percentiles_use_declared_population_rule() -> None:
    values = list(range(1, 101))

    assert nearest_rank_percentile(values, 50) == 50
    assert nearest_rank_percentile(values, 95) == 95
    assert nearest_rank_percentile(values, 99) == 99
    assert nearest_rank_percentile([9], 99) == 9
    assert nearest_rank_percentile([], 50) is None
    with pytest.raises(ValueError, match="between 1 and 100"):
        nearest_rank_percentile(values, 0)


def test_transport_http_and_skill_outcomes_are_separate() -> None:
    observations = (
        RequestObservation(1_000_000, 200, None, None, True, "SUCCESS", None),
        RequestObservation(2_000_000, 200, None, None, True, "BLOCKED", None),
        RequestObservation(3_000_000, 503, None, None, True, None, None),
        RequestObservation(4_000_000, None, "TIMEOUT", None, False, None, None),
    )

    summary = summarize_observations(
        observations,
        wall_seconds=0.5,
        expected_skill_status="SUCCESS",
        expected_service_status=None,
    )

    assert summary["attempted_request_count"] == 4
    assert summary["http_status_received_count"] == 3
    assert summary["complete_http_response_count"] == 3
    assert summary["http_2xx_status_count"] == 2
    assert summary["http_non_2xx_status_count"] == 1
    assert summary["transport_error_count"] == 1
    assert summary["transport_errors"] == {"TIMEOUT": 1}
    assert summary["response_read_error_count"] == 0
    assert summary["response_read_errors"] == {}
    assert summary["skill_status_counts"] == {"BLOCKED": 1, "SUCCESS": 1}
    assert summary["skill_status_unavailable_count"] == 2
    assert summary["functional_success_count"] == 1
    assert summary["functional_failure_count"] == 3
    assert summary["latency_ms"]["p95_nearest_rank"] == 4.0


def test_report_hash_ignores_only_itself_and_detects_mutation() -> None:
    report = {
        "schema_version": "proofflow.performance-report/v1",
        "summary": {"attempted_request_count": 3},
        "report_hash_semantics": {"kind": "UNSIGNED_CONTENT_DIGEST"},
    }
    digest = compute_report_hash(report)
    with_hash = {**report, "report_hash": digest}

    assert digest.startswith("sha256:")
    assert compute_report_hash(with_hash) == digest

    mutated = deepcopy(with_hash)
    mutated["summary"]["attempted_request_count"] = 4
    assert compute_report_hash(mutated) != digest


def test_non_loopback_targets_require_explicit_opt_in() -> None:
    assert validate_base_url("http://127.0.0.1:8787/") == "http://127.0.0.1:8787"
    assert validate_base_url("http://localhost:8787") == "http://localhost:8787"
    with pytest.raises(BenchmarkConfigurationError, match="non-loopback target refused"):
        validate_base_url("https://example.invalid")
    assert (
        validate_base_url("https://gateway.example.invalid/base/", allow_non_loopback=True)
        == "https://gateway.example.invalid/base"
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("warmup_requests_per_endpoint", MAX_WARMUP_REQUESTS_PER_ENDPOINT + 1, "warmup"),
        (
            "measured_requests_per_endpoint",
            MAX_MEASURED_REQUESTS_PER_ENDPOINT + 1,
            "measured request",
        ),
        ("concurrency", MAX_CONCURRENCY + 1, "concurrency"),
        ("timeout_seconds", MAX_TIMEOUT_SECONDS + 1, "timeout"),
    ),
)
def test_load_parameters_have_hard_resource_limits(
    field: str, value: int | float, message: str
) -> None:
    values = {
        "targets": (BenchmarkTarget("direct", "DIRECT_HTTP", "http://127.0.0.1:8787"),),
        field: value,
    }

    with pytest.raises(BenchmarkConfigurationError, match=message):
        BenchmarkConfig(**values).validate()
