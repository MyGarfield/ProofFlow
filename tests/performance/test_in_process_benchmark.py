from datetime import UTC, datetime

from benchmarks.performance.benchmark import (
    BenchmarkConfig,
    BenchmarkTarget,
    compute_report_hash,
    run_benchmark,
)
from benchmarks.performance.run import running_in_process_service


def test_in_process_benchmark_exercises_all_three_fixed_samples() -> None:
    with running_in_process_service() as (base_url, token):
        report = run_benchmark(
            BenchmarkConfig(
                targets=(BenchmarkTarget("direct", "DIRECT_HTTP", base_url),),
                warmup_requests_per_endpoint=1,
                measured_requests_per_endpoint=2,
                concurrency=2,
                resource_scope="CLIENT_AND_SERVICE",
            ),
            bearer_token=token,
            generated_at=datetime(2026, 8, 20, 5, 0, tzinfo=UTC),
        )

    assert report["summary"] == {
        "attempted_request_count": 6,
        "functional_success_count": 6,
        "functional_failure_count": 0,
        "all_measured_requests_functionally_successful": True,
        "all_target_preparations_successful": True,
        "benchmark_run_valid": True,
    }
    endpoint_reports = report["targets"][0]["endpoints"]
    assert [endpoint["endpoint"] for endpoint in endpoint_reports] == [
        "health",
        "rule_retrieve",
        "deterministic_calculate",
    ]
    assert all(
        endpoint["measurement"]["functional_failure_count"] == 0 for endpoint in endpoint_reports
    )
    assert report["limitations"]["production_sla_measured"] is False
    assert report["limitations"]["cost_measured"] is False
    assert report["limitations"]["agentteams_orchestration_measured"] is False
    assert report["limitations"]["llm_measured"] is False
    assert report["report_hash"] == compute_report_hash(report)
