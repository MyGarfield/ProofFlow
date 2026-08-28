from benchmarks.evaluation.deterministic_runner import (
    DETERMINISTIC_SCENARIO_RUNNERS,
    run_deterministic_scenario,
)
from benchmarks.evaluation.suite import classify_scenario_observation, validate_manifest


def test_all_ten_deterministic_manifest_scenarios_have_exact_adapters() -> None:
    manifest = validate_manifest()
    deterministic_ids = {
        scenario["id"]
        for scenario in manifest["scenarios"]
        if "deterministic_reference" in scenario["arm_ids"]
    }
    bound_ids = {
        scenario["id"]
        for scenario in manifest["scenarios"]
        if scenario["runner_binding"]["deterministic_reference"] is not None
    }

    assert len(deterministic_ids) == 10
    assert bound_ids == deterministic_ids
    assert set(DETERMINISTIC_SCENARIO_RUNNERS) == deterministic_ids


def test_deterministic_adapters_execute_only_public_contracts_and_match_manifest(
    tmp_path,
) -> None:
    manifest = validate_manifest()
    scenarios = {scenario["id"]: scenario for scenario in manifest["scenarios"]}

    for scenario_id in DETERMINISTIC_SCENARIO_RUNNERS:
        observation = run_deterministic_scenario(scenario_id, tmp_path / scenario_id)
        assert classify_scenario_observation(scenarios[scenario_id], observation) == "PASS"
