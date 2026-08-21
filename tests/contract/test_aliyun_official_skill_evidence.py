from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from collections.abc import Callable
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).parents[2]
DEPLOY = ROOT / "deploy/agentteams"
EVIDENCE_PATH = DEPLOY / "evidence/aliyun-official-skill-offline-preflight-2026-08-21.json"
SCHEMA_PATH = DEPLOY / "evidence/aliyun-official-skill-offline-preflight.schema.json"
VALIDATOR_PATH = DEPLOY / "scripts/validate_aliyun_official_skill_evidence.py"
COLLECTOR_PATH = DEPLOY / "scripts/collect_aliyun_official_skill_evidence.py"
RUNNER_PATH = DEPLOY / "scripts/run_aliyun_official_skill_offline_preflight.sh"
UPSTREAM_ROOT = ROOT / "third_party/aliyun/alibabacloud-openclaw-skill-security-scan/upstream"

EXPECTED_SKILLS = {
    "conflict_detect",
    "decision_audit",
    "deterministic_calculate",
    "document_package",
    "evidence_ingest",
    "human_approval",
    "rule_retrieve",
    "timeline_build",
}
EXPECTED_SOURCE_HASHES = {
    "SKILL.md": "d5df78b1d78361596b626fb129567e2fb69eb65002de7545e451b1f648311e80",
    "assets/LICENSE.txt": "c4db38611836ea364d14273ebfe902b106e220f07b8f723b8230125be7f2795b",
    "references/baseline.md": "b2bee705755d001079dadf4da9e1462d275c44a44fd08f7ba233835389be21b4",
    "references/report_template.md": (
        "9f52e97e0075dc609be666c259155b253280bb96c109f9c6f7a8d09d23b3ddbf"
    ),
    "references/skillaudit.md": "41de28a8680332ccfca1dcf247dd261fdd3e12de3dd660869dbd2d4f16764be4",
    "scripts/basic_udf.sh": "9fdf8763b6bfc5c5b681d781c7ab49caa36aa94125799d295441fbe952997466",
    "scripts/main.sh": "a0a4cf6a04bd8e367cf984cc385fcf9f2e11a00a9f96d3ab3eb88c424d508f94",
    "scripts/skill_zip_packager.sh": (
        "f61362ef8c2a3ba6ecf7e4f34740757dfb35b017def5e5bd5378818583824a47"
    ),
}


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("aliyun_skill_evidence_validator", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evidence() -> dict[str, Any]:
    return json.loads(EVIDENCE_PATH.read_text())


def test_current_evidence_passes_draft_2020_12_and_strict_semantics() -> None:
    document = evidence()
    schema = json.loads(SCHEMA_PATH.read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    assert list(validator.iter_errors(document)) == []

    semantic_validator = load_validator()
    semantic_validator.validate_semantics(document, strict=True)


def test_vendored_source_is_exact_complete_and_mit_licensed() -> None:
    observed: dict[str, str] = {}
    for source in sorted(UPSTREAM_ROOT.rglob("*")):
        if source.is_dir():
            continue
        assert source.is_file()
        assert not source.is_symlink()
        relative_path = source.relative_to(UPSTREAM_ROOT).as_posix()
        observed[relative_path] = sha256(source.read_bytes()).hexdigest()
    assert observed == EXPECTED_SOURCE_HASHES
    license_text = (UPSTREAM_ROOT / "assets/LICENSE.txt").read_text()
    assert license_text.startswith("MIT License\n")
    assert "Copyright (c) 2026 AliyunSecAI" in license_text


def test_upstream_cloud_off_switch_does_not_disable_openclaw_config_audit() -> None:
    main_script = (UPSTREAM_ROOT / "scripts/main.sh").read_text()
    basic_udf = (UPSTREAM_ROOT / "scripts/basic_udf.sh").read_text()

    assert "ALIYUN_SKILL_SEC_CLOUD=${ALIYUN_SKILL_SEC_CLOUD:-true}" in main_script
    assert 'if [ "$ALIYUN_SKILL_SEC_CLOUD" = "true" ]; then' in main_script
    assert 'if [ "$ALIYUN_SKILL_SEC_CLOUD" != "true" ]; then' in main_script
    assert "openclaw security audit --deep" in main_script
    assert "\n    run_config_audit\n" in main_script
    assert '--host) host="$2"' in basic_udf
    assert '-T "${zip_file}"' in basic_udf
    assert '"$presigned_url"' in basic_udf


def test_offline_runner_is_closed_to_exact_inputs_and_network() -> None:
    runner = RUNNER_PATH.read_text()
    assert "env -i" in runner
    assert "ALIYUN_SKILL_SEC_CLOUD=false" in runner
    assert "HOME=/var/empty" in runner
    assert "(deny network*)" in runner
    assert "sandbox-exec" in runner
    assert '"$task_tmp/collector.py"' in runner
    assert "sandbox_exit_code=$?" in runner
    assert "openclaw security audit" not in runner
    assert "curl " not in runner
    for skill_name in EXPECTED_SKILLS:
        assert skill_name in runner


def _missing_skill(document: dict[str, Any]) -> None:
    document["skill_inputs"].pop()


def _forged_pass(document: dict[str, Any]) -> None:
    document["scan"]["official_compatible_scan_status"] = "PASS"


def _changed_input_hash(document: dict[str, Any]) -> None:
    document["skill_inputs"][0]["sha256"] = f"sha256:{'f' * 64}"


def _changed_source_hash(document: dict[str, Any]) -> None:
    document["official_source"]["source_files"][0]["sha256"] = f"sha256:{'f' * 64}"


def _absolute_input_path(document: dict[str, Any]) -> None:
    document["skill_inputs"][0]["relative_path"] = "/Users/example/secret/SKILL.md"


def _runtime_overclaim(document: dict[str, Any]) -> None:
    document["integration"]["runtime_consumption"] = True


def _network_overclaim(document: dict[str, Any]) -> None:
    document["execution_boundary"]["network"]["external_network_observed"] = True


def _source_credential_forgery(document: dict[str, Any]) -> None:
    document["official_source"]["acquisition"]["credentials_used"] = True


def _reason_code_forgery(document: dict[str, Any]) -> None:
    document["scan"]["official_inconclusive_reason_code"] = "ALL_SAFE"


def _command_hash_forgery(document: dict[str, Any]) -> None:
    document["execution_boundary"]["command_receipt"]["canonical_argv_sha256"] = (
        f"sha256:{'f' * 64}"
    )


def _sandbox_profile_forgery(document: dict[str, Any]) -> None:
    document["execution_boundary"]["network"]["sandbox_profile_sha256"] = f"sha256:{'f' * 64}"


def _exit_code_forgery(document: dict[str, Any]) -> None:
    document["execution_boundary"]["command_receipt"]["sandbox_exec_exit_code"] = 1


def _command_absolute_path_forgery(document: dict[str, Any]) -> None:
    document["execution_boundary"]["command_receipt"]["canonical_argv"][16] = (
        "/Users/example/private/collector.py"
    )


def _scenario_replay_forgery(document: dict[str, Any]) -> None:
    scenarios = document["scan"]["results"][0]["scenario_results"]
    scenarios[1] = deepcopy(scenarios[0])


def _missing_limitation(document: dict[str, Any]) -> None:
    document["limitations"][-1] = "ALL_SAFE"


def _credential_output(document: dict[str, Any]) -> None:
    fake = "ghp_" + ("A" * 36)
    document["execution_boundary"]["network"]["observation_semantics"] = (
        f"Network scope remains bounded, but this forged record includes {fake}."
    )


@pytest.mark.parametrize(
    "mutate",
    [
        _missing_skill,
        _forged_pass,
        _changed_input_hash,
        _changed_source_hash,
        _absolute_input_path,
        _runtime_overclaim,
        _network_overclaim,
        _source_credential_forgery,
        _reason_code_forgery,
        _command_hash_forgery,
        _sandbox_profile_forgery,
        _exit_code_forgery,
        _command_absolute_path_forgery,
        _scenario_replay_forgery,
        _missing_limitation,
        _credential_output,
    ],
)
def test_schema_and_semantics_reject_evidence_forgery(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    validator = load_validator()
    document = evidence()
    mutate(document)
    with pytest.raises(validator.EvidenceValidationError):
        validator.validate_semantics(document, strict=True)


@pytest.mark.parametrize(
    "payload",
    [
        '{"same":1,"same":2}',
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"value":-Infinity}',
        '{"value":1e9999}',
    ],
)
def test_cli_rejects_duplicate_keys_and_non_finite_numbers_without_reflection(
    payload: str,
) -> None:
    result = subprocess.run(
        [sys.executable, str(VALIDATOR_PATH), "--strict", "-"],
        cwd=ROOT,
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert payload not in result.stdout
    assert payload not in result.stderr


def test_cli_duplicate_key_attack_on_valid_evidence_fails_closed() -> None:
    payload = EVIDENCE_PATH.read_text().replace(
        '"schema_version": "1.1",',
        '"schema_version": "1.1",\n  "schema_version": "1.1",',
        1,
    )
    result = subprocess.run(
        [sys.executable, str(VALIDATOR_PATH), "--strict", "-"],
        cwd=ROOT,
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert "schema_version" not in result.stdout
    assert "schema_version" not in result.stderr


def test_collector_refuses_unsandboxed_real_repository_inputs_without_reflection() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(COLLECTOR_PATH),
            "--source-root",
            str(UPSTREAM_ROOT),
            "--skills-root",
            str(DEPLOY / "skills"),
            "--collected-at",
            "2026-08-21T16:30:00+08:00",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert str(ROOT) not in result.stdout
    assert str(ROOT) not in result.stderr


def test_evidence_keeps_official_results_inconclusive_and_runtime_false() -> None:
    document = evidence()
    assert document["official_source"]["acquisition"]["network_used"] is True
    assert document["official_source"]["acquisition"]["credentials_used"] is False
    assert document["execution_boundary"]["network"]["external_network_observed"] is False
    assert document["execution_boundary"]["network"]["scope"] == (
        "SANDBOXED_COLLECTION_INVOCATION_ONLY"
    )
    assert document["execution_boundary"]["command_receipt"]["sandbox_exec_exit_code"] == 0
    assert document["scan"]["official_inconclusive_reason_code"] == (
        "OFFICIAL_TARGET_POLICY_EXCLUDES_SKILL_MD_ONLY_INPUTS"
    )
    assert document["scan"]["official_compatible_scan_status"] == (
        "INCONCLUSIVE_NO_ANALYZABLE_TARGETS"
    )
    assert document["scan"]["official_compatible_target_file_count"] == 0
    assert {item["skill_name"] for item in document["scan"]["results"]} == EXPECTED_SKILLS
    assert all(
        item["supplemental_contract_scan"]["status"] == "NO_INDICATOR_MATCHES"
        for item in document["scan"]["results"]
    )
    assert document["integration"] == {
        "recommended_agent_identity": "audit-agent",
        "recommended_stage": "DEPLOYMENT_PREFLIGHT",
        "official_skill_assigned_to_worker": False,
        "runtime_consumption": False,
        "live_worker_execution": False,
        "llm_inference": False,
        "agentteams_resources_mutated": False,
        "cloud_service_used": False,
    }
    serialized = json.dumps(document, ensure_ascii=False)
    assert "/Users/" not in serialized
    assert "/home/" not in serialized
