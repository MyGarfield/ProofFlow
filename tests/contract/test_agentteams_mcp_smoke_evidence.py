import importlib.util
import json
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).parents[2]
DEPLOY = ROOT / "deploy/agentteams"
SNAPSHOT_PATH = DEPLOY / "evidence/mcp-manager-operator-smoke-2026-08-20.json"
INFRA_SNAPSHOT_PATH = DEPLOY / "evidence/local-infra-smoke-2026-08-20.json"
SCHEMA_PATH = DEPLOY / "evidence/mcp-smoke-evidence.schema.json"
VALIDATOR_PATH = DEPLOY / "scripts/validate_mcp_smoke_evidence.py"
SUPPLY_CHAIN_EVIDENCE_PATH = ROOT / "deploy/tool-service/evidence/supply-chain-evidence.json"
EXPECTED_SKILL_ASSIGNMENTS = {
    "case-manager": {"human_approval", "document_package"},
    "evidence-agent": {"evidence_ingest", "timeline_build"},
    "rule-agent": {"rule_retrieve"},
    "calculation-agent": {"deterministic_calculate"},
    "strategy-agent": set(),
    "audit-agent": {"conflict_detect", "decision_audit"},
}
EXPECTED_TOOL_SERVICE_IMAGE_ID = (
    "sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775"
)
EXPECTED_TOOL_SERVICE_RUNTIME = {
    "container_name": "proofflow-tool-service",
    "image_id": EXPECTED_TOOL_SERVICE_IMAGE_ID,
    "state": "running",
    "health": "healthy",
    "service_port": 8787,
    "host_port_published": False,
    "security_profile": {
        "user": "65532:65532",
        "read_only_rootfs": True,
        "privileged": False,
        "cap_add": [],
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
    },
    "resource_limits": {
        "pids_limit": 128,
        "memory_bytes": 268435456,
        "memory_swap_bytes": 536870912,
        "nano_cpus": 1000000000,
        "tmpfs_tmp": "rw,noexec,nosuid,size=16m",
    },
    "network_profile": {
        "network_mode": "agentteams-net",
        "network_aliases": ["proofflow-tool-service.local"],
    },
}


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("agentteams_mcp_smoke_validator", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot() -> dict[str, Any]:
    return json.loads(SNAPSHOT_PATH.read_text())


def test_mcp_snapshot_passes_real_schema_and_strict_semantic_validation() -> None:
    document = snapshot()
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = load_validator()

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert document["schema_version"] == schema["properties"]["schema_version"]["const"] == "1.2"
    assert document["collector"]["version"] == "1.2"
    Draft202012Validator.check_schema(schema)
    assert (
        list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document))
        == []
    )
    validator.validate_semantics(document)
    validator.validate_semantics(document, strict=True)


def test_infrastructure_and_manager_mcp_smoke_are_distinct_evidence_layers() -> None:
    infrastructure = json.loads(INFRA_SNAPSHOT_PATH.read_text())
    mcp_smoke = snapshot()
    baseline = json.loads((DEPLOY / "baseline.json").read_text())

    assert infrastructure["evidence_kind"] == "agentteams-local-infra-smoke"
    assert infrastructure["summary"]["claim_level"] == "local-infrastructure-smoke-only"
    assert mcp_smoke["evidence_kind"] == "agentteams-manager-operator-mcp-smoke"
    assert mcp_smoke["summary"]["claim_level"] == "manager-operator-public-synthetic-mcp-smoke-only"
    assert infrastructure["collected_at"] < mcp_smoke["collected_at"]
    assert mcp_smoke["scope"]["worker_execution"] is False
    assert mcp_smoke["scope"]["llm_inference"] is False
    assert mcp_smoke["resources"]["team"]["operational_ready"] is False
    assert baseline["local_infrastructure_evidence"] == str(INFRA_SNAPSHOT_PATH.relative_to(DEPLOY))
    assert baseline["mcp_runtime_evidence"] == str(SNAPSHOT_PATH.relative_to(DEPLOY))
    assert baseline["mcp_runtime_observed_at"] < mcp_smoke["collected_at"]
    assert baseline["resource_inventory_observed_at"] < mcp_smoke["collected_at"]
    assert (
        baseline["tool_service_runtime_observed_at"]
        == (mcp_smoke["tool_service_runtime"]["observed_at"])
    )
    assert baseline["tool_service_runtime_observed_at"] < mcp_smoke["collected_at"]
    assert baseline["tool_service_runtime_evidence"] == str(SNAPSHOT_PATH.relative_to(DEPLOY))
    assert baseline["tool_service_image_id"] == EXPECTED_TOOL_SERVICE_IMAGE_ID
    assert (
        baseline["skill_distribution_observed_at"]
        == (mcp_smoke["skill_distribution"]["observed_at"])
    )
    assert mcp_smoke["skill_distribution"]["observed_at"] == mcp_smoke["collected_at"]
    assert baseline["skill_distribution_evidence"] == str(SNAPSHOT_PATH.relative_to(DEPLOY))
    assert baseline["skill_distribution_status"] == (
        "SIX_WORKER_ASSIGNMENTS_EIGHT_SKILLS_REPOSITORY_MANAGER_MINIO_SHA256_MATCH"
    )
    assert (
        "no Worker loaded, discovered, or executed a Skill"
        in baseline["skill_distribution_status_subject"]
    )
    assert (DEPLOY / baseline["tool_service_supply_chain_evidence"]).resolve() == (
        SUPPLY_CHAIN_EVIDENCE_PATH.resolve()
    )


def apply_attack(document: dict[str, Any], attack: str) -> None:
    if attack.startswith("missing-"):
        del document[attack.removeprefix("missing-")]
    elif attack == "root-extra":
        document["token"] = "must-not-be-reflected"
    elif attack == "privacy-false-claim":
        document["privacy"]["credential_values_inspected_or_emitted"] = True
    elif attack == "scope-worker-execution":
        document["scope"]["worker_execution"] = True
    elif attack == "claim-production":
        document["summary"]["claim_level"] = "production-ready"
    elif attack == "tool-service-image-repin":
        document["tool_service_image_id"] = f"sha256:{'f' * 64}"
    elif attack == "runtime-image-repin":
        document["tool_service_runtime"]["image_id"] = f"sha256:{'f' * 64}"
    elif attack == "runtime-root-user":
        document["tool_service_runtime"]["security_profile"]["user"] = "0:0"
    elif attack == "runtime-cap-drop-removed":
        document["tool_service_runtime"]["security_profile"]["cap_drop"] = []
    elif attack == "runtime-host-port-published":
        document["tool_service_runtime"]["host_port_published"] = True
    elif attack == "runtime-resource-limit-weakened":
        document["tool_service_runtime"]["resource_limits"]["pids_limit"] = 0
    elif attack == "runtime-observed-after-collection":
        document["tool_service_runtime"]["observed_at"] = "2026-08-21T14:07:05Z"
    elif attack == "skill-assignment-rebind":
        assignments = {
            item["worker_name"]: item
            for item in document["skill_distribution"]["worker_assignments"]
        }
        assignments["case-manager"]["assigned_skills"].remove("document_package")
        assignments["strategy-agent"]["assigned_skills"].append("document_package")
    elif attack == "skill-content-repin":
        content = document["skill_distribution"]["skill_content"][0]
        replacement = f"sha256:{'f' * 64}"
        content["repository_sha256"] = replacement
        content["manager_source_sha256"] = replacement
        content["worker_storage"][0]["sha256"] = replacement
    elif attack == "skill-manager-hash":
        document["skill_distribution"]["skill_content"][0]["manager_source_sha256"] = (
            f"sha256:{'f' * 64}"
        )
    elif attack == "skill-storage-worker-rebind":
        document["skill_distribution"]["skill_content"][0]["worker_storage"][0]["worker_name"] = (
            "case-manager"
        )
    elif attack == "skill-repository-path-rebind":
        document["skill_distribution"]["skill_content"][0]["repository_path"] = (
            "skills/decision_audit/SKILL.md"
        )
    elif attack == "skill-observed-at":
        document["skill_distribution"]["observed_at"] = "2026-08-19T20:35:40Z"
    elif attack == "server-rebind":
        document["mcp_servers"][0]["tools"] = ["retrieve_rules"]
        document["mcp_servers"][0]["allowed_consumers"] = [
            "manager",
            "worker-rule-agent",
        ]
    elif attack == "server-extra-consumer":
        document["mcp_servers"][0]["allowed_consumers"].append("worker-calculation-agent")
    elif attack == "probe-status":
        document["access_probes"][0]["http_status"] = 403
    elif attack == "probe-rebind":
        first, second = document["access_probes"]
        first["caller"], second["caller"] = second["caller"], first["caller"]
        first["expected_http_status"], second["expected_http_status"] = (
            second["expected_http_status"],
            first["expected_http_status"],
        )
        first["http_status"], second["http_status"] = (
            second["http_status"],
            first["http_status"],
        )
        first["outcome"], second["outcome"] = second["outcome"], first["outcome"]
    elif attack == "workflow-total":
        document["manager_workflow"]["deterministic_calculate"]["observed_total_decimal_string"] = (
            "60000.00"
        )
    elif attack == "workflow-hash":
        document["manager_workflow"]["deterministic_calculate"]["output_hash"] = (
            f"sha256:{'f' * 64}"
        )
    elif attack == "tamper-success":
        document["manager_workflow"]["tamper_probe"].update(
            {
                "deterministic_calculate_status": "SUCCESS",
                "issue_codes": [],
                "value_is_null": False,
            }
        )
    elif attack == "worker-running":
        document["resources"]["workers"][0]["phase"] = "Running"
    elif attack == "worker-mcp-rebind":
        evidence_worker = document["resources"]["workers"][1]
        rule_worker = document["resources"]["workers"][2]
        evidence_worker["mcp_servers"], rule_worker["mcp_servers"] = (
            rule_worker["mcp_servers"],
            evidence_worker["mcp_servers"],
        )
    elif attack == "team-pending":
        document["resources"]["team"]["controller_phase"] = "Pending"
    elif attack == "team-ready":
        document["resources"]["team"]["operational_ready"] = True
    elif attack == "human-secret":
        document["resources"]["humans"][0]["initialPassword"] = "must-not-be-reflected"
    elif attack == "summary-worker-runtime":
        document["summary"]["worker_runtime_observed"] = True
    elif attack == "summary-skill-runtime":
        document["summary"]["skill_runtime_consumption_observed"] = True
    elif attack == "summary-runtime-profile":
        document["summary"]["tool_service_runtime_profile_verified"] = False
    elif attack == "skill-summary-count":
        document["skill_distribution"]["summary"]["manager_repository_hash_matches"] = 7
    elif attack == "invalid-date-time":
        document["collected_at"] = "not-a-date-time"
    elif attack == "provenance-upgrade":
        document["provenance"]["gateway_acl"] = "signed-attestation"
    elif attack == "limitations-rewritten":
        document["limitations"] = ["production ready"] * 4
    else:
        raise AssertionError(f"unknown attack: {attack}")


@pytest.mark.parametrize(
    "attack",
    [
        "missing-collected_at",
        "missing-tool_service_image_id",
        "missing-tool_service_runtime",
        "missing-collector",
        "missing-scope",
        "missing-provenance",
        "missing-privacy",
        "missing-skill_distribution",
        "missing-limitations",
        "root-extra",
        "privacy-false-claim",
        "scope-worker-execution",
        "claim-production",
        "tool-service-image-repin",
        "runtime-image-repin",
        "runtime-root-user",
        "runtime-cap-drop-removed",
        "runtime-host-port-published",
        "runtime-resource-limit-weakened",
        "runtime-observed-after-collection",
        "skill-assignment-rebind",
        "skill-content-repin",
        "skill-manager-hash",
        "skill-storage-worker-rebind",
        "skill-repository-path-rebind",
        "skill-observed-at",
        "server-rebind",
        "server-extra-consumer",
        "probe-status",
        "probe-rebind",
        "workflow-total",
        "workflow-hash",
        "tamper-success",
        "worker-running",
        "worker-mcp-rebind",
        "team-pending",
        "team-ready",
        "human-secret",
        "summary-worker-runtime",
        "summary-skill-runtime",
        "summary-runtime-profile",
        "skill-summary-count",
        "invalid-date-time",
        "provenance-upgrade",
        "limitations-rewritten",
    ],
)
def test_mcp_schema_and_semantics_reject_public_evidence_attacks(attack: str) -> None:
    validator = load_validator()
    document = snapshot()
    apply_attack(document, attack)

    with pytest.raises(validator.McpSmokeValidationError):
        validator.validate_semantics(document, strict=True)


@pytest.mark.parametrize(
    "attack",
    [
        "tool-service-image-repin",
        "runtime-image-repin",
        "runtime-observed-after-collection",
        "skill-assignment-rebind",
        "skill-content-repin",
        "skill-manager-hash",
        "skill-storage-worker-rebind",
        "skill-repository-path-rebind",
        "skill-observed-at",
        "server-rebind",
        "probe-rebind",
        "worker-mcp-rebind",
    ],
)
def test_semantics_reject_cross_field_rebinding_that_schema_shape_allows(attack: str) -> None:
    validator = load_validator()
    document = snapshot()
    apply_attack(document, attack)

    validator.validate_schema(document)
    with pytest.raises(validator.McpSmokeValidationError):
        validator.validate_semantics(document, strict=True)


def test_tool_service_image_id_is_bound_to_validated_supply_chain_evidence() -> None:
    validator = load_validator()
    document = snapshot()
    supply_chain = json.loads(SUPPLY_CHAIN_EVIDENCE_PATH.read_text())

    assert document["tool_service_image_id"] == EXPECTED_TOOL_SERVICE_IMAGE_ID
    assert document["tool_service_runtime"]["image_id"] == EXPECTED_TOOL_SERVICE_IMAGE_ID
    assert supply_chain["subject"]["image_id"] == EXPECTED_TOOL_SERVICE_IMAGE_ID
    validator.validate_semantics(document, strict=True)

    document["tool_service_image_id"] = f"sha256:{'f' * 64}"
    validator.validate_schema(document)
    with pytest.raises(
        validator.McpSmokeValidationError,
        match="does not match the supply-chain evidence",
    ):
        validator.validate_semantics(document, strict=True)


def test_tool_service_runtime_profile_is_public_safe_and_fail_closed() -> None:
    document = snapshot()
    runtime = document["tool_service_runtime"]
    observed_at = runtime.pop("observed_at")

    assert runtime == EXPECTED_TOOL_SERVICE_RUNTIME
    assert observed_at < document["collected_at"]
    assert document["summary"]["tool_service_runtime_profile_verified"] is True


def test_skill_distribution_is_exact_and_hash_bound_to_repository_contracts() -> None:
    document = snapshot()
    distribution = document["skill_distribution"]
    assignments = {
        item["worker_name"]: set(item["assigned_skills"])
        for item in distribution["worker_assignments"]
    }
    content_by_name = {item["skill_name"]: item for item in distribution["skill_content"]}

    assert assignments == EXPECTED_SKILL_ASSIGNMENTS
    assert sum(len(skills) for skills in assignments.values()) == 8
    assert set(content_by_name) == set().union(*EXPECTED_SKILL_ASSIGNMENTS.values())
    for skill_name, content in content_by_name.items():
        repository_path = DEPLOY / content["repository_path"]
        repository_hash = f"sha256:{sha256(repository_path.read_bytes()).hexdigest()}"
        expected_workers = {
            worker for worker, skills in EXPECTED_SKILL_ASSIGNMENTS.items() if skill_name in skills
        }

        assert content["repository_sha256"] == repository_hash
        assert content["manager_source_observed"] is True
        assert content["manager_source_sha256"] == repository_hash
        assert content["manager_matches_repository"] is True
        assert {item["worker_name"] for item in content["worker_storage"]} == expected_workers
        assert all(item["object_observed"] is True for item in content["worker_storage"])
        assert all(item["sha256"] == repository_hash for item in content["worker_storage"])
        assert all(item["matches_repository"] is True for item in content["worker_storage"])

    assert distribution["summary"] == {
        "proof_flow_workers": 6,
        "assignment_entries": 8,
        "distinct_skills": 8,
        "repository_source_files_observed": 8,
        "manager_repository_hash_matches": 8,
        "worker_storage_objects_observed": 8,
        "worker_storage_repository_hash_matches": 8,
        "exact_assignment_match": True,
        "all_content_hashes_match": True,
        "worker_runtime_consumption_observed": False,
    }


@pytest.mark.parametrize(
    "attack",
    [
        "root-extra",
        "claim-production",
        "skill-content-repin",
        "server-rebind",
        "probe-status",
        "team-ready",
    ],
)
def test_strict_cli_rejects_attacks_without_reflecting_values(tmp_path: Path, attack: str) -> None:
    document = snapshot()
    apply_attack(document, attack)
    attack_path = tmp_path / "attacked-mcp-evidence.json"
    attack_path.write_text(json.dumps(document))

    result = subprocess.run(
        [sys.executable, str(VALIDATOR_PATH), "--strict", str(attack_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "must-not-be-reflected" not in result.stdout
    assert "must-not-be-reflected" not in result.stderr


@pytest.mark.parametrize(
    "payload",
    [
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"value":-Infinity}',
        '{"value":1e9999}',
        '{"same":1,"same":1}',
        '{"nested":{"same":1,"same":2}}',
    ],
)
def test_mcp_validator_rejects_non_finite_numbers_and_duplicate_keys(payload: str) -> None:
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


def test_mcp_snapshot_contains_only_allowlisted_identity_and_privacy_fields() -> None:
    document = snapshot()
    forbidden_keys = {
        "token",
        "cookie",
        "password",
        "initialPassword",
        "matrixUserID",
        "roomID",
        "raw_content",
        "raw_content_base64",
        "response_body",
        "environment",
    }

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            assert forbidden_keys.isdisjoint(value)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(document)
    assert document["privacy"] == {
        "existing_client_credentials_used": True,
        "credential_values_inspected_or_emitted": False,
        "cookies_inspected_or_emitted": False,
        "environment_dumped": False,
        "raw_material_values_emitted": False,
        "personal_identifiers_emitted": False,
    }


def test_agentteams_docs_keep_team_active_and_manager_smoke_claims_narrow() -> None:
    readme = (DEPLOY / "README.md").read_text()
    evidence_doc = (DEPLOY / "LOCAL_INFRA_EVIDENCE.md").read_text()

    assert "两个先后发生的证据层" in readme
    assert "operational_ready=false" in readme
    assert "Manager 操作员能调用 MCP 不等于" in readme
    assert "八条 Skill assignment" in readme
    assert "没有任何 Skill 被 Worker 加载" in readme
    assert "不能倒推扩大这份较早基础设施快照" in evidence_doc
    assert "两个证据层都未启动 Worker 或 LLM" in evidence_doc
    assert "八份已分配 MinIO Worker-storage" in evidence_doc


def test_mcp_validator_unknown_argument_is_redacted() -> None:
    sentinel = "do-not-reflect-this-mcp-value"
    result = subprocess.run(
        [sys.executable, str(VALIDATOR_PATH), f"--unknown={sentinel}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert sentinel not in result.stdout
    assert sentinel not in result.stderr
