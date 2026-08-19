#!/usr/bin/env python3
"""Validate public-safe AgentTeams Manager-operator MCP smoke evidence."""

from __future__ import annotations

import json
import math
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any, NoReturn, TextIO

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

AGENTTEAMS_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = AGENTTEAMS_ROOT / "evidence/mcp-smoke-evidence.schema.json"
SUPPLY_CHAIN_EVIDENCE_PATH = (
    Path(__file__).resolve().parents[2] / "tool-service/evidence/supply-chain-evidence.json"
)
SUPPLY_CHAIN_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "tool-service/evidence/supply-chain-evidence.schema.json"
)
EXPECTED_SCHEMA_VERSION = "1.1"
IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

EXPECTED_SERVERS = {
    "mcp-proof-evidence": (
        ("evidence_ingest",),
        ("manager", "worker-evidence-agent"),
    ),
    "mcp-proof-rules": (
        ("retrieve_rules",),
        ("manager", "worker-rule-agent"),
    ),
    "mcp-proof-calc": (
        ("deterministic_calculate",),
        ("manager", "worker-calculation-agent"),
    ),
}
EXPECTED_PROBES = {
    "evidence-worker-evidence-tools-list": {
        "caller": "worker-evidence-agent",
        "target": "mcp-proof-evidence",
        "operation": "tools/list",
        "expected_http_status": 200,
        "http_status": 200,
        "outcome": "allow",
    },
    "calculation-worker-evidence-tools-list": {
        "caller": "worker-calculation-agent",
        "target": "mcp-proof-evidence",
        "operation": "tools/list",
        "expected_http_status": 403,
        "http_status": 403,
        "outcome": "deny",
    },
}
EXPECTED_WORKERS = {
    "case-manager": ("team_leader", ()),
    "evidence-agent": ("worker", ("mcp-proof-evidence",)),
    "rule-agent": ("worker", ("mcp-proof-rules",)),
    "calculation-agent": ("worker", ("mcp-proof-calc",)),
    "strategy-agent": ("worker", ()),
    "audit-agent": ("worker", ()),
}
EXPECTED_SKILL_ASSIGNMENTS = {
    "case-manager": frozenset({"human_approval", "document_package"}),
    "evidence-agent": frozenset({"evidence_ingest", "timeline_build"}),
    "rule-agent": frozenset({"rule_retrieve"}),
    "calculation-agent": frozenset({"deterministic_calculate"}),
    "strategy-agent": frozenset(),
    "audit-agent": frozenset({"conflict_detect", "decision_audit"}),
}
EXPECTED_SKILL_WORKERS = {
    skill: frozenset({worker})
    for worker, skills in EXPECTED_SKILL_ASSIGNMENTS.items()
    for skill in skills
}
EXPECTED_HUMANS = {"proof-reviewer", "proof-approver"}


class McpSmokeValidationError(ValueError):
    """A public MCP smoke evidence invariant was violated."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise McpSmokeValidationError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_non_finite_constant(_value: str) -> NoReturn:
    raise McpSmokeValidationError("non-finite JSON number")


def _finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise McpSmokeValidationError("non-finite JSON number")
    return parsed


def _load_json(stream: TextIO) -> Any:
    return json.load(
        stream,
        object_pairs_hook=_object_without_duplicate_keys,
        parse_constant=_reject_non_finite_constant,
        parse_float=_finite_json_float,
    )


def load_evidence(path: str) -> dict[str, Any]:
    try:
        if path == "-":
            document = _load_json(sys.stdin)
        else:
            with Path(path).open(encoding="utf-8") as stream:
                document = _load_json(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise McpSmokeValidationError("evidence is not readable strict JSON") from exc
    if not isinstance(document, dict):
        raise McpSmokeValidationError("evidence root must be an object")
    return document


def _load_schema() -> dict[str, Any]:
    try:
        with SCHEMA_PATH.open(encoding="utf-8") as stream:
            schema = _load_json(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise McpSmokeValidationError("MCP evidence schema is not readable strict JSON") from exc
    if not isinstance(schema, dict):
        raise McpSmokeValidationError("MCP evidence schema root must be an object")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise McpSmokeValidationError("MCP evidence schema is not valid Draft 2020-12") from exc
    return schema


def _load_strict_object(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            document = _load_json(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise McpSmokeValidationError(f"{label} is not readable strict JSON") from exc
    if not isinstance(document, dict):
        raise McpSmokeValidationError(f"{label} root must be an object")
    return document


def _load_supply_chain_image_id() -> str:
    evidence = _load_strict_object(SUPPLY_CHAIN_EVIDENCE_PATH, "tool-service supply-chain evidence")
    schema = _load_strict_object(SUPPLY_CHAIN_SCHEMA_PATH, "tool-service supply-chain schema")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise McpSmokeValidationError(
            "tool-service supply-chain schema is not valid Draft 2020-12"
        ) from exc
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    if next(validator.iter_errors(evidence), None) is not None:
        raise McpSmokeValidationError(
            "tool-service supply-chain evidence does not conform to its JSON Schema"
        )
    subject = evidence.get("subject")
    if not isinstance(subject, dict):
        raise McpSmokeValidationError(
            "tool-service supply-chain evidence subject must be an object"
        )
    image_id = subject.get("image_id")
    if not isinstance(image_id, str) or IMAGE_ID_PATTERN.fullmatch(image_id) is None:
        raise McpSmokeValidationError("tool-service supply-chain evidence image ID is invalid")
    return image_id


def _repository_skill_sha256(skill_name: str) -> str:
    path = AGENTTEAMS_ROOT / "skills" / skill_name / "SKILL.md"
    if path.is_symlink():
        raise McpSmokeValidationError("a repository Skill contract must not be a symbolic link")
    try:
        return f"sha256:{sha256(path.read_bytes()).hexdigest()}"
    except OSError as exc:
        raise McpSmokeValidationError("a repository Skill contract is not readable") from exc


def validate_schema(document: dict[str, Any]) -> None:
    validator = Draft202012Validator(_load_schema(), format_checker=FormatChecker())
    if next(validator.iter_errors(document), None) is not None:
        raise McpSmokeValidationError("evidence does not conform to the MCP JSON Schema")


def _mapping(document: dict[str, Any], key: str) -> dict[str, Any]:
    value = document.get(key)
    if not isinstance(value, dict):
        raise McpSmokeValidationError(f"{key} must be an object")
    return value


def _records(document: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = document.get(key)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise McpSmokeValidationError(f"{key} must be an array of objects")
    return value


def _index_exact(
    records: list[dict[str, Any]], key: str, expected: set[str], label: str
) -> dict[str, dict[str, Any]]:
    identifiers = [item.get(key) for item in records]
    if any(not isinstance(identifier, str) for identifier in identifiers):
        raise McpSmokeValidationError(f"{label} identifiers must be strings")
    if len(identifiers) != len(set(identifiers)):
        raise McpSmokeValidationError(f"{label} identifiers must be unique")
    if set(identifiers) != expected:
        raise McpSmokeValidationError(f"{label} identifiers do not match the contract")
    return {item[key]: item for item in records}


def validate_semantics(document: dict[str, Any], *, strict: bool = False) -> None:
    validate_schema(document)
    if document.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        raise McpSmokeValidationError("schema version is outside the contract")
    if document.get("tool_service_image_id") != _load_supply_chain_image_id():
        raise McpSmokeValidationError(
            "tool-service image ID does not match the supply-chain evidence"
        )

    servers = _index_exact(
        _records(document, "mcp_servers"),
        "name",
        set(EXPECTED_SERVERS),
        "MCP server",
    )
    exact_acl_match = True
    for name, (expected_tools, expected_consumers) in EXPECTED_SERVERS.items():
        server = servers[name]
        if server.get("status") != "ok" or server.get("tool_count") != len(expected_tools):
            raise McpSmokeValidationError("MCP server status or tool count is inconsistent")
        if tuple(server.get("tools", ())) != expected_tools:
            raise McpSmokeValidationError("MCP tool inventory does not match its server")
        if tuple(server.get("allowed_consumers", ())) != expected_consumers:
            exact_acl_match = False
    if not exact_acl_match:
        raise McpSmokeValidationError(
            "MCP consumer ACL does not match the least-privilege contract"
        )

    probes = _index_exact(
        _records(document, "access_probes"),
        "probe_id",
        set(EXPECTED_PROBES),
        "access probe",
    )
    for probe_id, expected in EXPECTED_PROBES.items():
        probe = probes[probe_id]
        for key, expected_value in expected.items():
            if probe.get(key) != expected_value:
                raise McpSmokeValidationError("access probe result is inconsistent")

    workflow = _mapping(document, "manager_workflow")
    evidence_ingest = _mapping(workflow, "evidence_ingest")
    rule_retrieve = _mapping(workflow, "rule_retrieve")
    calculation = _mapping(workflow, "deterministic_calculate")
    tamper = _mapping(workflow, "tamper_probe")
    positive_workflow_passed = bool(
        evidence_ingest.get("calls") == 3
        and evidence_ingest.get("successful_calls") == 3
        and evidence_ingest.get("emitted_evidence_objects") == 13
        and rule_retrieve.get("status") == "SUCCESS"
        and rule_retrieve.get("citation_count") == 4
        and rule_retrieve.get("missing_issue_code_count") == 0
        and calculation.get("status") == "SUCCESS"
        and calculation.get("observed_total_decimal_string") == "60000"
        and calculation.get("value_present") is True
    )
    tamper_blocked = bool(
        tamper.get("mutation") == "same-scope-value-change-then-reseal"
        and tamper.get("deterministic_calculate_status") == "BLOCKED"
        and tamper.get("issue_codes") == ["UNTRUSTED_EVIDENCE"]
        and tamper.get("value_is_null") is True
    )
    if not positive_workflow_passed or not tamper_blocked:
        raise McpSmokeValidationError("Manager operator workflow result is inconsistent")

    skill_distribution = _mapping(document, "skill_distribution")
    if skill_distribution.get("observed_at") != document.get("collected_at"):
        raise McpSmokeValidationError("Skill distribution observation time is inconsistent")
    assignments = _index_exact(
        _records(skill_distribution, "worker_assignments"),
        "worker_name",
        set(EXPECTED_SKILL_ASSIGNMENTS),
        "Skill assignment Worker",
    )
    exact_skill_assignments = True
    assigned_skill_names: set[str] = set()
    assignment_entries = 0
    for worker_name, expected_skills in EXPECTED_SKILL_ASSIGNMENTS.items():
        assigned_skills = assignments[worker_name].get("assigned_skills")
        if not isinstance(assigned_skills, list) or set(assigned_skills) != expected_skills:
            exact_skill_assignments = False
            continue
        assignment_entries += len(assigned_skills)
        assigned_skill_names.update(assigned_skills)
    if assigned_skill_names != set(EXPECTED_SKILL_WORKERS):
        exact_skill_assignments = False

    skill_content = _index_exact(
        _records(skill_distribution, "skill_content"),
        "skill_name",
        set(EXPECTED_SKILL_WORKERS),
        "Skill content",
    )
    repository_source_files_observed = 0
    manager_repository_hash_matches = 0
    worker_storage_objects_observed = 0
    worker_storage_repository_hash_matches = 0
    all_content_hashes_match = True
    for skill_name, expected_workers in EXPECTED_SKILL_WORKERS.items():
        content = skill_content[skill_name]
        expected_repository_path = f"skills/{skill_name}/SKILL.md"
        repository_hash = _repository_skill_sha256(skill_name)
        if content.get("repository_path") == expected_repository_path:
            repository_source_files_observed += 1
        else:
            all_content_hashes_match = False
        if content.get("repository_sha256") != repository_hash:
            all_content_hashes_match = False
        manager_match = bool(
            content.get("manager_source_observed") is True
            and content.get("manager_source_sha256") == repository_hash
            and content.get("manager_matches_repository") is True
        )
        if manager_match:
            manager_repository_hash_matches += 1
        else:
            all_content_hashes_match = False

        storage = _index_exact(
            _records(content, "worker_storage"),
            "worker_name",
            set(expected_workers),
            "Skill worker-storage copy",
        )
        for storage_copy in storage.values():
            object_observed = storage_copy.get("object_observed") is True
            storage_match = bool(
                object_observed
                and storage_copy.get("sha256") == repository_hash
                and storage_copy.get("matches_repository") is True
            )
            worker_storage_objects_observed += int(object_observed)
            worker_storage_repository_hash_matches += int(storage_match)
            if not storage_match:
                all_content_hashes_match = False

    skill_summary = _mapping(skill_distribution, "summary")
    expected_skill_summary = {
        "proof_flow_workers": len(assignments),
        "assignment_entries": assignment_entries,
        "distinct_skills": len(assigned_skill_names),
        "repository_source_files_observed": repository_source_files_observed,
        "manager_repository_hash_matches": manager_repository_hash_matches,
        "worker_storage_objects_observed": worker_storage_objects_observed,
        "worker_storage_repository_hash_matches": (worker_storage_repository_hash_matches),
        "exact_assignment_match": exact_skill_assignments,
        "all_content_hashes_match": all_content_hashes_match,
        "worker_runtime_consumption_observed": False,
    }
    for key, expected_value in expected_skill_summary.items():
        if skill_summary.get(key) != expected_value:
            raise McpSmokeValidationError("Skill distribution summary is inconsistent")
    skill_distribution_verified = bool(
        exact_skill_assignments
        and assignment_entries == len(EXPECTED_SKILL_WORKERS)
        and len(assigned_skill_names) == len(EXPECTED_SKILL_WORKERS)
        and all_content_hashes_match
    )
    if not skill_distribution_verified:
        raise McpSmokeValidationError("Skill distribution evidence is inconsistent")

    resources = _mapping(document, "resources")
    workers = _index_exact(_records(resources, "workers"), "name", set(EXPECTED_WORKERS), "Worker")
    all_workers_stopped = True
    for name, (expected_role, expected_mcp) in EXPECTED_WORKERS.items():
        worker = workers[name]
        if (
            worker.get("desired_state") != "Stopped"
            or worker.get("phase") != "Stopped"
            or worker.get("runtime") != "openclaw"
            or worker.get("team") != "proof-flow-case-review"
            or worker.get("role") != expected_role
            or tuple(worker.get("mcp_servers", ())) != expected_mcp
        ):
            all_workers_stopped = False
    if not all_workers_stopped or resources.get("proof_flow_worker_containers") != 0:
        raise McpSmokeValidationError("Stopped Worker inventory is inconsistent")

    team = _mapping(resources, "team")
    team_operational_ready = bool(
        team.get("controller_phase") == "Active"
        and team.get("leader_worker_phase") == "Running"
        and team.get("ready_workers") == team.get("specialist_worker_count") == 5
        and resources.get("proof_flow_worker_containers") == team.get("member_count") == 6
    )
    if (
        team.get("leader_name") != "case-manager"
        or team.get("member_count") != 6
        or team.get("specialist_worker_count") != 5
        or team.get("ready_workers") != 0
        or team.get("operational_ready") is not team_operational_ready
    ):
        raise McpSmokeValidationError("Team readiness observation is inconsistent")

    humans = _index_exact(_records(resources, "humans"), "name", EXPECTED_HUMANS, "Human")
    for human in humans.values():
        if (
            human.get("phase") != "Active"
            or human.get("permission_level") != 2
            or human.get("accessible_teams") != ["proof-flow-case-review"]
        ):
            raise McpSmokeValidationError("Human scope observation is inconsistent")

    summary = _mapping(document, "summary")
    expected_summary = {
        "mcp_servers_ok": sum(item.get("status") == "ok" for item in servers.values()),
        "exact_acl_match": exact_acl_match,
        "authorized_tools_list_passed": probes["evidence-worker-evidence-tools-list"].get("outcome")
        == "allow",
        "cross_role_denial_observed": probes["calculation-worker-evidence-tools-list"].get(
            "outcome"
        )
        == "deny",
        "manager_positive_workflow_passed": positive_workflow_passed,
        "resealed_tamper_blocked": tamper_blocked,
        "all_workers_stopped": all_workers_stopped,
        "worker_runtime_observed": resources.get("proof_flow_worker_containers") != 0,
        "team_operational_ready": team_operational_ready,
        "human_resources_configured": len(humans),
        "skill_distribution_verified": skill_distribution_verified,
        "skill_runtime_consumption_observed": skill_summary.get(
            "worker_runtime_consumption_observed"
        ),
    }
    for key, expected_value in expected_summary.items():
        if summary.get(key) != expected_value:
            raise McpSmokeValidationError("MCP smoke summary is inconsistent")

    strict_passed = bool(
        exact_acl_match
        and positive_workflow_passed
        and tamper_blocked
        and all_workers_stopped
        and not expected_summary["worker_runtime_observed"]
        and not team_operational_ready
        and skill_distribution_verified
        and not expected_summary["skill_runtime_consumption_observed"]
    )
    if strict and not strict_passed:
        raise McpSmokeValidationError("strict MCP smoke consistency gate failed")


def _usage() -> None:
    print("Usage: validate_mcp_smoke_evidence.py [--strict] FILE|-", file=sys.stderr)


def _fail(message: str, status: int) -> NoReturn:
    print(f"MCP smoke evidence validation failed: {message}.", file=sys.stderr)
    raise SystemExit(status)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    strict = False
    path: str | None = None
    for argument in arguments:
        if argument == "--strict":
            strict = True
        elif argument in {"-h", "--help"}:
            _usage()
            return 0
        elif argument.startswith("-") and argument != "-":
            _fail("unknown argument was redacted", 2)
        elif path is None:
            path = argument
        else:
            _fail("too many arguments", 2)
    if path is None:
        _usage()
        return 2
    try:
        document = load_evidence(path)
        validate_semantics(document, strict=strict)
    except McpSmokeValidationError as exc:
        _fail(str(exc), 1 if strict else 2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
