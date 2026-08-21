#!/usr/bin/env python3
"""Validate the schema and cross-field semantics of public AgentTeams evidence.

Draft 2020-12 JSON Schema is the wire-contract gate. This validator additionally
covers cross-field invariants and an optional strict collection gate. It never
reports input values, so malformed input cannot turn validation into a reflection
channel.
"""

from __future__ import annotations

import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any, NoReturn, TextIO

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "evidence/public-evidence.schema.json"
EXPECTED_SCHEMA_VERSION = "1.2"

EXPECTED_IMAGE_COMPONENTS = {
    "controller-embedded",
    "manager-openclaw",
    "worker-openclaw",
}
EXPECTED_IMAGE_TAGS = {
    "controller-embedded": (
        "higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-embedded:v1.2.2"
    ),
    "manager-openclaw": (
        "higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-manager:v1.2.2"
    ),
    "worker-openclaw": (
        "higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-worker:v1.2.2"
    ),
}
EXPECTED_LOCAL_IMAGE_IDS = {
    "controller-embedded": (
        "sha256:c7e467bfa5a2a733ea021c19f223180eef85e3e534873feceb8a7a132253125f"
    ),
    "manager-openclaw": "sha256:dd11878943e4a425ff38dcc152c9d44ea0e68d97bac89f711207134b8636c0fb",
    "worker-openclaw": "sha256:301f9e311654eca203246fa666d63a126244ea8793f700603d2a6d37b7ffea75",
}
EXPECTED_REPO_DIGESTS = {
    component: f"{EXPECTED_IMAGE_TAGS[component].rsplit(':', 1)[0]}@{image_id}"
    for component, image_id in EXPECTED_LOCAL_IMAGE_IDS.items()
}
EXPECTED_HTTP_HEALTH_CODES = {
    "controller-api",
    "element-web",
    "higress-console",
    "higress-matrix-route",
    "matrix-versions",
    "minio-live",
}
EXPECTED_BOOLEAN_HEALTH_CHECKS = {
    "controller-container",
    "controller-docker-socket-api",
    "manager-container",
    "manager-openclaw-gateway",
}
EXPECTED_HEALTH_CHECKS = set(EXPECTED_HTTP_HEALTH_CODES) | EXPECTED_BOOLEAN_HEALTH_CHECKS


class EvidenceValidationError(ValueError):
    """A public-safe evidence invariant was violated."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceValidationError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_non_finite_constant(_value: str) -> NoReturn:
    raise EvidenceValidationError("non-finite JSON number")


def _finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise EvidenceValidationError("non-finite JSON number")
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
        raise EvidenceValidationError("evidence is not readable strict JSON") from exc
    if not isinstance(document, dict):
        raise EvidenceValidationError("evidence root must be an object")
    return document


def _load_public_schema() -> dict[str, Any]:
    try:
        with SCHEMA_PATH.open(encoding="utf-8") as stream:
            schema = _load_json(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError("public evidence schema is not readable strict JSON") from exc
    if not isinstance(schema, dict):
        raise EvidenceValidationError("public evidence schema root must be an object")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise EvidenceValidationError("public evidence schema is not valid Draft 2020-12") from exc
    return schema


def validate_schema(document: dict[str, Any]) -> None:
    validator = Draft202012Validator(_load_public_schema(), format_checker=FormatChecker())
    if next(validator.iter_errors(document), None) is not None:
        raise EvidenceValidationError("evidence does not conform to the public JSON Schema")


def _mapping(document: dict[str, Any], key: str) -> dict[str, Any]:
    value = document.get(key)
    if not isinstance(value, dict):
        raise EvidenceValidationError(f"{key} must be an object")
    return value


def _records(document: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = document.get(key)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise EvidenceValidationError(f"{key} must be an array of objects")
    return value


def _require_exact_unique_ids(
    records: list[dict[str, Any]], key: str, expected: set[str], label: str
) -> None:
    identifiers = [item.get(key) for item in records]
    if any(not isinstance(identifier, str) for identifier in identifiers):
        raise EvidenceValidationError(f"{label} identifiers must be strings")
    if len(identifiers) != len(set(identifiers)):
        raise EvidenceValidationError(f"{label} identifiers must be unique")
    if set(identifiers) != expected:
        raise EvidenceValidationError(f"{label} identifiers do not match the contract")


def _require_unique_non_null(values: list[Any], label: str) -> None:
    observed = [value for value in values if value is not None]
    if any(not isinstance(value, str) for value in observed):
        raise EvidenceValidationError(f"{label} values must be strings")
    if len(observed) != len(set(observed)):
        raise EvidenceValidationError(f"{label} values must be unique")


def _expected_source_status(source: dict[str, Any]) -> str:
    if source.get("checkout_supplied") is not True:
        if (
            source.get("observed_commit") is not None
            or source.get("commit_matches") is not False
            or source.get("local_colima_socket_patch_present") is not False
            or source.get("local_embedded_console_patch_present") is not False
            or source.get("checkout_has_local_modifications") is not False
        ):
            return "fail"
        return "skip"
    if source.get("observed_commit") is None:
        return "fail"
    if (
        source.get("commit_matches") is True
        and source.get("local_colima_socket_patch_present") is True
        and source.get("local_embedded_console_patch_present") is True
    ):
        return "pass"
    return "fail"


def _expected_resolver_status(resolver: dict[str, Any], container_socket: dict[str, Any]) -> str:
    if container_socket.get("colima_running") is not True:
        if (
            resolver.get("backup_present") is False
            and resolver.get("backup_first_line_has_invalid_dash_e_prefix") is None
            and resolver.get("current_syntax_allowlist_ok") is None
            and resolver.get("normalized_backup_matches_current") is None
        ):
            return "skip"
        return "fail"
    if resolver.get("current_syntax_allowlist_ok") is not True:
        return "fail"
    if resolver.get("backup_present") is True:
        if (
            resolver.get("backup_first_line_has_invalid_dash_e_prefix") is True
            and resolver.get("normalized_backup_matches_current") is True
        ):
            return "pass"
        return "fail"
    if (
        resolver.get("backup_first_line_has_invalid_dash_e_prefix") is None
        and resolver.get("normalized_backup_matches_current") is None
    ):
        return "pass"
    return "fail"


def _strict_gate_expected(document: dict[str, Any]) -> bool:
    source = _mapping(document, "source")
    resolver = _mapping(document, "resolver")
    container_socket = _mapping(document, "container_socket")
    images = _records(document, "images")
    health_checks = _records(document, "health_checks")
    return bool(
        source.get("verification_status") != "fail"
        and resolver.get("verification_status") != "fail"
        and all(item.get("local_image_id_matches_reference") is True for item in images)
        and all(item.get("repo_digest_matches_reference") is True for item in images)
        and all(item.get("status") == "pass" for item in health_checks)
        and _expected_resolver_status(resolver, container_socket)
        == resolver.get("verification_status")
    )


def _expected_health_status(check: dict[str, Any]) -> str:
    check_id = check.get("check_id")
    if check_id in EXPECTED_HTTP_HEALTH_CODES:
        if (
            check.get("expected_http_status") != "200"
            or check.get("observation") is not None
            or not isinstance(check.get("http_status"), str)
        ):
            raise EvidenceValidationError("HTTP health observation shape is inconsistent")
        return "pass" if check.get("http_status") == "200" else "fail"
    if check_id in EXPECTED_BOOLEAN_HEALTH_CHECKS:
        observation = check.get("observation")
        if (
            check.get("expected_http_status") is not None
            or check.get("http_status") is not None
            or not isinstance(observation, bool)
        ):
            raise EvidenceValidationError("boolean health observation shape is inconsistent")
        return "pass" if observation else "fail"
    raise EvidenceValidationError("health check identifier is outside the contract")


def validate_semantics(document: dict[str, Any], *, strict: bool = False) -> None:
    validate_schema(document)
    if document.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        raise EvidenceValidationError("schema version is outside the contract")
    if document.get("evidence_kind") != "agentteams-local-infra-smoke":
        raise EvidenceValidationError("evidence kind is outside the contract")

    source = _mapping(document, "source")
    runtime = _mapping(document, "runtime")
    resolver = _mapping(document, "resolver")
    container_socket = _mapping(document, "container_socket")
    summary = _mapping(document, "summary")
    images = _records(document, "images")
    health_checks = _records(document, "health_checks")

    _require_exact_unique_ids(images, "component", EXPECTED_IMAGE_COMPONENTS, "image component")
    _require_exact_unique_ids(health_checks, "check_id", EXPECTED_HEALTH_CHECKS, "health check")
    health_by_id = {item["check_id"]: item for item in health_checks}

    for image in images:
        component = image.get("component")
        if image.get("tag") != EXPECTED_IMAGE_TAGS.get(component):
            raise EvidenceValidationError("image tag does not match its component")
        if image.get("reference_local_image_id") != EXPECTED_LOCAL_IMAGE_IDS.get(component):
            raise EvidenceValidationError("reference local image ID is outside the contract")
        if image.get("reference_repo_digest") != EXPECTED_REPO_DIGESTS.get(component):
            raise EvidenceValidationError("reference repository digest is outside the contract")
    _require_unique_non_null(
        [item.get("reference_local_image_id") for item in images], "reference local image ID"
    )
    _require_unique_non_null(
        [item.get("observed_local_image_id") for item in images], "observed local image ID"
    )
    _require_unique_non_null(
        [item.get("reference_repo_digest") for item in images], "reference repository digest"
    )
    _require_unique_non_null(
        [item.get("observed_repo_digest") for item in images], "observed repository digest"
    )

    observed_commit = source.get("observed_commit")
    expected_commit = source.get("expected_commit")
    expected_commit_match = observed_commit is not None and observed_commit == expected_commit
    if source.get("commit_matches") is not expected_commit_match:
        raise EvidenceValidationError("source commit match flag is inconsistent")
    if source.get("verification_status") != _expected_source_status(source):
        raise EvidenceValidationError("source verification status is inconsistent")

    if resolver.get("resolver_addresses_emitted") is not False:
        raise EvidenceValidationError("resolver addresses must not be emitted")
    if resolver.get("resolver_file_hashes_emitted") is not False:
        raise EvidenceValidationError("resolver file hashes must not be emitted")
    if resolver.get("verification_status") != _expected_resolver_status(resolver, container_socket):
        raise EvidenceValidationError("resolver verification status is inconsistent")

    if (
        container_socket.get("colima_daemon_local_socket_present") is True
        and container_socket.get("colima_running") is not True
    ):
        raise EvidenceValidationError("Colima socket observation is inconsistent")
    if (
        container_socket.get("controller_docker_api_ping_ok") is True
        and container_socket.get("controller_socket_present") is not True
    ):
        raise EvidenceValidationError("Controller Docker socket observation is inconsistent")

    for image in images:
        local_match = image.get("observed_local_image_id") is not None and image.get(
            "observed_local_image_id"
        ) == image.get("reference_local_image_id")
        repo_match = image.get("observed_repo_digest") is not None and image.get(
            "observed_repo_digest"
        ) == image.get("reference_repo_digest")
        if image.get("local_image_id_matches_reference") is not local_match:
            raise EvidenceValidationError("local image ID match flag is inconsistent")
        if image.get("repo_digest_matches_reference") is not repo_match:
            raise EvidenceValidationError("repository digest match flag is inconsistent")

    for check in health_checks:
        if check.get("status") != _expected_health_status(check):
            raise EvidenceValidationError("health status does not match its public observation")
    if health_by_id["controller-docker-socket-api"].get("observation") is not container_socket.get(
        "controller_docker_api_ping_ok"
    ):
        raise EvidenceValidationError("Docker socket health observation is inconsistent")
    if (
        health_by_id["manager-openclaw-gateway"].get("observation") is True
        and runtime.get("manager_runtime_observed") != "openclaw"
    ):
        raise EvidenceValidationError("Manager runtime health observation is inconsistent")

    status_values = [item["status"] for item in health_checks]
    statuses = Counter(status_values)
    expected_counts = {
        "passed": statuses["pass"],
        "failed": statuses["fail"],
        "skipped": statuses["skip"],
    }
    for key, expected in expected_counts.items():
        if summary.get(key) != expected:
            raise EvidenceValidationError("health summary counts are inconsistent")
    if summary.get("all_observed_components_healthy") is not (
        statuses["pass"] == len(health_checks)
    ):
        raise EvidenceValidationError("aggregate health flag is inconsistent")

    worker_containers = runtime.get("worker_containers_observed")
    proof_flow_running = runtime.get("proof_flow_worker_containers_running")
    if proof_flow_running > worker_containers:
        raise EvidenceValidationError("ProofFlow Worker container counts are inconsistent")
    if (worker_containers == 0) is not (
        runtime.get("worker_runtime_observed") == "none-zero-workers"
    ):
        raise EvidenceValidationError("Worker runtime observation is inconsistent")

    all_six_running = runtime.get("proof_flow_worker_containers_running") == 6
    if summary.get("all_six_proof_flow_workers_running") is not all_six_running:
        raise EvidenceValidationError("Worker aggregate flag is inconsistent")

    strict_gate_expected = _strict_gate_expected(document)
    if summary.get("strict_collection_gate_passed") is not strict_gate_expected:
        raise EvidenceValidationError("strict collection gate flag is inconsistent")
    if strict and not strict_gate_expected:
        raise EvidenceValidationError("strict collection gate failed")


def _usage() -> None:
    print("Usage: validate_public_evidence.py [--strict] FILE|-", file=sys.stderr)


def _fail(message: str, status: int) -> NoReturn:
    print(f"Evidence validation failed: {message}.", file=sys.stderr)
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
    except EvidenceValidationError as exc:
        _fail(str(exc), 1 if strict else 2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
