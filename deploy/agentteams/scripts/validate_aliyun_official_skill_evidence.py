#!/usr/bin/env python3
"""Validate offline Aliyun official Skill preflight evidence without echoing inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, NoReturn, TextIO

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = (
    ROOT / "deploy/agentteams/evidence/aliyun-official-skill-offline-preflight.schema.json"
)
VENDORED_ROOT = ROOT / "third_party/aliyun/alibabacloud-openclaw-skill-security-scan/upstream"
SKILLS_ROOT = ROOT / "deploy/agentteams/skills"

PROOFLOW_BASE_COMMIT = "b63eeb60d1072c73d2d0d1d6061b3c8f800487a4"
SANDBOX_PROFILE = "(version 1) (allow default) (deny network*)"
OFFICIAL_EMPTY_TARGET_REASON = "OFFICIAL_TARGET_POLICY_EXCLUDES_SKILL_MD_ONLY_INPUTS"
SOURCE_DIGESTS = {
    "SKILL.md": "sha256:d5df78b1d78361596b626fb129567e2fb69eb65002de7545e451b1f648311e80",
    "assets/LICENSE.txt": (
        "sha256:c4db38611836ea364d14273ebfe902b106e220f07b8f723b8230125be7f2795b"
    ),
    "references/baseline.md": (
        "sha256:b2bee705755d001079dadf4da9e1462d275c44a44fd08f7ba233835389be21b4"
    ),
    "references/report_template.md": (
        "sha256:9f52e97e0075dc609be666c259155b253280bb96c109f9c6f7a8d09d23b3ddbf"
    ),
    "references/skillaudit.md": (
        "sha256:41de28a8680332ccfca1dcf247dd261fdd3e12de3dd660869dbd2d4f16764be4"
    ),
    "scripts/basic_udf.sh": (
        "sha256:9fdf8763b6bfc5c5b681d781c7ab49caa36aa94125799d295441fbe952997466"
    ),
    "scripts/main.sh": ("sha256:a0a4cf6a04bd8e367cf984cc385fcf9f2e11a00a9f96d3ab3eb88c424d508f94"),
    "scripts/skill_zip_packager.sh": (
        "sha256:f61362ef8c2a3ba6ecf7e4f34740757dfb35b017def5e5bd5378818583824a47"
    ),
}
EXPECTED_SKILLS = (
    "conflict_detect",
    "decision_audit",
    "deterministic_calculate",
    "document_package",
    "evidence_ingest",
    "human_approval",
    "rule_retrieve",
    "timeline_build",
)
SCENARIOS = (
    (1, "REVERSE_SHELL_OR_BACKDOOR", "CRITICAL"),
    (2, "CREDENTIAL_HARVESTING", "CRITICAL"),
    (3, "DATA_EXFILTRATION", "HIGH"),
    (4, "CRYPTOMINER", "CRITICAL"),
    (5, "PERMISSION_ABUSE", "HIGH"),
    (6, "PROMPT_INJECTION", "HIGH"),
    (7, "CODE_OBFUSCATION", "MEDIUM"),
    (8, "RANSOMWARE", "CRITICAL"),
    (9, "PERSISTENCE", "MEDIUM"),
    (10, "SUPPLY_CHAIN_ATTACK", "MEDIUM"),
    (11, "MALICIOUS_DOWNLOADER", "CRITICAL"),
    (12, "PRIVACY_DATA_EXPOSURE", "MEDIUM"),
)
SUPPLEMENTAL_CHECKS = {
    "ABSOLUTE_USER_PATH": re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\)"),
    "CLOUD_OR_SERVICE_TOKEN_LITERAL": re.compile(
        r"(?:AKIA[0-9A-Z]{16}|LTAI[0-9A-Za-z]{20}|gh[op]_[0-9A-Za-z]{36}|"
        r"glpat-[0-9A-Za-z-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,})"
    ),
    "CREDENTIAL_FILE_PATH": re.compile(
        r"(?:\.ssh/(?:id_rsa|id_ed25519)|\.aws/credentials|\.config/gh/hosts|"
        r"\.git-credentials|\.docker/config\.json|\.kube/config|\.env(?:\.|$))",
        re.IGNORECASE | re.MULTILINE,
    ),
    "DYNAMIC_EVAL": re.compile(r"\beval\s*\("),
    "EXPLICIT_PROMPT_OVERRIDE": re.compile(
        r"(?:ignore (?:all|previous).*instructions|system prompt.*override|"
        r"do anything now|\bjailbreak\b)",
        re.IGNORECASE,
    ),
    "EXTERNAL_URL_LITERAL": re.compile(r"https?://[^\s)>\]}`]+", re.IGNORECASE),
    "HARDCODED_SECRET_ASSIGNMENT": re.compile(
        r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)"
        r"\s*[:=]\s*['\"][^'\"]{16,}['\"]",
        re.IGNORECASE,
    ),
    "PRIVATE_KEY_BLOCK": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "SHELL_OR_DOWNLOADER_COMMAND": re.compile(
        r"(?:\b(?:curl|wget|sudo)\b|\bnc\s+-[elp]|\b(?:bash|sh)\s+-c\b)",
        re.IGNORECASE,
    ),
}
EXPECTED_LIMITATIONS = {
    "OFFICIAL_MAIN_SCRIPT_NOT_EXECUTED",
    "OPENCLAW_DEEP_AUDIT_NOT_EXECUTED",
    "OFFICIAL_STATIC_POLICY_EXCLUDES_SKILL_MD",
    "OFFICIAL_COMPATIBLE_TARGET_SET_WAS_EMPTY",
    "SUPPLEMENTAL_PATTERN_SCAN_CANNOT_PROVE_SKILL_SAFETY",
    "NO_CLOUD_INTELLIGENCE_OR_DEEP_ANALYSIS",
    "NO_WORKER_SKILL_CONSUMPTION_RECEIPT",
    "UNSIGNED_POINT_IN_TIME_EVIDENCE",
}
EXPECTED_ENVIRONMENT = {
    "ALIYUN_SKILL_SEC_CLOUD",
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "PROOFFLOW_NETWORK_SANDBOX",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
    "REPORT_LANG",
    "TMPDIR",
}
SECRET_LITERAL = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|LTAI[0-9A-Za-z]{20}|gh[op]_[0-9A-Za-z]{36}|"
    r"glpat-[0-9A-Za-z-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


class EvidenceValidationError(ValueError):
    """The evidence does not satisfy its public contract."""


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


def _load_schema() -> dict[str, Any]:
    try:
        with SCHEMA_PATH.open(encoding="utf-8") as stream:
            schema = _load_json(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError("schema is not readable strict JSON") from exc
    if not isinstance(schema, dict):
        raise EvidenceValidationError("schema root must be an object")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise EvidenceValidationError("schema is not valid Draft 2020-12") from exc
    return schema


def validate_schema(document: dict[str, Any]) -> None:
    validator = Draft202012Validator(_load_schema(), format_checker=FormatChecker())
    if next(validator.iter_errors(document), None) is not None:
        raise EvidenceValidationError("evidence does not conform to schema")


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _canonical_sandbox_command(collected_at: str) -> list[str]:
    return [
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME=/var/empty",
        "TMPDIR=<bounded-ephemeral>",
        "LANG=C",
        "LC_ALL=C",
        "ALIYUN_SKILL_SEC_CLOUD=false",
        "REPORT_LANG=zh",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONHASHSEED=0",
        "PROOFFLOW_NETWORK_SANDBOX=macos-sandbox-exec-deny-network-v1",
        "/usr/bin/sandbox-exec",
        "-p",
        SANDBOX_PROFILE,
        "<python3>",
        "<bounded-ephemeral>/collector.py",
        "--source-root",
        "<bounded-ephemeral>/source",
        "--skills-root",
        "<bounded-ephemeral>/skills",
        "--collected-at",
        collected_at,
    ]


def _canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return _sha256(payload)


def _files(root: Path) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        raise EvidenceValidationError("expected source directory is unsafe")
    files: list[Path] = []
    for candidate in root.rglob("*"):
        if candidate.is_symlink():
            raise EvidenceValidationError("symlinked evidence input is forbidden")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise EvidenceValidationError("non-regular evidence input")
        files.append(candidate)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def _records_by_key(records: Any, key: str) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
        raise EvidenceValidationError("expected an array of records")
    identifiers = [item.get(key) for item in records]
    if any(not isinstance(item, str) for item in identifiers):
        raise EvidenceValidationError("record identifiers must be strings")
    if len(identifiers) != len(set(identifiers)):
        raise EvidenceValidationError("record identifiers must be unique")
    return {str(item[key]): item for item in records}


def _validate_pinned_source(document: dict[str, Any]) -> None:
    source = document["official_source"]
    if source["acquisition"] != {
        "mode": "PUBLIC_GIT_HTTPS_WITH_CLEAN_ENVIRONMENT",
        "network_used": True,
        "credentials_used": False,
        "occurred_before_offline_collection": True,
        "content_reverified_by_hash_inside_sandbox": True,
    }:
        raise EvidenceValidationError("source acquisition boundary changed")
    records = _records_by_key(source["source_files"], "path")
    if set(records) != set(SOURCE_DIGESTS):
        raise EvidenceValidationError("pinned source inventory is not exact")
    actual_files = _files(VENDORED_ROOT)
    actual_paths = {item.relative_to(VENDORED_ROOT).as_posix() for item in actual_files}
    if actual_paths != set(SOURCE_DIGESTS):
        raise EvidenceValidationError("vendored source file set changed")
    for source_file in actual_files:
        relative_path = source_file.relative_to(VENDORED_ROOT).as_posix()
        payload = source_file.read_bytes()
        record = records[relative_path]
        if record != {
            "path": relative_path,
            "sha256": SOURCE_DIGESTS[relative_path],
            "bytes": len(payload),
        }:
            raise EvidenceValidationError("pinned source record mismatch")
        if _sha256(payload) != SOURCE_DIGESTS[relative_path]:
            raise EvidenceValidationError("vendored source digest mismatch")
    if source["license"]["sha256"] != SOURCE_DIGESTS["assets/LICENSE.txt"]:
        raise EvidenceValidationError("license digest mismatch")


def _validate_skill_inputs(document: dict[str, Any]) -> None:
    inputs = _records_by_key(document["skill_inputs"], "skill_name")
    results = _records_by_key(document["scan"]["results"], "skill_name")
    if set(inputs) != set(EXPECTED_SKILLS) or set(results) != set(EXPECTED_SKILLS):
        raise EvidenceValidationError("skill input/result set is not exact")
    if document["subject"]["expected_skill_names"] != list(EXPECTED_SKILLS):
        raise EvidenceValidationError("expected skill order changed")

    for skill_name in EXPECTED_SKILLS:
        directory = SKILLS_ROOT / skill_name
        files = _files(directory)
        if [item.relative_to(directory).as_posix() for item in files] != ["SKILL.md"]:
            raise EvidenceValidationError("public Skill directory is not a one-file contract")
        payload = files[0].read_bytes()
        text = payload.decode("utf-8")
        expected_input = {
            "skill_name": skill_name,
            "relative_path": f"deploy/agentteams/skills/{skill_name}/SKILL.md",
            "sha256": _sha256(payload),
            "bytes": len(payload),
            "regular_file": True,
            "directory_file_count": 1,
            "symlink_count": 0,
        }
        if inputs[skill_name] != expected_input:
            raise EvidenceValidationError("Skill input digest or shape mismatch")

        expected_matches = sorted(
            check_id for check_id, pattern in SUPPLEMENTAL_CHECKS.items() if pattern.search(text)
        )
        if expected_matches:
            raise EvidenceValidationError(
                "current Skill content has supplemental indicator matches"
            )
        result = results[skill_name]
        if result["official_rule_replay_reason_code"] != OFFICIAL_EMPTY_TARGET_REASON:
            raise EvidenceValidationError("official empty-target reason changed")
        if result["supplemental_contract_scan"]["matched_check_ids"] != expected_matches:
            raise EvidenceValidationError("supplemental result disagrees with current Skill")
        scenarios = result["scenario_results"]
        observed = [(item["scenario_id"], item["name"], item["severity"]) for item in scenarios]
        if observed != list(SCENARIOS):
            raise EvidenceValidationError("official scenario ledger is incomplete or reordered")
        if any(
            item["status"] != "INCONCLUSIVE_EMPTY_TARGET_SET" or item["match_count"] is not None
            for item in scenarios
        ):
            raise EvidenceValidationError("empty target set was represented as a finding verdict")


def _walk_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [text for item in value for text in _walk_strings(item)]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _walk_strings(item)]
    return []


def validate_semantics(document: dict[str, Any], *, strict: bool = False) -> None:
    validate_schema(document)
    if document["subject"]["proof_flow_base_commit"] != PROOFLOW_BASE_COMMIT:
        raise EvidenceValidationError("ProofFlow base commit changed")

    implementation = document["implementation_audit"]
    expected_sets = {
        "main_required_commands": {"openclaw", "curl", "grep", "date", "mkdir"},
        "main_optional_commands": {"jq", "realpath", "zip", "tar"},
        "packager_commands": {"zip", "du", "cp", "find", "touch", "stat", "xargs"},
        "cloud_enabled_data_classes": {"ZIP_MD5", "SKILL_NAME", "SKILL_ZIP_BYTES"},
        "official_main_non_execution_reasons": {
            "UNCONDITIONAL_OPENCLAW_DEEP_AUDIT_WOULD_READ_OUT_OF_SCOPE_CONFIGURATION",
            "LOCAL_BASH_BELOW_UPSTREAM_MINIMUM",
        },
        "official_static_target_policy": {
            "package.json",
            "src/**",
            "scripts/** excluding scripts/main.sh and scripts/basic_udf.sh",
        },
    }
    for key, expected in expected_sets.items():
        if set(implementation[key]) != expected or len(implementation[key]) != len(expected):
            raise EvidenceValidationError("implementation audit closed set mismatch")

    execution = document["execution_boundary"]
    environment = set(execution["environment_names"])
    if not EXPECTED_ENVIRONMENT.issubset(environment):
        raise EvidenceValidationError("sanitized environment names are incomplete")
    if environment - EXPECTED_ENVIRONMENT - {"__CF_USER_TEXT_ENCODING"}:
        raise EvidenceValidationError("unexpected environment name was published")
    if set(execution["os_injected_environment_names"]) not in (
        set(),
        {"__CF_USER_TEXT_ENCODING"},
    ):
        raise EvidenceValidationError("unexpected OS-injected environment name")
    network = execution["network"]
    expected_network = {
        "mechanism": "MACOS_SANDBOX_EXEC_DENY_NETWORK_ALL",
        "scope": "SANDBOXED_COLLECTION_INVOCATION_ONLY",
        "enforced": True,
        "sandbox_profile": SANDBOX_PROFILE,
        "sandbox_profile_sha256": _sha256(SANDBOX_PROFILE.encode("utf-8")),
        "probe_target_class": "LOOPBACK_TCP_DISCARD_PORT",
        "probe_status": "BLOCKED_EPERM",
        "probe_errno": 1,
        "external_network_observed": False,
        "observation_semantics": (
            "Collector and descendants could not connect through network sockets; "
            "no claim is made about processes outside this sandbox."
        ),
    }
    if network != expected_network:
        raise EvidenceValidationError("network boundary is not fail-closed")

    canonical_command = _canonical_sandbox_command(document["collected_at"])
    expected_receipt = {
        "canonicalization": "COMPACT_JSON_UTF8_ARGV_WITH_TMP_ROOT_AND_PYTHON_PATH_REDACTED",
        "canonical_argv": canonical_command,
        "canonical_argv_sha256": _canonical_json_sha256(canonical_command),
        "sandbox_exec_exit_code": 0,
        "exit_code_semantics": (
            "The committed artifact was retained only after the runner observed exit code 0 "
            "from sandbox-exec; this is not an upstream main.sh result."
        ),
    }
    if execution["command_receipt"] != expected_receipt:
        raise EvidenceValidationError("sandbox command receipt mismatch")

    if set(document["scan"]["supplemental_check_ids"]) != set(SUPPLEMENTAL_CHECKS):
        raise EvidenceValidationError("supplemental check inventory mismatch")
    if document["scan"]["official_inconclusive_reason_code"] != OFFICIAL_EMPTY_TARGET_REASON:
        raise EvidenceValidationError("official scan reason code mismatch")
    if set(document["limitations"]) != EXPECTED_LIMITATIONS:
        raise EvidenceValidationError("required limitations are incomplete")
    if any(SECRET_LITERAL.search(text) for text in _walk_strings(document)):
        raise EvidenceValidationError("evidence contains a credential-like literal")
    if any("/Users/" in text or "/home/" in text for text in _walk_strings(document)):
        raise EvidenceValidationError("evidence contains a user-specific absolute path")

    integration = document["integration"]
    if any(
        integration[key]
        for key in (
            "official_skill_assigned_to_worker",
            "runtime_consumption",
            "live_worker_execution",
            "llm_inference",
            "agentteams_resources_mutated",
            "cloud_service_used",
        )
    ):
        raise EvidenceValidationError("offline preflight overclaims runtime or mutation")

    _validate_skill_inputs(document)
    if strict:
        _validate_pinned_source(document)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("evidence")
    arguments = parser.parse_args()
    try:
        document = load_evidence(arguments.evidence)
        validate_semantics(document, strict=arguments.strict)
    except EvidenceValidationError:
        print("ALIYUN_OFFICIAL_SKILL_EVIDENCE_INVALID", file=sys.stderr)
        return 1
    print("ALIYUN_OFFICIAL_SKILL_EVIDENCE_VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
