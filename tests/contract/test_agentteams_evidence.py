import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from types import ModuleType
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from proofflow.contracts import DeterministicCalculateToolCall

ROOT = Path(__file__).parents[2]
DEPLOY = ROOT / "deploy/agentteams"
SNAPSHOT_PATH = DEPLOY / "evidence/local-infra-smoke-2026-08-20.json"
VALIDATOR_PATH = DEPLOY / "scripts/validate_public_evidence.py"
JQ = shutil.which("jq")
CURL = shutil.which("curl")


class Always200ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()

    def log_message(self, _format: str, *args: object) -> None:
        del args


def mcp_argument(filename: str, argument_name: str) -> dict[str, Any]:
    document = yaml.safe_load((DEPLOY / "mcp" / filename).read_text())
    arguments = {item["name"]: item for item in document["tools"][0]["args"]}
    return arguments[argument_name]


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("agentteams_evidence_validator", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot() -> dict[str, Any]:
    return json.loads(SNAPSHOT_PATH.read_text())


def test_public_snapshot_passes_semantic_and_strict_validation() -> None:
    validator = load_validator()
    document = snapshot()

    validator.validate_semantics(document)
    validator.validate_semantics(document, strict=True)

    schema = json.loads((DEPLOY / "evidence/public-evidence.schema.json").read_text())
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(schema)
    assert (
        list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document))
        == []
    )


@pytest.mark.parametrize(
    ("collection", "identifier"),
    [("images", "component"), ("health_checks", "check_id")],
)
def test_semantic_validator_rejects_duplicate_identifiers(collection: str, identifier: str) -> None:
    validator = load_validator()
    document = snapshot()
    assert document[collection][0][identifier]
    document[collection][1] = deepcopy(document[collection][0])

    with pytest.raises(validator.EvidenceValidationError, match="identifiers must be unique"):
        validator.validate_semantics(document)


def apply_public_evidence_attack(document: dict[str, Any], attack: str) -> None:
    if attack.startswith("missing-"):
        del document[attack.removeprefix("missing-")]
    elif attack == "collector-read-write":
        document["collector"]["read_only_runtime_checks"] = False
    elif attack == "collector-version":
        document["collector"]["version"] = "production"
    elif attack == "scope-private":
        document["scope"]["synthetic_data_only"] = False
    elif attack == "claim-production":
        document["summary"]["claim_level"] = "production-ready"
    elif attack == "root-extra":
        document["secret_material"] = "must-not-be-accepted"
    elif attack == "nested-extra":
        document["resolver"]["raw_addresses"] = ["must-not-be-accepted"]
    elif attack == "invalid-date-time":
        document["collected_at"] = "not-a-date-time"
    elif attack == "http-pass-500":
        document["health_checks"][1]["http_status"] = "500"
    elif attack == "non-http-code":
        document["health_checks"][0]["http_status"] = "200"
    elif attack == "non-http-false-pass":
        document["health_checks"][0]["observation"] = False
    elif attack == "all-health-skip":
        for check in document["health_checks"]:
            check["status"] = "skip"
        document["summary"].update(
            {
                "passed": 0,
                "failed": 0,
                "skipped": 10,
                "all_observed_components_healthy": True,
            }
        )
    elif attack == "image-reference-repin":
        image = document["images"][0]
        image_id = f"sha256:{'f' * 64}"
        repo_digest = (
            "higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/"
            f"agentteams-embedded@{image_id}"
        )
        image.update(
            {
                "reference_local_image_id": image_id,
                "observed_local_image_id": image_id,
                "reference_repo_digest": repo_digest,
                "observed_repo_digest": repo_digest,
            }
        )
    elif attack == "socket-contradiction":
        document["container_socket"]["controller_socket_present"] = False
    elif attack == "runtime-count-contradiction":
        document["runtime"]["proof_flow_worker_containers_running"] = 1
    elif attack == "manager-runtime-contradiction":
        document["runtime"]["manager_runtime_observed"] = "unknown"
    elif attack == "worker-runtime-contradiction":
        document["runtime"]["worker_runtime_observed"] = "openclaw-only"
    elif attack == "limitations-rewritten":
        document["limitations"] = ["production ready"] * 4
    elif attack == "source-version":
        document["source"]["expected_version"] = "v9.9.9"
    else:
        raise AssertionError(f"unknown test attack: {attack}")


@pytest.mark.parametrize(
    "attack",
    [
        "missing-collected_at",
        "missing-collector",
        "missing-scope",
        "missing-limitations",
        "collector-read-write",
        "collector-version",
        "scope-private",
        "claim-production",
        "root-extra",
        "nested-extra",
        "invalid-date-time",
        "http-pass-500",
        "non-http-code",
        "non-http-false-pass",
        "all-health-skip",
        "image-reference-repin",
        "socket-contradiction",
        "runtime-count-contradiction",
        "manager-runtime-contradiction",
        "worker-runtime-contradiction",
        "limitations-rewritten",
        "source-version",
    ],
)
def test_schema_and_semantic_gate_reject_public_evidence_attacks(attack: str) -> None:
    validator = load_validator()
    document = snapshot()
    apply_public_evidence_attack(document, attack)

    with pytest.raises(validator.EvidenceValidationError):
        validator.validate_semantics(document, strict=True)


@pytest.mark.parametrize(
    "attack",
    [
        "collector-read-write",
        "scope-private",
        "claim-production",
        "http-pass-500",
        "root-extra",
    ],
)
def test_strict_cli_executes_schema_gate(tmp_path: Path, attack: str) -> None:
    document = snapshot()
    apply_public_evidence_attack(document, attack)
    attack_path = tmp_path / "attacked-evidence.json"
    attack_path.write_text(json.dumps(document))

    result = subprocess.run(
        [sys.executable, str(VALIDATOR_PATH), "--strict", str(attack_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "must-not-be-accepted" not in result.stdout
    assert "must-not-be-accepted" not in result.stderr


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
def test_strict_json_loader_rejects_non_finite_numbers_and_duplicate_keys(payload: str) -> None:
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


def test_semantic_validator_rejects_summary_detail_disagreement() -> None:
    validator = load_validator()
    document = snapshot()
    document["summary"]["passed"] -= 1

    with pytest.raises(validator.EvidenceValidationError, match="summary counts"):
        validator.validate_semantics(document)


def test_semantic_validator_rejects_duplicate_observed_image_ids() -> None:
    validator = load_validator()
    document = snapshot()
    document["images"][1]["observed_local_image_id"] = document["images"][0][
        "observed_local_image_id"
    ]
    document["images"][1]["local_image_id_matches_reference"] = False
    document["summary"]["strict_collection_gate_passed"] = False

    with pytest.raises(validator.EvidenceValidationError, match="image ID values must be unique"):
        validator.validate_semantics(document)


def source_mismatch(document: dict[str, Any]) -> None:
    document["source"]["observed_commit"] = "0" * 40
    document["source"]["commit_matches"] = False
    document["source"]["verification_status"] = "fail"


def image_mismatch(document: dict[str, Any]) -> None:
    image = document["images"][0]
    image["observed_local_image_id"] = None
    image["local_image_id_matches_reference"] = False


def resolver_mismatch(document: dict[str, Any]) -> None:
    document["resolver"]["normalized_backup_matches_current"] = False
    document["resolver"]["verification_status"] = "fail"


@pytest.mark.parametrize("mutate", [source_mismatch, image_mismatch, resolver_mismatch])
def test_strict_gate_covers_source_image_and_resolver_mismatch(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    validator = load_validator()
    document = snapshot()
    mutate(document)
    document["summary"]["strict_collection_gate_passed"] = False

    validator.validate_semantics(document)
    with pytest.raises(validator.EvidenceValidationError, match="strict collection gate failed"):
        validator.validate_semantics(document, strict=True)


def test_snapshot_does_not_publish_resolver_file_fingerprints() -> None:
    document = snapshot()
    resolver = document["resolver"]

    assert resolver["resolver_file_hashes_emitted"] is False
    assert "backup_sha256" not in resolver
    assert "current_sha256" not in resolver


def test_image_observation_distinguishes_local_id_from_repo_digest_metadata() -> None:
    observation = json.loads((DEPLOY / "images.local-observed.json").read_text())
    evidence_images = {item["component"]: item for item in snapshot()["images"]}

    assert observation["artifact_kind"] == "point-in-time-local-docker-image-observation"
    assert len(observation["images"]) == 3
    for image in observation["images"]:
        assert image["local_image_id_observed"].startswith("sha256:")
        assert "@sha256:" in image["repo_digest_metadata_observed"]
        assert "digest" not in image or image["digest"] is None
        evidence = evidence_images[image["component"]]
        assert evidence["reference_local_image_id"] == image["local_image_id_observed"]
        assert evidence["reference_repo_digest"] == image["repo_digest_metadata_observed"]


def test_collector_parses_only_a_top_level_boolean_openclaw_health_flag() -> None:
    collector = (DEPLOY / "scripts/collect-public-evidence.sh").read_text()

    assert "jq -e -s 'length == 1 and (.[0] | type == \"object\" and .ok == true)'" in collector
    assert 'grep -Eq \'"ok"' not in collector
    assert "python3 -c 'import jsonschema'" in collector


def test_collector_disables_proxies_for_every_loopback_curl() -> None:
    collector = (DEPLOY / "scripts/collect-public-evidence.sh").read_text()

    assert "curl --silent --show-error --noproxy '*' --output /dev/null" in collector
    assert "docker exec \"${container}\" curl --silent --show-error --noproxy '*'" in collector
    assert 'curl --silent --show-error --noproxy "*" --fail' in collector


@pytest.mark.skipif(CURL is None, reason="curl is unavailable")
def test_noproxy_prevents_a_fake_proxy_from_forging_loopback_200() -> None:
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Always200ProxyHandler)
    thread = Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    target_socket = socket.socket()
    target_socket.bind(("127.0.0.1", 0))
    unused_port = target_socket.getsockname()[1]
    target_socket.close()
    environment = os.environ.copy()
    for key in ("ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "all_proxy", "https_proxy"):
        environment.pop(key, None)
    environment.update(
        {
            "http_proxy": f"http://127.0.0.1:{proxy.server_port}",
            "NO_PROXY": "",
            "no_proxy": "",
        }
    )
    base_command = [
        str(CURL),
        "--silent",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}",
        "--max-time",
        "2",
    ]
    target_url = f"http://127.0.0.1:{unused_port}/health"

    try:
        proxied = subprocess.run(
            [*base_command, target_url],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        bypassed = subprocess.run(
            [*base_command, "--noproxy", "*", target_url],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=2)

    assert proxied.returncode == 0
    assert proxied.stdout == "200"
    assert bypassed.returncode != 0
    assert bypassed.stdout == "000"


@pytest.mark.skipif(JQ is None, reason="collector dependency jq is unavailable")
@pytest.mark.parametrize(
    ("payload", "accepted"),
    [
        ('{"ok":true}', True),
        ('{"nested":{"ok":true}}', False),
        ('{"ok":"true"}', False),
        ('{"ok":false}\n{"ok":true}', False),
        ('{"ok":', False),
    ],
)
def test_openclaw_health_filter_rejects_noncanonical_success(payload: str, accepted: bool) -> None:
    result = subprocess.run(
        [
            str(JQ),
            "-e",
            "-s",
            'length == 1 and (.[0] | type == "object" and .ok == true)',
        ],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )

    assert (result.returncode == 0) is accepted


@pytest.mark.parametrize(
    "command",
    [
        [str(DEPLOY / "scripts/collect-public-evidence.sh")],
        [str(DEPLOY / "scripts/preflight-macos-colima.sh")],
        [sys.executable, str(VALIDATOR_PATH)],
    ],
)
def test_unknown_arguments_are_not_reflected(command: list[str]) -> None:
    sentinel = "do-not-reflect-this-value"
    result = subprocess.run(
        [*command, f"--unknown={sentinel}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert sentinel not in result.stdout
    assert sentinel not in result.stderr


def test_baseline_names_the_subject_of_each_negative_claim() -> None:
    baseline = json.loads((DEPLOY / "baseline.json").read_text())

    assert baseline["status"] == "MANAGER_OPERATOR_MCP_SMOKE_VERIFIED_WORKERS_STOPPED"
    assert "Manager-operator synthetic tool smoke" in baseline["status_subject"]
    assert baseline["runtime_evidence"] == "MANAGER_OPERATOR_PUBLIC_SYNTHETIC_MCP_SMOKE_ONLY"
    assert "without Worker containers" in baseline["runtime_evidence_subject"]
    assert (
        baseline["local_infrastructure_status"] == "SMOKE_VERIFIED_ZERO_PROOFFLOW_WORKER_CONTAINERS"
    )
    assert "Worker CR inventory" in baseline["local_infrastructure_status_subject"]
    assert baseline["local_image_observation"] == "images.local-observed.json"
    assert baseline["local_infrastructure_observed_at"] == snapshot()["collected_at"]


def test_llm_preflight_patch_documents_help_secret_regression_tests() -> None:
    patch = (DEPLOY / "patches/v1.2.2-llm-preflight-help-redaction.patch").read_text()
    collector = (DEPLOY / "scripts/collect-public-evidence.sh").read_text()

    assert "TestLLMPreflightHelpDoesNotExposeAPIKeyFromEnv" in patch
    assert "TestLLMPreflightRootHelpAndSubcommandHelpDoNotExposeAPIKey" in patch
    assert "TestLLMPreflightCompletionAndErrorDoNotExposeAPIKey" in patch
    assert "TestLLMPreflightCommandUsesAPIKeyFromEnvAtRunTime" in patch
    assert "TestLLMPreflightCommandFlagOverridesEnvironmentAPIKey" in patch
    assert 'StringVar(&apiKeyFlag, "api-key", ""' in patch
    assert "assertCommandTreeDoesNotContain" in patch
    assert "agt llm-preflight --help" not in "\n".join(
        line for line in collector.splitlines() if not line.lstrip().startswith("#")
    )


@pytest.mark.parametrize(
    ("filename", "schema_filename", "context_definition"),
    [
        (
            "mcp-proof-rules.yaml",
            "tool-rule-retrieve-call.schema.json",
            "RuleRetrieveToolContext",
        ),
        (
            "mcp-proof-calc.yaml",
            "tool-deterministic-calculate-call.schema.json",
            "DeterministicCalculateToolContext",
        ),
    ],
)
def test_mcp_context_hints_match_core_constraints(
    filename: str,
    schema_filename: str,
    context_definition: str,
) -> None:
    context = mcp_argument(filename, "context")
    gateway_properties = context["properties"]
    core_schema = json.loads((ROOT / "schemas" / schema_filename).read_text())
    core_properties = core_schema["$defs"][context_definition]["properties"]

    assert context["required"] is True
    for identifier in ("tenant_id", "case_id", "trace_id", "idempotency_key"):
        assert gateway_properties[identifier] == {
            "type": core_properties[identifier]["type"],
            "required": True,
            "minLength": core_properties[identifier]["minLength"],
        }
    assert gateway_properties["expected_state_version"] == {
        "type": core_properties["expected_state_version"]["type"],
        "required": True,
        "minimum": core_properties["expected_state_version"]["minimum"],
    }


def test_rule_mcp_query_hints_match_core_constraints() -> None:
    gateway_properties = mcp_argument("mcp-proof-rules.yaml", "arguments")["properties"]
    core_schema = json.loads((ROOT / "schemas/tool-rule-retrieve-call.schema.json").read_text())
    core_properties = core_schema["$defs"]["RuleRetrieveRequest"]["properties"]

    issue_codes = gateway_properties["issue_codes"]
    assert issue_codes["required"] is True
    for keyword in ("type", "minItems", "maxItems", "uniqueItems"):
        assert issue_codes[keyword] == core_properties["issue_codes"][keyword]
    assert issue_codes["items"] == {"type": "string", "minLength": 1}
    assert gateway_properties["jurisdiction"] == {
        "type": core_properties["jurisdiction"]["type"],
        "required": True,
        "minLength": core_properties["jurisdiction"]["minLength"],
    }
    assert gateway_properties["as_of_date"] == {
        "type": core_properties["as_of_date"]["type"],
        "required": True,
        "format": core_properties["as_of_date"]["format"],
    }


def test_calc_mcp_requires_exact_rule_scope_pass_through() -> None:
    document = yaml.safe_load((DEPLOY / "mcp/mcp-proof-calc.yaml").read_text())
    tool = document["tools"][0]
    arguments = mcp_argument("mcp-proof-calc.yaml", "arguments")
    rule_scope = arguments["properties"]["rule_scope"]
    core_schema = json.loads(
        (ROOT / "schemas/tool-deterministic-calculate-call.schema.json").read_text()
    )
    core_properties = core_schema["$defs"]["RuleScopeReceipt"]["properties"]

    assert rule_scope["type"] == "object"
    assert rule_scope["required"] is True
    assert rule_scope["additionalProperties"] is False
    assert set(rule_scope["properties"]) == {
        "issue_codes",
        "jurisdiction",
        "as_of_date",
        "catalog_version",
        "rule_query_input_hash",
    }

    issue_codes = rule_scope["properties"]["issue_codes"]
    assert issue_codes["required"] is True
    for keyword in ("type", "minItems", "maxItems", "uniqueItems"):
        assert issue_codes[keyword] == core_properties["issue_codes"][keyword]
    assert issue_codes["items"] == {"type": "string", "minLength": 1}

    for field_name in ("jurisdiction", "catalog_version"):
        field = rule_scope["properties"][field_name]
        assert field == {
            "type": core_properties[field_name]["type"],
            "required": True,
            "minLength": core_properties[field_name]["minLength"],
        }
    assert rule_scope["properties"]["as_of_date"] == {
        "type": core_properties["as_of_date"]["type"],
        "required": True,
        "format": core_properties["as_of_date"]["format"],
    }
    assert rule_scope["properties"]["rule_query_input_hash"] == {
        "type": core_properties["rule_query_input_hash"]["type"],
        "required": True,
        "pattern": core_properties["rule_query_input_hash"]["pattern"],
    }

    pass_through_guidance = " ".join(
        (tool["description"], arguments["description"], rule_scope["description"])
    ).lower()
    assert "value.rule_scope" in pass_through_guidance
    assert "unchanged" in pass_through_guidance
    assert "rewrite" in pass_through_guidance


def test_backend_contract_fails_closed_when_rule_scope_is_missing() -> None:
    payload = {
        "fixture_status": "SYNTHETIC",
        "context": {
            "tenant_id": "public-tenant",
            "case_id": "public-case",
            "trace_id": "public-trace",
            "idempotency_key": "public-idempotency-key",
            "expected_state_version": 0,
        },
        "arguments": {"evidence": [], "rule_citations": []},
    }

    with pytest.raises(ValidationError) as exc_info:
        DeterministicCalculateToolCall.model_validate(payload)

    assert {
        (tuple(error["loc"]), error["type"]) for error in exc_info.value.errors(include_url=False)
    } == {(("arguments", "rule_scope"), "missing")}

    core_schema = json.loads(
        (ROOT / "schemas/tool-deterministic-calculate-call.schema.json").read_text()
    )
    assert "rule_scope" in core_schema["$defs"]["CalculateRequest"]["required"]


def test_mcp_docs_disclose_nested_required_gateway_boundary() -> None:
    readme = (DEPLOY / "README.md").read_text()

    assert "不能声称网关已经执行完整的嵌套 JSON Schema" in readme
    assert "服务端 Pydantic 合同仍是 fail-closed 权威边界" in readme
    assert "arguments.rule_scope" in readme
    assert "HTTP 422" in readme
