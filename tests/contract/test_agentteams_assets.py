import json
import re
from hashlib import sha256
from importlib import metadata
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from proofflow.contracts import EvidenceIngestToolCall

ROOT = Path(__file__).parents[2]
DEPLOY = ROOT / "deploy/agentteams"
EXPECTED_WORKERS = {
    "case-manager",
    "evidence-agent",
    "rule-agent",
    "calculation-agent",
    "strategy-agent",
    "audit-agent",
}
EXPECTED_SKILLS = {
    "evidence_ingest",
    "timeline_build",
    "rule_retrieve",
    "deterministic_calculate",
    "conflict_detect",
    "decision_audit",
    "human_approval",
    "document_package",
}


def yaml_documents(path: Path) -> list[dict]:
    return [item for item in yaml.safe_load_all(path.read_text()) if item]


def test_agentteams_baseline_keeps_manager_smoke_claim_narrow() -> None:
    baseline = json.loads((DEPLOY / "baseline.json").read_text())

    assert baseline["agentteams_version"] == "v1.2.2"
    assert baseline["agentteams_commit"] == "849182af8e017168a5a200a87b1062142caf462d"
    assert baseline["status"] == "MANAGER_OPERATOR_MCP_SMOKE_VERIFIED_WORKERS_STOPPED"
    assert baseline["runtime_evidence"] == "MANAGER_OPERATOR_PUBLIC_SYNTHETIC_MCP_SMOKE_ONLY"
    assert (
        baseline["mcp_runtime_status"]
        == "THREE_SERVERS_OK_EXACT_ACL_POSITIVE_AND_NEGATIVE_SMOKE_VERIFIED"
    )
    for excluded_claim in ("Worker", "LLM", "Team", "Human"):
        assert excluded_claim in baseline["runtime_evidence_subject"]
    assert baseline["mcp_templates"] == [
        "mcp-proof-evidence",
        "mcp-proof-rules",
        "mcp-proof-calc",
    ]


def test_six_workers_start_stopped_and_keep_mcp_least_privilege_shape() -> None:
    workers = yaml_documents(DEPLOY / "01-workers-stopped.yaml")

    assert len(workers) == 6
    assert {item["metadata"]["name"] for item in workers} == EXPECTED_WORKERS
    assert all(item["apiVersion"] == "agentteams.io/v1beta1" for item in workers)
    assert all(item["kind"] == "Worker" for item in workers)
    assert all(item["spec"]["state"] == "Stopped" for item in workers)
    assert all(item["spec"]["model"] == "REPLACE_WITH_MODEL_ID" for item in workers)

    mcp_by_worker = {
        item["metadata"]["name"]: item["spec"].get("mcpServers", []) for item in workers
    }
    assert mcp_by_worker["evidence-agent"] == [
        {
            "name": "mcp-proof-evidence",
            "url": "http://aigw-local.agentteams.io:8080/mcp-servers/mcp-proof-evidence/mcp",
            "transport": "http",
        }
    ]
    assert [server["name"] for server in mcp_by_worker["rule-agent"]] == ["mcp-proof-rules"]
    assert [server["name"] for server in mcp_by_worker["calculation-agent"]] == ["mcp-proof-calc"]
    assert all(
        not servers
        for worker, servers in mcp_by_worker.items()
        if worker not in {"evidence-agent", "rule-agent", "calculation-agent"}
    )


def test_team_has_exactly_one_leader_and_all_six_workers() -> None:
    team = yaml_documents(DEPLOY / "02-team.yaml")[0]
    members = team["spec"]["workerMembers"]

    assert team["metadata"]["name"] == "proof-flow-case-review"
    assert {item["name"] for item in members} == EXPECTED_WORKERS
    leaders = [item["name"] for item in members if item["role"] == "team_leader"]
    assert leaders == ["case-manager"]


def test_humans_are_scoped_to_the_proof_flow_team() -> None:
    humans = yaml_documents(DEPLOY / "03-humans.yaml")

    assert {item["metadata"]["name"] for item in humans} == {
        "proof-reviewer",
        "proof-approver",
    }
    assert all(item["spec"]["accessibleTeams"] == ["proof-flow-case-review"] for item in humans)


def test_all_eight_agentteams_skill_frontmatters_are_valid() -> None:
    skill_files = sorted((DEPLOY / "skills").glob("*/SKILL.md"))
    observed: set[str] = set()
    for path in skill_files:
        text = path.read_text()
        assert text.startswith("---\n")
        _, frontmatter, body = text.split("---", maxsplit=2)
        metadata = yaml.safe_load(frontmatter)
        observed.add(metadata["name"])
        assert metadata["name"] == path.parent.name
        assert metadata["description"]
        assert metadata["assign_when"]
        assert "Integration status:" in body

    assert observed == EXPECTED_SKILLS


def test_mcp_templates_keep_backend_token_empty_and_bind_identity_to_route() -> None:
    expected = {
        "mcp-proof-evidence.yaml": (
            "evidence_ingest",
            "http://proofflow-tool-service.local:8787/v1/tools/evidence-ingest",
        ),
        "mcp-proof-rules.yaml": (
            "retrieve_rules",
            "http://proofflow-tool-service.local:8787/v1/tools/rule-retrieve",
        ),
        "mcp-proof-calc.yaml": (
            "deterministic_calculate",
            "http://proofflow-tool-service.local:8787/v1/tools/deterministic-calculate",
        ),
    }
    assert {path.name for path in (DEPLOY / "mcp").glob("*.yaml")} == set(expected)

    for filename, (tool_name, url) in expected.items():
        document = yaml.safe_load((DEPLOY / "mcp" / filename).read_text())
        assert document["server"]["config"] == {"accessToken": ""}
        assert document["server"]["allowTools"] == [tool_name]
        assert len(document["tools"]) == 1

        tool = document["tools"][0]
        assert tool["name"] == tool_name
        assert tool["requestTemplate"]["url"] == url
        assert tool["requestTemplate"]["method"] == "POST"
        assert tool["requestTemplate"]["argsToJsonBody"] is True
        headers = {item["key"]: item["value"] for item in tool["requestTemplate"]["headers"]}
        assert headers == {
            "Authorization": "Bearer {{.config.accessToken}}",
            "Content-Type": "application/json",
        }

        arguments = {item["name"]: item for item in tool["args"]}
        context_properties = arguments["context"]["properties"]
        assert "caller_identity" not in context_properties
        assert "actor_kind" not in context_properties
        assert arguments["fixture_status"]["default"] == "SYNTHETIC"


def test_evidence_mcp_matches_backend_identity_and_strict_base64_contract() -> None:
    document = yaml.safe_load((DEPLOY / "mcp/mcp-proof-evidence.yaml").read_text())
    tool = document["tools"][0]
    arguments = {item["name"]: item for item in tool["args"]}
    schema = EvidenceIngestToolCall.model_json_schema()
    core_context = schema["$defs"]["EvidenceIngestToolContext"]["properties"]
    core_arguments = schema["$defs"]["EvidenceIngestToolArguments"]["properties"]

    fixture_status = arguments["fixture_status"]
    assert fixture_status["enum"] == ["SYNTHETIC"]
    assert "PUBLIC SYNTHETIC" in tool["description"]
    assert "does not prove" in fixture_status["description"]

    context = arguments["context"]
    assert context["required"] is True
    assert context["additionalProperties"] is False
    assert "caller_identity" not in context["properties"]
    assert "actor_kind" not in context["properties"]
    assert "PF-A2" in context["description"]
    for identifier in ("tenant_id", "case_id", "trace_id", "idempotency_key"):
        assert context["properties"][identifier] == {
            "type": core_context[identifier]["type"],
            "required": True,
            "minLength": core_context[identifier]["minLength"],
        }
    assert context["properties"]["expected_state_version"] == {
        "type": core_context["expected_state_version"]["type"],
        "required": True,
        "minimum": core_context["expected_state_version"]["minimum"],
    }

    gateway_arguments = arguments["arguments"]
    assert gateway_arguments["required"] is True
    assert gateway_arguments["additionalProperties"] is False
    for field_name in ("document_id", "media_type"):
        assert gateway_arguments["properties"][field_name] == {
            "type": core_arguments[field_name]["type"],
            "required": True,
            "minLength": core_arguments[field_name]["minLength"],
        }
    assert gateway_arguments["properties"]["declared_sha256"] == {
        "type": core_arguments["declared_sha256"]["type"],
        "required": True,
        "pattern": core_arguments["declared_sha256"]["pattern"],
    }

    raw_content = gateway_arguments["properties"]["raw_content_base64"]
    assert raw_content["required"] is True
    assert raw_content["type"] == core_arguments["raw_content_base64"]["type"]
    assert raw_content["contentEncoding"] == "base64"
    assert raw_content["pattern"] == (
        r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    )
    for encoded in ("", "e30=", "TQ==", "TWE=", "TWFu"):
        assert re.fullmatch(raw_content["pattern"], encoded)
    for invalid in ("-_8=", "TQ", "TQ=", "TQ===", "TW Fu"):
        assert re.fullmatch(raw_content["pattern"], invalid) is None

    valid_call = EvidenceIngestToolCall.model_validate(
        {
            "fixture_status": "SYNTHETIC",
            "context": {
                "tenant_id": "public-tenant",
                "case_id": "synthetic-case",
                "trace_id": "synthetic-trace",
                "idempotency_key": "synthetic-ingest",
                "expected_state_version": 0,
            },
            "arguments": {
                "document_id": "synthetic-document",
                "media_type": "application/json",
                "declared_sha256": f"sha256:{'0' * 64}",
                "raw_content_base64": "e30=",
            },
        }
    )
    assert valid_call.context.caller_identity == "PF-A2"
    assert valid_call.context.actor_kind.value == "AGENT"

    for invalid in ("-_8=", "TQ", "TQ=", "TQ===", "TW Fu"):
        payload = valid_call.model_dump(mode="json")
        payload["arguments"]["raw_content_base64"] = invalid
        with pytest.raises(ValidationError, match="strict standard Base64"):
            EvidenceIngestToolCall.model_validate(payload)


def test_tool_service_image_is_pinned_locked_and_non_root() -> None:
    dockerfile = (ROOT / "deploy/tool-service/Dockerfile").read_text()
    requirements = (ROOT / "deploy/tool-service/requirements.lock").read_text()
    dockerignore = (ROOT / ".dockerignore").read_text().splitlines()

    assert dockerfile.startswith(
        "FROM python:3.12-alpine@sha256:"
        "285a71327884a4d50efbea30104473b0fa43ecefa499458899670ca30dae76e5\n"
    )
    assert "--require-hashes" in dockerfile
    assert "python -m pip uninstall --yes pip" in dockerfile
    assert "importlib.util.find_spec('pip') is None" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "pydantic==" in requirements
    assert "--hash=sha256:" in requirements
    assert "submission/private" in dockerignore
    catalog_digest = "sha256:27686c904451870dd5953ec6e47c155a395b2f279995e50f68aea984e6bf91de"
    catalog_path = ROOT / "data/rules/cn_labor_contract_law.catalog.json"
    observed_catalog_digest = f"sha256:{sha256(catalog_path.read_bytes()).hexdigest()}"
    assert observed_catalog_digest == catalog_digest
    assert f'"--rules-sha256", "{catalog_digest}"' in dockerfile


def test_tool_service_image_excludes_secrets_and_carries_license_notices() -> None:
    dockerfile = (ROOT / "deploy/tool-service/Dockerfile").read_text()
    dockerignore = set((ROOT / ".dockerignore").read_text().splitlines())
    requirements = (ROOT / "deploy/tool-service/requirements.lock").read_text()
    third_party_notices = (ROOT / "deploy/tool-service/THIRD_PARTY_NOTICES.md").read_text()

    assert "COPY LICENSE NOTICE /usr/share/doc/proofflow/" in dockerfile
    assert "COPY deploy/tool-service/THIRD_PARTY_NOTICES.md /usr/share/doc/proofflow/" in dockerfile
    assert (ROOT / "LICENSE").is_file()
    assert (ROOT / "NOTICE").is_file()

    required_secret_exclusions = {
        ".env",
        ".env.*",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*.crt",
        "*.cer",
        "*.der",
        "*.jks",
        "*.keystore",
        "*.kdbx",
        "id_rsa",
        "id_rsa.*",
        "id_ed25519",
        "id_ed25519.*",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.*",
        "secrets/",
        "**/secrets/",
        "submission/private",
    }
    assert required_secret_exclusions <= dockerignore
    assert {
        "!LICENSE",
        "!NOTICE",
        "!deploy/tool-service/Dockerfile",
        "!deploy/tool-service/requirements.lock",
        "!deploy/tool-service/THIRD_PARTY_NOTICES.md",
    } <= dockerignore
    assert "src" not in dockerignore and "src/" not in dockerignore
    assert "data" not in dockerignore and "data/" not in dockerignore

    expected_distributions = {
        "annotated-types": ("0.8.0", "MIT"),
        "pydantic": ("2.13.4", "MIT"),
        "pydantic-core": ("2.46.4", "MIT"),
        "typing-extensions": ("4.16.0", "PSF-2.0"),
        "typing-inspection": ("0.4.4", "MIT"),
    }
    locked_distributions = dict(
        re.findall(r"^([a-z0-9-]+)==([^ \\\n]+)", requirements, flags=re.MULTILINE)
    )
    assert locked_distributions == {
        name: version for name, (version, _license) in expected_distributions.items()
    }

    for name, (version, license_expression) in expected_distributions.items():
        distribution = metadata.distribution(name)
        assert distribution.version == version
        assert distribution.metadata["License-Expression"] == license_expression
        assert distribution.metadata.get_all("License-File") == ["LICENSE"]
        assert f"| `{name}` | `{version}` | `{license_expression}` | `LICENSE` |" in (
            third_party_notices
        )
        license_paths = [
            path
            for path in distribution.files or ()
            if str(path).endswith(".dist-info/licenses/LICENSE")
        ]
        assert len(license_paths) == 1
        assert distribution.locate_file(license_paths[0]).read_text().strip()
