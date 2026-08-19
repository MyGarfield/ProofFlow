import json
from pathlib import Path

import yaml

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


def test_agentteams_version_is_pinned_but_not_claimed_deployed() -> None:
    baseline = json.loads((DEPLOY / "baseline.json").read_text())

    assert baseline["agentteams_version"] == "v1.2.2"
    assert baseline["agentteams_commit"] == "849182af8e017168a5a200a87b1062142caf462d"
    assert baseline["status"] == "PINNED_NOT_DEPLOYED"
    assert baseline["runtime_evidence"] == "NONE"


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
    assert [server["name"] for server in mcp_by_worker["rule-agent"]] == ["mcp-proof-rules"]
    assert [server["name"] for server in mcp_by_worker["calculation-agent"]] == ["mcp-proof-calc"]
    assert all(
        not servers
        for worker, servers in mcp_by_worker.items()
        if worker not in {"rule-agent", "calculation-agent"}
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
