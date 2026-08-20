import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).parents[2]
RESEARCH_DIR = ROOT / "research"
SOURCES_PATH = RESEARCH_DIR / "frontier_sources.json"
SCHEMA_PATH = RESEARCH_DIR / "frontier_sources.schema.json"
DOC_PATH = ROOT / "docs/11_FRONTIER_RESEARCH_AND_CHAMPION_STRATEGY.md"

RUBRIC_IDS = (
    "scene_value_and_reproducibility",
    "multi_agent_collaboration_loop",
    "skill_engineering_and_reuse",
    "engineering_runtime_and_security_audit",
    "open_source",
)
RUBRIC_WEIGHTS = (25, 25, 25, 20, 5)

EXPECTED_CLAIM_IDS = (
    "CL-SCORE-WEIGHTS",
    "CL-THREE-ROLE-BASELINE",
    "CL-SIMPLE-COMPOSABLE",
    "CL-AUTONOMY-RISK",
    "CL-MCP-HUMAN-DENY",
    "CL-MCP-AUTH-BOUNDARY",
    "CL-A2A-OPAQUE-INTEROP",
    "CL-TRACE-STRUCTURE",
    "CL-OTEL-AGENT-SEMANTICS",
    "CL-EVAL-HARNESS-BUDGET",
    "CL-MULTIAGENT-FAILURES",
    "CL-MAGENTIC-ORCHESTRATION",
    "CL-TAU-BENCH-RELIABILITY",
    "CL-STATEFUL-TOOLS",
    "CL-PROMPT-INJECTION",
    "CL-ADAPTIVE-CONTEXT",
    "CL-PERSISTENT-HITL",
    "CL-FAILURE-ATTRIBUTION",
    "CL-HYPOTHESIS-PROOF-CARRYING-CONTEXT",
    "CL-HYPOTHESIS-SPECIALIZATION",
    "CL-HYPOTHESIS-CONTEXT-TRADEOFF",
    "CL-HYPOTHESIS-PORTABLE-PROTOCOL",
    "CL-UNKNOWN-PROOFFLOW-AGENT-UPLIFT",
    "CL-UNKNOWN-A2A-RUN",
    "CL-UNKNOWN-MEMORY-GAIN",
    "CL-UNKNOWN-OTEL-COMPLIANCE",
    "CL-OBJECTION-DETERMINISTIC-DOMINATES",
    "CL-OBJECTION-MULTIAGENT-ATTACK-SURFACE",
    "CL-OBJECTION-BENCHMARK-GENERALIZATION",
    "CL-OBJECTION-HUMAN-WAIT-COST",
)

EXPECTED_SOURCE_METADATA = {
    "FR-001": (
        "OFFICIAL_COMPETITION_PAGE",
        "Agent Infra 新智基座 track details and review dimensions",
        "GOAI Global Open-source AI Challenge",
        None,
        "https://www.goaihz.com/tracks",
    ),
    "FR-002": (
        "OFFICIAL_COMPETITION_MANUAL",
        "Agent Infra 新智基座 participant handbook",
        "GOAI Global Open-source AI Challenge",
        None,
        "https://oss.goaihz.com/prod/20260720/6e21b053-f18b-4857-83e2-835bd96d5434.pdf",
    ),
    "FR-003": (
        "OFFICIAL_DOCS",
        "Building effective agents",
        "Anthropic",
        "2024-12-19",
        "https://www.anthropic.com/engineering/building-effective-agents",
    ),
    "FR-004": (
        "OFFICIAL_DOCS",
        "Trustworthy agents in practice",
        "Anthropic",
        "2026-04-09",
        "https://www.anthropic.com/research/trustworthy-agents",
    ),
    "FR-005": (
        "OFFICIAL_SPEC",
        "Model Context Protocol 2025-06-18 server tools specification",
        "Model Context Protocol",
        "2025-06-18",
        "https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
    ),
    "FR-006": (
        "OFFICIAL_SPEC",
        "Model Context Protocol 2025-06-18 authorization specification",
        "Model Context Protocol",
        "2025-06-18",
        "https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization",
    ),
    "FR-007": (
        "OFFICIAL_REPO",
        "Agent2Agent (A2A) Protocol Specification",
        "A2A Project / Linux Foundation",
        None,
        "https://github.com/a2aproject/A2A/blob/16ba52690519bf55b9388e34d4db356efa88aa51/docs/specification.md",
    ),
    "FR-008": (
        "OFFICIAL_REPO",
        "OpenAI Agents SDK tracing documentation",
        "OpenAI",
        None,
        "https://github.com/openai/openai-agents-python/blob/f73e747530d898328ba56eaf45c6f6d1ec806cc8/docs/tracing.md",
    ),
    "FR-009": (
        "OFFICIAL_REPO",
        "Semantic conventions for GenAI agent and framework spans",
        "OpenTelemetry GenAI Semantic Conventions",
        None,
        "https://github.com/open-telemetry/semantic-conventions-genai/blob/8a3767d6c5d09bc0917722720973c0c44182d960/docs/gen-ai/gen-ai-agent-spans.md",
    ),
    "FR-010": (
        "OFFICIAL_DOCS",
        "A shared playbook for trustworthy third party evaluations",
        "OpenAI",
        "2026-05-29",
        "https://openai.com/index/trustworthy-third-party-evaluations-foundations/",
    ),
    "FR-011": (
        "PAPER",
        "Magentic-One: A Generalist Multi-Agent System for Solving Complex Tasks",
        "arXiv (original paper)",
        "2024-11-07",
        "https://arxiv.org/abs/2411.04468v1",
    ),
    "FR-012": (
        "PAPER",
        "Why Do Multi-Agent LLM Systems Fail?",
        "arXiv (original paper)",
        "2025-03-17",
        "https://arxiv.org/abs/2503.13657v3",
    ),
    "FR-013": (
        "PAPER",
        "τ-bench: A Benchmark for Tool-Agent-User Interaction in Real-World Domains",
        "arXiv (original paper)",
        "2024-06-17",
        "https://arxiv.org/abs/2406.12045v1",
    ),
    "FR-014": (
        "PAPER",
        (
            "ToolSandbox: A Stateful, Conversational, Interactive Evaluation Benchmark "
            "for LLM Tool Use Capabilities"
        ),
        "arXiv (original paper)",
        "2024-08-08",
        "https://arxiv.org/abs/2408.04682v2",
    ),
    "FR-015": (
        "OFFICIAL_REPO",
        "ToolSandbox official repository",
        "Apple",
        None,
        "https://github.com/apple/ToolSandbox/blob/165848b9a78cead7ca7fe7c89c688b58e6501219/README.md",
    ),
    "FR-016": (
        "PAPER",
        (
            "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and "
            "Defenses for LLM Agents"
        ),
        "arXiv (original paper)",
        "2024-06-19",
        "https://arxiv.org/abs/2406.13352v3",
    ),
    "FR-017": (
        "PAPER",
        "Agentic Context Engineering: Evolving Contexts for Self-Improving Language Models",
        "arXiv (original paper)",
        "2025-10-06",
        "https://arxiv.org/abs/2510.04618v3",
    ),
    "FR-018": (
        "OFFICIAL_PROJECT_DOCS",
        "LangChain Human-in-the-loop middleware",
        "LangChain",
        None,
        "https://docs.langchain.com/oss/python/langchain/human-in-the-loop",
    ),
    "FR-019": (
        "OFFICIAL_PROJECT_DOCS",
        "LangGraph persistence documentation",
        "LangChain",
        None,
        "https://docs.langchain.com/oss/python/langgraph/persistence",
    ),
    "FR-020": (
        "OFFICIAL_PROJECT_DOCS",
        "LangGraph memory documentation",
        "LangChain",
        None,
        "https://docs.langchain.com/oss/python/langgraph/add-memory",
    ),
    "FR-021": (
        "PAPER",
        (
            "Which Agent Causes Task Failures and When? On Automated Failure Attribution "
            "of LLM Multi-Agent Systems"
        ),
        "arXiv (original paper)",
        "2025-04-30",
        "https://arxiv.org/abs/2505.00212v3",
    ),
}

SOURCE_TYPE_DOMAINS = {
    "OFFICIAL_COMPETITION_PAGE": {"www.goaihz.com"},
    "OFFICIAL_COMPETITION_MANUAL": {"oss.goaihz.com"},
    "OFFICIAL_DOCS": {"www.anthropic.com", "openai.com"},
    "OFFICIAL_SPEC": {"modelcontextprotocol.io"},
    "OFFICIAL_REPO": {"github.com"},
    "OFFICIAL_PROJECT_DOCS": {"docs.langchain.com"},
    "PAPER": {"arxiv.org"},
}


def source_document() -> dict:
    return json.loads(SOURCES_PATH.read_text(encoding="utf-8"))


def normalized_registry(document: dict) -> bytes:
    payload = {
        "claims": document["claims"],
        "official_rubric": document["official_rubric"],
        "sources": document["sources"],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def validate_public_source_url(source: dict) -> None:
    parsed = urlparse(source["url"])
    assert parsed.scheme == "https"
    assert parsed.username is None and parsed.password is None
    assert parsed.query == ""
    assert parsed.fragment == ""
    assert parsed.hostname == source["domain"]
    assert source["domain"] in SOURCE_TYPE_DOMAINS[source["source_type"]]
    assert not re.search(r"(?i)(?:token|api[_-]?key|secret|signature|sig)=", source["url"])


def test_frontier_source_schema_and_exact_registry_are_valid() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    document = source_document()

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
    assert document["research_id"] == "frontier-champion-research-2026-08-21-r1"

    claims = document["claims"]
    sources = document["sources"]
    assert len(claims) == 30
    assert len(sources) == 21
    assert tuple(item["claim_id"] for item in claims) == EXPECTED_CLAIM_IDS
    assert tuple(item["source_id"] for item in sources) == tuple(EXPECTED_SOURCE_METADATA)

    integrity = document["registry_integrity"]
    assert integrity["claim_count"] == 30
    assert integrity["source_count"] == 21
    assert tuple(integrity["claim_ids"]) == EXPECTED_CLAIM_IDS
    assert tuple(integrity["source_ids"]) == tuple(EXPECTED_SOURCE_METADATA)
    assert integrity["is_signature"] is False
    digest = hashlib.sha256(normalized_registry(document)).hexdigest()
    assert integrity["normalized_registry_sha256"] == f"sha256:{digest}"

    rubric = document["official_rubric"]
    dimensions = rubric["dimensions"]
    assert tuple(item["id"] for item in dimensions) == RUBRIC_IDS
    assert tuple(item["weight_points"] for item in dimensions) == RUBRIC_WEIGHTS
    assert len({item["id"] for item in dimensions}) == 5
    assert sum(item["weight_points"] for item in dimensions) == 100
    assert rubric["total_points"] == 100
    assert tuple(rubric["source_ids"]) == ("FR-001", "FR-002")

    assert {item["layer"] for item in claims} == {
        "VERIFIED_FACT",
        "TESTABLE_HYPOTHESIS",
        "NO_EVIDENCE",
        "STRONGEST_OBJECTION",
    }
    for source in sources:
        expected = EXPECTED_SOURCE_METADATA[source["source_id"]]
        actual = tuple(
            source[field] for field in ("source_type", "title", "publisher", "published_at", "url")
        )
        assert actual == expected
        assert source["accessed_at"] == document["accessed_at"] == "2026-08-21"
        validate_public_source_url(source)


def test_rubric_prefix_items_still_require_common_dimension_fields() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    document = source_document()
    del document["official_rubric"]["dimensions"][0]["source_ids"]

    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)


def test_claim_source_ids_and_supports_are_exact_bidirectional_links() -> None:
    document = source_document()
    claims_by_id = {item["claim_id"]: item for item in document["claims"]}
    claim_sources = {claim_id: set(claim["source_ids"]) for claim_id, claim in claims_by_id.items()}
    source_claims = {source["source_id"]: set(source["supports"]) for source in document["sources"]}

    for claim in document["claims"]:
        assert claim["official_score_dimensions"]
        if claim["layer"] == "VERIFIED_FACT":
            assert claim["source_ids"]
        inverse = {
            source_id
            for source_id, supported in source_claims.items()
            if claim["claim_id"] in supported
        }
        assert set(claim["source_ids"]) == inverse

    for source in document["sources"]:
        assert source["supports"]
        for claim_id in source["supports"]:
            assert claim_id in claims_by_id
            assert source["source_id"] in claim_sources[claim_id]


def test_every_citation_pair_matches_claim_centric_source_ids() -> None:
    document = source_document()
    strategy = DOC_PATH.read_text(encoding="utf-8")
    claims_by_id = {item["claim_id"]: item for item in document["claims"]}
    pair_pattern = re.compile(r"\[(CL-[A-Z0-9_-]+)\]((?:\[FR-[0-9]{3}\])+)")
    cited_claims = set()

    for match in pair_pattern.finditer(strategy):
        claim_id = match.group(1)
        source_ids = set(re.findall(r"FR-[0-9]{3}", match.group(2)))
        assert claim_id in claims_by_id
        assert source_ids == set(claims_by_id[claim_id]["source_ids"])
        cited_claims.add(claim_id)

    facts_with_sources = {claim["claim_id"] for claim in document["claims"] if claim["source_ids"]}
    assert cited_claims == facts_with_sources


def test_strategy_mentions_exact_registered_claims_sources_and_urls() -> None:
    document = source_document()
    strategy = DOC_PATH.read_text(encoding="utf-8")
    registered_claims = {item["claim_id"] for item in document["claims"]}
    registered_sources = {item["source_id"] for item in document["sources"]}
    cited_claims = set(re.findall(r"(?:`|\[)(CL-[A-Z0-9_-]+)(?:`|\])", strategy))
    cited_sources = set(re.findall(r"FR-[0-9]{3}", strategy))

    assert cited_claims == registered_claims
    assert cited_sources == registered_sources
    for source in document["sources"]:
        assert source["url"] in strategy


def test_source_revision_records_freeze_or_bound_the_content() -> None:
    document = source_document()

    for source in document["sources"]:
        revision = source["revision"]
        kind = revision["kind"]
        if kind == "GIT_COMMIT":
            match = re.search(r"/blob/([0-9a-f]{40})/", source["url"])
            assert match
            assert match.group(1) == revision["value"]
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", revision["content_sha256"])
        elif kind == "ARXIV_VERSION":
            match = re.search(r"/abs/[0-9]{4}\.[0-9]{5}v([1-9][0-9]*)$", source["url"])
            assert match
            assert revision["value"] == f"v{match.group(1)}"
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", revision["content_sha256"])
        elif kind == "FILE_SHA256":
            assert source["source_id"] == "FR-002"
            assert revision["value"] == revision["content_sha256"]
        elif kind == "SPEC_VERSION":
            assert revision["value"] in source["url"]
        elif kind == "UNVERSIONED_POINT_IN_TIME":
            assert any(
                "UNVERSIONED_POINT_IN_TIME" in limitation for limitation in source["limitations"]
            )
        else:  # pragma: no cover - the JSON Schema rejects unknown kinds first.
            raise AssertionError(f"unexpected revision kind: {kind}")


@pytest.mark.parametrize(
    "unsafe_url",
    (
        "https://user:password@github.com/a2aproject/A2A",
        "https://github.com/a2aproject/A2A?token=redacted",
        "https://github.com/a2aproject/A2A?api_key=redacted",
        "https://github.com/a2aproject/A2A?signature=redacted",
        "https://github.com/a2aproject/A2A#fragment",
    ),
)
def test_public_source_url_policy_rejects_credentials_queries_and_fragments(
    unsafe_url: str,
) -> None:
    source = {
        "url": unsafe_url,
        "domain": "github.com",
        "source_type": "OFFICIAL_REPO",
    }
    with pytest.raises(AssertionError):
        validate_public_source_url(source)


def test_public_materials_have_no_obvious_pii_or_secret_patterns() -> None:
    public_paths = (DOC_PATH, SOURCES_PATH, SCHEMA_PATH)
    secret_pattern = re.compile(
        r"(?i)(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
        r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|"
        r"xox[baprs]-[A-Za-z0-9-]{20,})\b|"
        r"\b(?:api[_ -]?key|access[_ -]?token|client[_ -]?secret)\s*[:=])"
    )
    pii_pattern = re.compile(
        r"(?:\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|"
        r"(?<!\d)1[3-9]\d{9}(?!\d)|(?<!\d)\d{17}[\dXx](?!\d))"
    )

    for path in public_paths:
        content = path.read_text(encoding="utf-8")
        assert not secret_pattern.search(content), path
        assert not pii_pattern.search(content), path


def test_strategy_keeps_score_and_execution_boundaries_explicit() -> None:
    strategy = DOC_PATH.read_text(encoding="utf-8")

    for arm in ("deterministic_reference", "single_agent", "six_agent"):
        assert arm in strategy
    for marker in (
        "UNKNOWN",
        "UNSAFE_SUCCESS",
        "leader_phase=Running",
        "specialist_ready_workers=5",
        "total_worker_containers=6",
        "specialist_ready_workers=0",
        "total_worker_containers=1",
        "Stopped",
        "NOT_EXECUTED",
        "25/25/25/20/5",
    ):
        assert marker in strategy
