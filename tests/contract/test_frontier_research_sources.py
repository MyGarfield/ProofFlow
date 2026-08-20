import json
import re
from pathlib import Path
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).parents[2]
RESEARCH_DIR = ROOT / "research"
SOURCES_PATH = RESEARCH_DIR / "frontier_sources.json"
SCHEMA_PATH = RESEARCH_DIR / "frontier_sources.schema.json"
DOC_PATH = ROOT / "docs/11_FRONTIER_RESEARCH_AND_CHAMPION_STRATEGY.md"


def source_document() -> dict:
    return json.loads(SOURCES_PATH.read_text(encoding="utf-8"))


def test_frontier_source_schema_and_registry_are_valid() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    document = source_document()

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)

    claims = document["claims"]
    sources = document["sources"]
    claim_ids = [item["claim_id"] for item in claims]
    source_ids = [item["source_id"] for item in sources]
    assert len(claim_ids) == len(set(claim_ids))
    assert len(source_ids) == len(set(source_ids))
    assert set(source_ids) == {f"FR-{index:03d}" for index in range(1, len(sources) + 1)}
    assert {item["layer"] for item in claims} == {
        "VERIFIED_FACT",
        "TESTABLE_HYPOTHESIS",
        "NO_EVIDENCE",
        "STRONGEST_OBJECTION",
    }

    known_claims = set(claim_ids)
    for source in sources:
        assert set(source["supports"]).issubset(known_claims)
        assert source["accessed_at"] == document["accessed_at"] == "2026-08-20"
        parsed = urlparse(source["url"])
        assert parsed.scheme == "https"
        assert parsed.username is None and parsed.password is None
        assert parsed.hostname is not None
        assert "localhost" not in parsed.hostname


def test_every_registered_claim_source_and_url_is_referenced_by_strategy_doc() -> None:
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


def test_claim_supports_links_only_to_registered_claims() -> None:
    document = source_document()
    claims_by_id = {item["claim_id"]: item for item in document["claims"]}

    for source in document["sources"]:
        assert source["supports"]
        for claim_id in source["supports"]:
            assert claims_by_id[claim_id]["layer"] == "VERIFIED_FACT"


def test_strategy_keeps_score_and_execution_boundaries_explicit() -> None:
    strategy = DOC_PATH.read_text(encoding="utf-8")

    for arm in ("deterministic_reference", "single_agent", "six_agent"):
        assert arm in strategy
    for weight in ("25", "25", "25", "20", "5"):
        assert weight in strategy
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
    ):
        assert marker in strategy
