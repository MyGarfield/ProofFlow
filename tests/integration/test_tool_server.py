import json
import socket
import threading
import time
from base64 import b64encode
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import pytest

from proofflow.contracts import (
    CalculateOutput,
    CaseManifest,
    DeterministicCalculateToolCall,
    EvidenceIngestOutput,
    EvidenceIngestRequest,
    EvidenceIngestToolCall,
    RuleCatalog,
    RuleRetrieveOutput,
    RuleRetrieveRequest,
    RuleRetrieveToolCall,
)
from proofflow.models import (
    DataClassification,
    EvidenceObject,
    FactStatus,
    SkillContext,
    SkillResult,
    SkillStatus,
)
from proofflow.skills import evidence_ingest, rule_retrieve
from proofflow.tool_server import (
    DETERMINISTIC_CALCULATE_PATH,
    EVIDENCE_INGEST_PATH,
    HEALTH_PATH,
    MAX_CHUNK_LINE_BYTES,
    MAX_CHUNK_TRAILER_BYTES,
    RULE_RETRIEVE_PATH,
    ProofFlowToolHTTPServer,
    ToolServerConfigurationError,
    api_token_from_environment,
    load_rule_catalog,
)

ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "examples/cases/happy_path"
RULES = ROOT / "data/rules/cn_labor_contract_law.catalog.json"
NOW = datetime(2026, 8, 20, 3, 0, tzinfo=UTC)
TOKEN = "synthetic-test-backend-token"


def context(identity: str, key: str) -> SkillContext:
    return SkillContext(
        tenant_id="tenant-public-demo",
        case_id="case-happy-001",
        caller_identity=identity,
        trace_id="trace-http-integration",
        idempotency_key=key,
        expected_state_version=0,
    )


def fixture_evidence() -> tuple[EvidenceObject, ...]:
    manifest = CaseManifest.model_validate_json((FIXTURE / "manifest.json").read_text())
    evidence: list[EvidenceObject] = []
    for document in manifest.documents:
        path = FIXTURE / document.path
        result = evidence_ingest(
            context("PF-A2", document.document_id),
            EvidenceIngestRequest(
                document_id=document.document_id,
                media_type=document.media_type,
                declared_sha256=document.sha256,
                raw_content=path.read_bytes(),
            ),
            now=NOW,
        )
        assert result.value is not None
        evidence.extend(result.value.evidence_objects)
    return tuple(evidence)


def evidence_ingest_calls() -> tuple[EvidenceIngestToolCall, ...]:
    manifest = CaseManifest.model_validate_json((FIXTURE / "manifest.json").read_text())
    calls: list[EvidenceIngestToolCall] = []
    for document in manifest.documents:
        calls.append(
            EvidenceIngestToolCall(
                fixture_status="SYNTHETIC",
                context=context("PF-A2", document.document_id).model_dump(mode="json"),
                arguments={
                    "document_id": document.document_id,
                    "media_type": document.media_type,
                    "declared_sha256": document.sha256,
                    "raw_content_base64": b64encode((FIXTURE / document.path).read_bytes()).decode(
                        "ascii"
                    ),
                },
            )
        )
    return tuple(calls)


def ingest_fixture_over_http(base_url: str) -> tuple[EvidenceObject, ...]:
    evidence: list[EvidenceObject] = []
    for call in evidence_ingest_calls():
        status, body = request_json(
            base_url,
            EVIDENCE_INGEST_PATH,
            payload=call.model_dump(mode="json"),
            token=TOKEN,
        )
        result = SkillResult[EvidenceIngestOutput].model_validate_json(json.dumps(body))
        assert status == 200
        assert result.status == SkillStatus.SUCCESS
        assert result.value is not None
        evidence.extend(result.value.evidence_objects)
    return tuple(evidence)


def fixture_rules() -> RuleRetrieveOutput:
    result = rule_retrieve(
        context("PF-A3", "fixture-rules"),
        RuleRetrieveRequest(
            issue_codes=(
                "economic_compensation_amount",
                "economic_compensation_wage_basis",
            ),
            jurisdiction="CN-ZJ-HZ",
            as_of_date=datetime(2026, 8, 20, tzinfo=UTC).date(),
        ),
        catalog=RuleCatalog.model_validate_json(RULES.read_text()),
        now=NOW,
    )
    assert result.value is not None
    return result.value


@contextmanager
def running_service(**server_options: Any) -> Iterator[str]:
    catalog = RuleCatalog.model_validate_json(RULES.read_text())
    server = ProofFlowToolHTTPServer(
        ("127.0.0.1", 0),
        catalog=catalog,
        api_token=TOKEN,
        clock=lambda: NOW,
        **server_options,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request_json(
    base_url: str,
    path: str,
    *,
    payload: Any | None = None,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers: dict[str, str] = {}
    data: bytes | None = None
    method = "GET"
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(base_url + path, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def raw_exchange(base_url: str, request: bytes, *, shutdown_write: bool = False) -> bytes:
    parsed = urlsplit(base_url)
    assert parsed.hostname is not None and parsed.port is not None
    with socket.create_connection((parsed.hostname, parsed.port), timeout=2) as connection:
        connection.settimeout(2)
        connection.sendall(request)
        if shutdown_write:
            connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            try:
                chunk = connection.recv(64 * 1024)
            except ConnectionResetError:
                break
            if not chunk:
                break
            response.extend(chunk)
    return bytes(response)


def parse_raw_response(response: bytes) -> tuple[int, dict[str, Any]]:
    headers, separator, body = response.partition(b"\r\n\r\n")
    assert separator and headers.startswith(b"HTTP/1.1 ")
    status = int(headers.split(b" ", 2)[1])
    return status, json.loads(body)


def raw_post_request(
    path: str,
    body: bytes,
    content_length_headers: tuple[str, ...] = (),
    *,
    transfer_encoding_headers: tuple[str, ...] = (),
    additional_headers: tuple[str, ...] = (),
) -> bytes:
    content_lengths = "".join(f"Content-Length: {value}\r\n" for value in content_length_headers)
    transfer_encodings = "".join(
        f"Transfer-Encoding: {value}\r\n" for value in transfer_encoding_headers
    )
    additional = "".join(f"{value}\r\n" for value in additional_headers)
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        f"Authorization: Bearer {TOKEN}\r\n"
        "Content-Type: application/json\r\n"
        f"{content_lengths}"
        f"{transfer_encodings}"
        f"{additional}"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    return headers + body


def encode_chunked_body(
    chunks: tuple[bytes, ...],
    *,
    first_extension: str | None = None,
    trailers: tuple[bytes, ...] = (),
) -> bytes:
    encoded = bytearray()
    for index, chunk in enumerate(chunks):
        extension = f";{first_extension}" if index == 0 and first_extension else ""
        encoded.extend(f"{len(chunk):X}{extension}\r\n".encode("ascii"))
        encoded.extend(chunk)
        encoded.extend(b"\r\n")
    encoded.extend(b"0\r\n")
    for trailer in trailers:
        encoded.extend(trailer)
        encoded.extend(b"\r\n")
    encoded.extend(b"\r\n")
    return bytes(encoded)


def rule_call() -> RuleRetrieveToolCall:
    return RuleRetrieveToolCall(
        fixture_status="SYNTHETIC",
        context=context("PF-A3", "http-rule").model_dump(mode="json"),
        arguments=RuleRetrieveRequest(
            issue_codes=(
                "economic_compensation_amount",
                "economic_compensation_wage_basis",
            ),
            jurisdiction="CN-ZJ-HZ",
            as_of_date=datetime(2026, 8, 20, tzinfo=UTC).date(),
        ),
    )


def calculate_call(
    *,
    evidence: tuple[EvidenceObject, ...] | None = None,
    rules: RuleRetrieveOutput | None = None,
) -> DeterministicCalculateToolCall:
    rules = fixture_rules() if rules is None else rules
    return DeterministicCalculateToolCall(
        fixture_status="SYNTHETIC",
        context=context("PF-A4", "http-calculate").model_dump(mode="json"),
        arguments={
            "evidence": fixture_evidence() if evidence is None else evidence,
            "rule_citations": rules.citations,
            "rule_scope": rules.rule_scope,
            "formula_version": "cn-economic-compensation-v0.1",
        },
    )


def reseal_artifact(
    artifact: Any,
    *,
    meta_updates: dict[str, Any] | None = None,
    artifact_updates: dict[str, Any] | None = None,
) -> Any:
    updated_meta = artifact.meta.model_copy(update={**(meta_updates or {}), "content_hash": None})
    return artifact.model_copy(update={"meta": updated_meta, **(artifact_updates or {})}).seal()


def test_health_is_public_and_contains_no_authentication_material() -> None:
    with running_service() as base_url:
        status, body = request_json(base_url, HEALTH_PATH)

    assert status == 200
    assert body["status"] == "ok"
    assert body["side_effects"] == "IN_MEMORY_SYNTHETIC_ARTIFACT_REGISTRY"
    assert "count" not in body
    assert "case" not in body
    assert TOKEN not in json.dumps(body)


@pytest.mark.parametrize("token", [None, "wrong-token"])
def test_tool_endpoints_reject_missing_or_invalid_bearer(token: str | None) -> None:
    payload = rule_call().model_dump(mode="json")
    with running_service() as base_url:
        status, body = request_json(base_url, RULE_RETRIEVE_PATH, payload=payload, token=token)

    assert status == 401
    assert body == {
        "error": {
            "code": "UNAUTHORIZED",
            "message": "valid Bearer authorization is required",
        }
    }
    assert TOKEN not in json.dumps(body)


@pytest.mark.parametrize("token", [None, "wrong-token"])
def test_evidence_ingest_rejects_missing_or_invalid_bearer(token: str | None) -> None:
    payload = evidence_ingest_calls()[0].model_dump(mode="json")
    with running_service() as base_url:
        status, body = request_json(
            base_url,
            EVIDENCE_INGEST_PATH,
            payload=payload,
            token=token,
        )

    assert status == 401
    assert body["error"]["code"] == "UNAUTHORIZED"
    assert TOKEN not in json.dumps(body)


def test_evidence_ingest_schema_and_source_hash_fail_closed() -> None:
    invalid_base64 = evidence_ingest_calls()[0].model_dump(mode="json")
    invalid_base64["arguments"]["raw_content_base64"] = "not standard base64-_"
    non_synthetic = evidence_ingest_calls()[0].model_dump(mode="json")
    non_synthetic["fixture_status"] = "REAL"
    source_mismatch = evidence_ingest_calls()[0].model_dump(mode="json")
    source_mismatch["arguments"]["declared_sha256"] = "sha256:" + "0" * 64

    with running_service() as base_url:
        base64_status, base64_body = request_json(
            base_url,
            EVIDENCE_INGEST_PATH,
            payload=invalid_base64,
            token=TOKEN,
        )
        synthetic_status, synthetic_body = request_json(
            base_url,
            EVIDENCE_INGEST_PATH,
            payload=non_synthetic,
            token=TOKEN,
        )
        hash_status, hash_body = request_json(
            base_url,
            EVIDENCE_INGEST_PATH,
            payload=source_mismatch,
            token=TOKEN,
        )

    assert base64_status == 422
    assert base64_body["error"]["code"] == "SCHEMA_VALIDATION_FAILED"
    assert synthetic_status == 422
    assert synthetic_body["error"]["code"] == "SCHEMA_VALIDATION_FAILED"
    assert hash_status == 200
    assert hash_body["status"] == "BLOCKED"
    assert hash_body["value"] is None
    assert {issue["code"] for issue in hash_body["issues"]} == {"SOURCE_HASH_MISMATCH"}


def test_trusted_evidence_is_process_local_and_lost_after_restart() -> None:
    with running_service() as first_base_url:
        evidence = ingest_fixture_over_http(first_base_url)
    payload = calculate_call(evidence=evidence).model_dump(mode="json")

    with running_service() as restarted_base_url:
        status, body = request_json(
            restarted_base_url,
            DETERMINISTIC_CALCULATE_PATH,
            payload=payload,
            token=TOKEN,
        )

    assert status == 200
    assert body["status"] == "BLOCKED"
    assert body["value"] is None
    assert "UNTRUSTED_EVIDENCE" in {issue["code"] for issue in body["issues"]}


def test_trusted_evidence_capacity_failure_is_atomic_and_bounded() -> None:
    payload = evidence_ingest_calls()[0].model_dump(mode="json")
    with running_service(trusted_artifact_capacity=1) as base_url:
        status, body = request_json(
            base_url,
            EVIDENCE_INGEST_PATH,
            payload=payload,
            token=TOKEN,
        )

    assert status == 503
    assert body == {
        "error": {
            "code": "TRUST_STORE_CAPACITY_EXHAUSTED",
            "message": "trusted Evidence registry capacity is exhausted",
        }
    }
    assert len(json.dumps(body)) < 512


def test_rule_and_calculation_tools_run_over_http_with_existing_core_contracts() -> None:
    with running_service() as base_url:
        evidence = ingest_fixture_over_http(base_url)
        rule_status, rule_body = request_json(
            base_url,
            RULE_RETRIEVE_PATH,
            payload=rule_call().model_dump(mode="json"),
            token=TOKEN,
        )
        rule_result = SkillResult[RuleRetrieveOutput].model_validate_json(json.dumps(rule_body))
        assert rule_result.value is not None

        calculate_call = DeterministicCalculateToolCall(
            fixture_status="SYNTHETIC",
            context=context("PF-A4", "http-calculate").model_dump(mode="json"),
            arguments={
                "evidence": evidence,
                "rule_citations": rule_result.value.citations,
                "rule_scope": rule_result.value.rule_scope,
                "formula_version": "cn-economic-compensation-v0.1",
            },
        )
        calculate_status, calculate_body = request_json(
            base_url,
            DETERMINISTIC_CALCULATE_PATH,
            payload=calculate_call.model_dump(mode="json"),
            token=TOKEN,
        )

    calculation_result = SkillResult[CalculateOutput].model_validate_json(
        json.dumps(calculate_body)
    )
    assert rule_status == 200
    assert rule_result.status == SkillStatus.SUCCESS
    assert calculate_status == 200
    assert calculation_result.status == SkillStatus.SUCCESS
    assert calculation_result.value is not None
    assert calculation_result.value.sheet.total == Decimal("60000.00")
    assert calculation_result.value.sheet.verify_hash()


def test_rule_http_no_match_returns_needs_human_without_citations() -> None:
    payload = rule_call().model_dump(mode="json")
    payload["arguments"] = {
        "issue_codes": ["not_in_catalog"],
        "jurisdiction": "CN-ZJ-HZ",
        "as_of_date": "2026-08-20",
    }
    with running_service() as base_url:
        status, body = request_json(
            base_url,
            RULE_RETRIEVE_PATH,
            payload=payload,
            token=TOKEN,
        )

    result = SkillResult[RuleRetrieveOutput].model_validate_json(json.dumps(body))
    assert status == 200
    assert result.status == SkillStatus.NEEDS_HUMAN
    assert result.value is not None
    assert result.value.citations == ()
    assert result.value.missing_issue_codes == ("not_in_catalog",)


def test_chunked_rule_to_calculation_flow_runs_over_real_http_socket() -> None:
    rule_payload = json.dumps(rule_call().model_dump(mode="json"), ensure_ascii=False).encode()
    rule_chunks = (rule_payload[:23], rule_payload[23:211], rule_payload[211:])
    rule_body = encode_chunked_body(
        rule_chunks,
        first_extension='proof="synthetic"',
        trailers=(b"X-ProofFlow-Smoke: accepted",),
    )

    with running_service() as base_url:
        evidence = ingest_fixture_over_http(base_url)
        rule_response = raw_exchange(
            base_url,
            raw_post_request(
                RULE_RETRIEVE_PATH,
                rule_body,
                transfer_encoding_headers=("chunked",),
                additional_headers=("Trailer: X-ProofFlow-Smoke",),
            ),
        )
        rule_status, rule_result_body = parse_raw_response(rule_response)
        rule_result = SkillResult[RuleRetrieveOutput].model_validate_json(
            json.dumps(rule_result_body)
        )
        assert rule_result.value is not None

        calculation_payload = calculate_call(evidence=evidence).model_dump(mode="json")
        calculation_payload["arguments"]["rule_citations"] = [
            citation.model_dump(mode="json") for citation in rule_result.value.citations
        ]
        calculation_payload["arguments"]["rule_scope"] = rule_result.value.rule_scope.model_dump(
            mode="json"
        )
        calculation_bytes = json.dumps(calculation_payload, ensure_ascii=False).encode()
        calculation_chunks = tuple(
            calculation_bytes[index : index + 997]
            for index in range(0, len(calculation_bytes), 997)
        )
        calculation_response = raw_exchange(
            base_url,
            raw_post_request(
                DETERMINISTIC_CALCULATE_PATH,
                encode_chunked_body(calculation_chunks),
                transfer_encoding_headers=("chunked",),
            ),
        )

    calculation_status, calculation_result_body = parse_raw_response(calculation_response)
    calculation_result = SkillResult[CalculateOutput].model_validate_json(
        json.dumps(calculation_result_body)
    )
    assert rule_status == 200
    assert rule_result.status == SkillStatus.SUCCESS
    assert calculation_status == 200
    assert calculation_result.status == SkillStatus.SUCCESS
    assert calculation_result.value is not None
    assert calculation_result.value.sheet.total == Decimal("60000.00")


def test_schema_validation_and_route_owned_identity_fail_with_422() -> None:
    invalid_schema = rule_call().model_dump(mode="json")
    invalid_schema["unexpected"] = "must be rejected"
    wrong_rule_identity = rule_call().model_dump(mode="json")
    wrong_rule_identity["context"]["caller_identity"] = "PF-A4"
    wrong_calculation_identity = calculate_call().model_dump(mode="json")
    wrong_calculation_identity["context"]["caller_identity"] = "PF-A3"
    route_owned_identity = rule_call().model_dump(mode="json")
    del route_owned_identity["context"]["caller_identity"]
    with running_service() as base_url:
        invalid_status, invalid_body = request_json(
            base_url,
            RULE_RETRIEVE_PATH,
            payload=invalid_schema,
            token=TOKEN,
        )
        wrong_rule_status, wrong_rule_body = request_json(
            base_url,
            RULE_RETRIEVE_PATH,
            payload=wrong_rule_identity,
            token=TOKEN,
        )
        wrong_calculation_status, wrong_calculation_body = request_json(
            base_url,
            DETERMINISTIC_CALCULATE_PATH,
            payload=wrong_calculation_identity,
            token=TOKEN,
        )
        defaulted_status, defaulted_body = request_json(
            base_url,
            RULE_RETRIEVE_PATH,
            payload=route_owned_identity,
            token=TOKEN,
        )

    assert invalid_status == 422
    assert invalid_body["error"]["code"] == "SCHEMA_VALIDATION_FAILED"
    assert invalid_body["error"]["details"] == [
        {"location": ["unexpected"], "type": "extra_forbidden"}
    ]
    assert wrong_rule_status == 422
    assert wrong_rule_body["error"]["code"] == "SCHEMA_VALIDATION_FAILED"
    assert wrong_calculation_status == 422
    assert wrong_calculation_body["error"]["code"] == "SCHEMA_VALIDATION_FAILED"
    assert defaulted_status == 200
    assert defaulted_body["status"] == "SUCCESS"


def test_calculation_artifact_attacks_return_stable_blocked_codes() -> None:
    with running_service() as base_url:
        registered_evidence = ingest_fixture_over_http(base_url)
        call = calculate_call(evidence=registered_evidence)
        base_payload = call.model_dump(mode="json")
        evidence = call.arguments.evidence[0]
        rule = call.arguments.rule_citations[0]

        tampered_evidence = deepcopy(base_payload)
        tampered_evidence["arguments"]["evidence"][0]["normalized_value"] = "tampered"
        tampered_rule = deepcopy(base_payload)
        tampered_rule["arguments"]["rule_citations"][0]["excerpt"] = "tampered"
        tampered_scope = deepcopy(base_payload)
        tampered_scope["arguments"]["rule_scope"]["jurisdiction"] = "US-CA"

        attacks: list[tuple[str, dict[str, Any], str]] = [
            ("evidence seal", tampered_evidence, "UNVERIFIED_ARTIFACT"),
            ("rule seal", tampered_rule, "UNVERIFIED_ARTIFACT"),
            ("rule scope", tampered_scope, "RULE_SCOPE_MISMATCH"),
        ]
        artifact_variants = (
            (
                "modified and resealed evidence",
                "evidence",
                reseal_artifact(
                    evidence,
                    artifact_updates={"normalized_value": "99999.00"},
                ),
                "UNTRUSTED_EVIDENCE",
            ),
            (
                "unresolved evidence",
                "evidence",
                reseal_artifact(
                    evidence,
                    artifact_updates={"fact_status": FactStatus.PROPOSED},
                ),
                "UNRESOLVED_PARAMETER",
            ),
            (
                "evidence producer",
                "evidence",
                reseal_artifact(evidence, meta_updates={"producer_identity": "PF-A5"}),
                "UNVERIFIED_ARTIFACT",
            ),
            (
                "rule producer",
                "rule_citations",
                reseal_artifact(rule, meta_updates={"producer_identity": "PF-A5"}),
                "UNVERIFIED_ARTIFACT",
            ),
            (
                "classification",
                "evidence",
                reseal_artifact(
                    evidence,
                    meta_updates={"classification": DataClassification.INTERNAL},
                ),
                "UNVERIFIED_ARTIFACT",
            ),
            (
                "cross tenant",
                "evidence",
                reseal_artifact(evidence, meta_updates={"tenant_id": "tenant-other"}),
                "CROSS_TENANT_REFERENCE",
            ),
            (
                "cross case",
                "evidence",
                reseal_artifact(evidence, meta_updates={"case_id": "case-other"}),
                "CROSS_TENANT_REFERENCE",
            ),
            (
                "cross trace",
                "evidence",
                reseal_artifact(evidence, meta_updates={"trace_id": "trace-other"}),
                "CROSS_TENANT_REFERENCE",
            ),
            (
                "catalog mismatch",
                "rule_citations",
                reseal_artifact(rule, artifact_updates={"excerpt": "forged summary"}),
                "UNVERIFIED_ARTIFACT",
            ),
        )
        for name, collection, artifact, expected_code in artifact_variants:
            payload = deepcopy(base_payload)
            payload["arguments"][collection][0] = artifact.model_dump(mode="json")
            attacks.append((name, payload, expected_code))

        for name, payload, expected_code in attacks:
            status, body = request_json(
                base_url,
                DETERMINISTIC_CALCULATE_PATH,
                payload=payload,
                token=TOKEN,
            )
            assert status == 200, name
            assert body["status"] == "BLOCKED", name
            assert body["value"] is None, name
            assert expected_code in {issue["code"] for issue in body["issues"]}, name


@pytest.mark.parametrize(
    "issue_codes",
    [
        [],
        ["duplicate", "duplicate"],
        [f"issue-{index}" for index in range(33)],
        ["duplicate"] * 1000,
    ],
)
def test_rule_issue_code_cardinality_and_uniqueness_fail_closed(
    issue_codes: list[str],
) -> None:
    payload = rule_call().model_dump(mode="json")
    payload["arguments"]["issue_codes"] = issue_codes
    with running_service() as base_url:
        status, body = request_json(
            base_url,
            RULE_RETRIEVE_PATH,
            payload=payload,
            token=TOKEN,
        )

    assert status == 422
    assert body["error"]["code"] == "SCHEMA_VALIDATION_FAILED"
    assert len(json.dumps(body)) < 4096


@pytest.mark.parametrize("length_delta", [0, 1])
def test_duplicate_or_conflicting_content_length_is_rejected(length_delta: int) -> None:
    body = json.dumps(rule_call().model_dump(mode="json")).encode("utf-8")
    lengths = (str(len(body)), str(len(body) + length_delta))
    with running_service() as base_url:
        response = raw_exchange(
            base_url,
            raw_post_request(RULE_RETRIEVE_PATH, body, lengths),
        )

    status, payload = parse_raw_response(response)
    assert status == 400
    assert payload["error"]["code"] == "AMBIGUOUS_CONTENT_LENGTH"


def test_content_length_and_transfer_encoding_are_rejected_together() -> None:
    body = json.dumps(rule_call().model_dump(mode="json")).encode()
    request = raw_post_request(
        RULE_RETRIEVE_PATH,
        encode_chunked_body((body,)),
        (str(len(body)),),
        transfer_encoding_headers=("chunked",),
    )
    with running_service() as base_url:
        response = raw_exchange(base_url, request)

    status, payload = parse_raw_response(response)
    assert status == 400
    assert payload["error"]["code"] == "AMBIGUOUS_REQUEST_FRAMING"


def test_extremely_long_decimal_content_length_returns_bounded_413() -> None:
    with running_service() as base_url:
        response = raw_exchange(
            base_url,
            raw_post_request(RULE_RETRIEVE_PATH, b"", ("9" * 5000,)),
        )

    status, payload = parse_raw_response(response)
    assert status == 413
    assert payload["error"]["code"] == "REQUEST_TOO_LARGE"


@pytest.mark.parametrize(
    ("transfer_encodings", "expected_code"),
    [
        (("chunked", "chunked"), "AMBIGUOUS_TRANSFER_ENCODING"),
        (("chunked, chunked",), "AMBIGUOUS_TRANSFER_ENCODING"),
        (("gzip",), "UNSUPPORTED_TRANSFER_ENCODING"),
        (("gzip, chunked",), "AMBIGUOUS_TRANSFER_ENCODING"),
    ],
)
def test_ambiguous_or_unsupported_transfer_encoding_is_rejected(
    transfer_encodings: tuple[str, ...],
    expected_code: str,
) -> None:
    with running_service() as base_url:
        response = raw_exchange(
            base_url,
            raw_post_request(
                RULE_RETRIEVE_PATH,
                b"0\r\n\r\n",
                transfer_encoding_headers=transfer_encodings,
            ),
        )

    status, payload = parse_raw_response(response)
    assert status == 400
    assert payload["error"]["code"] == expected_code


@pytest.mark.parametrize(
    ("framing", "expected_code"),
    [
        ("content-length-vt", "INVALID_CONTENT_LENGTH"),
        ("content-length-ff", "INVALID_CONTENT_LENGTH"),
        ("transfer-encoding-vt", "INVALID_TRANSFER_ENCODING"),
        ("transfer-encoding-ff", "INVALID_TRANSFER_ENCODING"),
    ],
)
def test_framing_headers_reject_non_ows_control_bytes(
    framing: str,
    expected_code: str,
) -> None:
    body = json.dumps(rule_call().model_dump(mode="json")).encode()
    control = "\x0b" if framing.endswith("vt") else "\x0c"
    if framing.startswith("content-length"):
        request = raw_post_request(
            RULE_RETRIEVE_PATH,
            body,
            (control + str(len(body)),),
        )
    else:
        request = raw_post_request(
            RULE_RETRIEVE_PATH,
            encode_chunked_body((body,)),
            transfer_encoding_headers=(control + "chunked",),
        )

    with running_service() as base_url:
        response = raw_exchange(base_url, request)

    status, payload = parse_raw_response(response)
    assert status == 400
    assert payload["error"]["code"] == expected_code


def test_framing_headers_accept_only_space_and_tab_ows() -> None:
    body = json.dumps(rule_call().model_dump(mode="json")).encode()
    fixed_request = raw_post_request(
        RULE_RETRIEVE_PATH,
        body,
        (f"\t{len(body)}\t",),
    )
    chunked_request = raw_post_request(
        RULE_RETRIEVE_PATH,
        encode_chunked_body((body,)),
        transfer_encoding_headers=("\tchunked\t",),
    )

    with running_service() as base_url:
        fixed_response = raw_exchange(base_url, fixed_request)
        chunked_response = raw_exchange(base_url, chunked_request)

    fixed_status, fixed_payload = parse_raw_response(fixed_response)
    chunked_status, chunked_payload = parse_raw_response(chunked_response)
    assert fixed_status == 200
    assert fixed_payload["status"] == "SUCCESS"
    assert chunked_status == 200
    assert chunked_payload["status"] == "SUCCESS"


@pytest.mark.parametrize(
    "malformed_body",
    [
        b"Z\r\n{}\r\n0\r\n\r\n",
        b"2\n{}\r\n0\r\n\r\n",
        b"2\r\n{}\n0\r\n\r\n",
        b"0\r\nMalformed-Trailer\r\n\r\n",
        b"0\r\nContent-Length: 0\r\n\r\n",
        b"F" * (MAX_CHUNK_LINE_BYTES + 1) + b"\r\n",
    ],
)
def test_malformed_chunk_framing_is_rejected(malformed_body: bytes) -> None:
    with running_service() as base_url:
        response = raw_exchange(
            base_url,
            raw_post_request(
                RULE_RETRIEVE_PATH,
                malformed_body,
                transfer_encoding_headers=("chunked",),
            ),
        )

    status, payload = parse_raw_response(response)
    assert status == 400
    assert payload["error"]["code"] == "INVALID_CHUNKED_BODY"


def test_chunked_body_rejects_premature_eof() -> None:
    with running_service() as base_url:
        response = raw_exchange(
            base_url,
            raw_post_request(
                RULE_RETRIEVE_PATH,
                b"5\r\n{}",
                transfer_encoding_headers=("chunked",),
            ),
            shutdown_write=True,
        )

    status, payload = parse_raw_response(response)
    assert status == 400
    assert payload["error"]["code"] == "INCOMPLETE_CHUNKED_BODY"


def test_chunked_body_and_trailer_limits_are_enforced() -> None:
    with running_service(max_body_bytes=8) as base_url:
        oversized_body_response = raw_exchange(
            base_url,
            raw_post_request(
                RULE_RETRIEVE_PATH,
                encode_chunked_body((b"123456789",)),
                transfer_encoding_headers=("chunked",),
            ),
        )
    oversized_trailer = b"0\r\nX-Fill: " + b"a" * MAX_CHUNK_TRAILER_BYTES + b"\r\n\r\n"
    with running_service() as base_url:
        oversized_trailer_response = raw_exchange(
            base_url,
            raw_post_request(
                RULE_RETRIEVE_PATH,
                oversized_trailer,
                transfer_encoding_headers=("chunked",),
            ),
        )

    body_status, body_payload = parse_raw_response(oversized_body_response)
    trailer_status, trailer_payload = parse_raw_response(oversized_trailer_response)
    assert body_status == 413
    assert body_payload["error"]["code"] == "REQUEST_TOO_LARGE"
    assert trailer_status == 413
    assert trailer_payload["error"]["code"] == "CHUNKED_TRAILERS_TOO_LARGE"


def test_deep_json_returns_400_instead_of_dropping_connection() -> None:
    body = b"[" * 80 + b"0" + b"]" * 80
    with running_service() as base_url:
        response = raw_exchange(
            base_url,
            raw_post_request(RULE_RETRIEVE_PATH, body, (str(len(body)),)),
        )

    status, payload = parse_raw_response(response)
    assert status == 400
    assert payload["error"]["code"] == "JSON_NESTING_TOO_DEEP"


@pytest.mark.parametrize(
    "body",
    [
        b'{"fixture_status":"SYNTHETIC","fixture_status":"SYNTHETIC"}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'{"value":' + b"1" * 5000 + b"}",
    ],
)
def test_non_standard_or_ambiguous_json_is_rejected(body: bytes) -> None:
    with running_service() as base_url:
        response = raw_exchange(
            base_url,
            raw_post_request(RULE_RETRIEVE_PATH, body, (str(len(body)),)),
        )

    status, payload = parse_raw_response(response)
    assert status == 400
    assert payload["error"]["code"] == "INVALID_JSON"


@pytest.mark.parametrize(
    "field",
    ["tenant_id", "case_id", "trace_id", "idempotency_key"],
)
def test_empty_context_identifiers_are_rejected_at_http_boundary(field: str) -> None:
    payload = rule_call().model_dump(mode="json")
    payload["context"][field] = "   "
    with running_service() as base_url:
        status, body = request_json(
            base_url,
            RULE_RETRIEVE_PATH,
            payload=payload,
            token=TOKEN,
        )

    assert status == 422
    assert body["error"]["code"] == "SCHEMA_VALIDATION_FAILED"


def test_expected_state_version_string_is_not_coerced() -> None:
    payload = rule_call().model_dump(mode="json")
    payload["context"]["expected_state_version"] = "0"
    with running_service() as base_url:
        status, body = request_json(
            base_url,
            RULE_RETRIEVE_PATH,
            payload=payload,
            token=TOKEN,
        )

    assert status == 422
    assert body["error"]["code"] == "SCHEMA_VALIDATION_FAILED"
    assert body["error"]["details"] == [
        {"location": ["context", "expected_state_version"], "type": "int_type"}
    ]


def test_rule_date_rejects_datetime_string_even_at_midnight() -> None:
    payload = rule_call().model_dump(mode="json")
    payload["arguments"]["as_of_date"] = "2026-08-20T00:00:00"
    with running_service() as base_url:
        status, body = request_json(
            base_url,
            RULE_RETRIEVE_PATH,
            payload=payload,
            token=TOKEN,
        )

    assert status == 422
    assert body["error"]["code"] == "SCHEMA_VALIDATION_FAILED"
    assert body["error"]["details"] == [
        {"location": ["arguments", "as_of_date"], "type": "date_parsing"}
    ]


def test_fixed_length_body_rejects_premature_eof() -> None:
    body = json.dumps(rule_call().model_dump(mode="json")).encode()
    with running_service() as base_url:
        response = raw_exchange(
            base_url,
            raw_post_request(RULE_RETRIEVE_PATH, body, (str(len(body) + 5),)),
            shutdown_write=True,
        )

    status, payload = parse_raw_response(response)
    assert status == 400
    assert payload["error"]["code"] == "INCOMPLETE_REQUEST_BODY"


@pytest.mark.parametrize(
    ("header", "expected_code"),
    [
        (f"Authorization: Bearer {TOKEN}\r\n", "AMBIGUOUS_AUTHORIZATION"),
        ("Content-Type: application/json\r\n", "AMBIGUOUS_CONTENT_TYPE"),
    ],
)
def test_duplicate_security_sensitive_headers_are_rejected(
    header: str,
    expected_code: str,
) -> None:
    body = json.dumps(rule_call().model_dump(mode="json")).encode()
    marker = header.encode("ascii")
    request = raw_post_request(RULE_RETRIEVE_PATH, body, (str(len(body)),))
    request = request.replace(marker, marker + marker, 1)
    with running_service() as base_url:
        response = raw_exchange(base_url, request)

    status, payload = parse_raw_response(response)
    assert status == 400
    assert payload["error"]["code"] == expected_code


def test_slow_request_body_hits_socket_read_deadline() -> None:
    body = b"{"
    with running_service(read_timeout_seconds=0.1) as base_url:
        response = raw_exchange(
            base_url,
            raw_post_request(RULE_RETRIEVE_PATH, body, ("100",)),
        )

    status, payload = parse_raw_response(response)
    assert status == 408
    assert payload["error"]["code"] == "REQUEST_TIMEOUT"


def test_slow_chunked_body_hits_aggregate_read_deadline() -> None:
    with running_service(read_timeout_seconds=0.1) as base_url:
        response = raw_exchange(
            base_url,
            raw_post_request(
                RULE_RETRIEVE_PATH,
                b"10\r\n{",
                transfer_encoding_headers=("chunked",),
            ),
        )

    status, payload = parse_raw_response(response)
    assert status == 408
    assert payload["error"]["code"] == "REQUEST_TIMEOUT"


@pytest.mark.parametrize(
    "initial_request",
    [
        b"P",
        b"POST /v1/tools/rule-retrieve HTTP/1.1\r\nHost: 127.0.0.1",
    ],
    ids=("request-line", "headers"),
)
def test_request_line_and_headers_share_one_aggregate_deadline(
    initial_request: bytes,
) -> None:
    with running_service(read_timeout_seconds=0.12) as base_url:
        parsed = urlsplit(base_url)
        assert parsed.hostname is not None and parsed.port is not None
        started = time.monotonic()
        with socket.create_connection((parsed.hostname, parsed.port), timeout=2) as connection:
            connection.settimeout(2)
            connection.sendall(initial_request)
            while time.monotonic() - started < 0.3:
                time.sleep(0.025)
                try:
                    connection.sendall(b"x")
                except OSError:
                    break
            response = bytearray()
            while True:
                try:
                    chunk = connection.recv(64 * 1024)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                response.extend(chunk)
        elapsed = time.monotonic() - started

    status, payload = parse_raw_response(bytes(response))
    assert status == 408
    assert payload["error"]["code"] == "REQUEST_TIMEOUT"
    assert elapsed < 0.8


def test_concurrency_limit_returns_bounded_503() -> None:
    body = json.dumps(rule_call().model_dump(mode="json")).encode("utf-8")
    with running_service(
        max_concurrent_requests=1,
        read_timeout_seconds=2,
    ) as base_url:
        parsed = urlsplit(base_url)
        assert parsed.hostname is not None and parsed.port is not None
        with socket.create_connection((parsed.hostname, parsed.port), timeout=2) as slow:
            slow.settimeout(2)
            request = raw_post_request(RULE_RETRIEVE_PATH, body, (str(len(body)),))
            header_end = request.index(b"\r\n\r\n") + 4
            slow.sendall(request[: header_end + 1])
            time.sleep(0.05)

            overloaded_status, overloaded_body = request_json(base_url, HEALTH_PATH)
            slow.sendall(request[header_end + 1 :])
            first_response = bytearray()
            while chunk := slow.recv(64 * 1024):
                first_response.extend(chunk)

    first_status, first_body = parse_raw_response(bytes(first_response))
    assert overloaded_status == 503
    assert overloaded_body["error"]["code"] == "SERVER_BUSY"
    assert first_status == 200
    assert first_body["status"] == "SUCCESS"


def test_response_size_limit_replaces_oversized_payload() -> None:
    with running_service(max_response_bytes=256) as base_url:
        status, body = request_json(
            base_url,
            RULE_RETRIEVE_PATH,
            payload=rule_call().model_dump(mode="json"),
            token=TOKEN,
        )

    assert status == 500
    assert body["error"]["code"] == "RESPONSE_TOO_LARGE"


def test_token_configuration_rejects_missing_or_ambiguous_values() -> None:
    assert api_token_from_environment({"PROOFFLOW_TOOL_API_TOKEN": TOKEN}) == TOKEN
    with pytest.raises(ToolServerConfigurationError):
        api_token_from_environment({})
    with pytest.raises(ToolServerConfigurationError):
        api_token_from_environment({"PROOFFLOW_TOOL_API_TOKEN": " has-spaces "})


def test_rule_catalog_requires_matching_public_digest_pin() -> None:
    expected = f"sha256:{sha256(RULES.read_bytes()).hexdigest()}"
    assert load_rule_catalog(RULES, expected).catalog_version == "2026-08-20"
    with pytest.raises(ToolServerConfigurationError, match="digest pin"):
        load_rule_catalog(RULES, "sha256:" + "0" * 64)
    with pytest.raises(ToolServerConfigurationError, match="lowercase"):
        load_rule_catalog(RULES, "not-a-digest")
