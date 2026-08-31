#!/usr/bin/env python3
"""Export deterministic JSON Schemas for the public ProofFlow contracts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from proofflow.action_certificate import (
    MAX_ENVELOPE_BYTES,
    MAX_PAYLOAD_BYTES,
    REJECT_VERIFICATION_REASONS,
    UNKNOWN_VERIFICATION_REASONS,
    UTC_RFC3339_Z_PATTERN,
    ActionCertificatePredicate,
    ActionCertificateStatement,
    ActionCertificateVerificationResult,
    ApprovalRevocationSnapshot,
    DsseEnvelope,
    ExpectedBinding,
    TrustPolicy,
)
from proofflow.contracts import (
    CalculateOutput,
    DeterministicCalculateToolCall,
    EvidenceIngestOutput,
    EvidenceIngestToolCall,
    RuleRetrieveOutput,
    RuleRetrieveToolCall,
)
from proofflow.execution_receipt import (
    REJECT_RECEIPT_REASONS,
    UNKNOWN_RECEIPT_REASONS,
    ExecutionReceiptPredicate,
    ExecutionReceiptStatement,
    ExecutionReceiptVerificationResult,
    ExpectedExecutionBinding,
)
from proofflow.models import (
    ApprovalRecord,
    ApprovalRequest,
    AuditReport,
    CalculationSheet,
    CaseRecord,
    ConflictReport,
    EvidenceObject,
    HumanDecision,
    PackageManifest,
    Proposal,
    RuleCitation,
    SkillContext,
    SkillResult,
    TimelineEvent,
    TraceEvent,
)
from proofflow.outcome_closure import (
    FAIL_OUTCOME_REASONS,
    PASS_OUTCOME_REASONS,
    UNKNOWN_OUTCOME_REASONS,
    UNSAFE_OUTCOME_REASONS,
    ExpectedOutcomeBinding,
    OutcomeClosurePredicate,
    OutcomeClosureStatement,
    OutcomeClosureVerificationReason,
    OutcomeClosureVerificationResult,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "schemas"
MODELS: dict[str, type[BaseModel]] = {
    "action-certificate-dsse-envelope": DsseEnvelope,
    "action-certificate-expected-binding": ExpectedBinding,
    "action-certificate-predicate-v0p1": ActionCertificatePredicate,
    "action-certificate-revocation-snapshot": ApprovalRevocationSnapshot,
    "action-certificate-statement-v0p1": ActionCertificateStatement,
    "action-certificate-trust-policy-v0p1": TrustPolicy,
    "action-certificate-verification-result-v0p1": ActionCertificateVerificationResult,
    "execution-receipt-expected-binding-v0p1": ExpectedExecutionBinding,
    "execution-receipt-predicate-v0p1": ExecutionReceiptPredicate,
    "execution-receipt-statement-v0p1": ExecutionReceiptStatement,
    "execution-receipt-verification-result-v0p1": ExecutionReceiptVerificationResult,
    "outcome-closure-expected-binding-v0p1": ExpectedOutcomeBinding,
    "outcome-closure-predicate-v0p1": OutcomeClosurePredicate,
    "outcome-closure-statement-v0p1": OutcomeClosureStatement,
    "outcome-closure-verification-result-v0p1": OutcomeClosureVerificationResult,
    "approval-record": ApprovalRecord,
    "approval-request": ApprovalRequest,
    "audit-report": AuditReport,
    "calculation-sheet": CalculationSheet,
    "case-record": CaseRecord,
    "conflict-report": ConflictReport,
    "evidence-object": EvidenceObject,
    "human-decision": HumanDecision,
    "package-manifest": PackageManifest,
    "proposal": Proposal,
    "rule-citation": RuleCitation,
    "skill-context": SkillContext,
    "skill-result": SkillResult[dict[str, Any]],
    "timeline-event": TimelineEvent,
    "trace-event": TraceEvent,
    "tool-deterministic-calculate-call": DeterministicCalculateToolCall,
    "tool-deterministic-calculate-result": SkillResult[CalculateOutput],
    "tool-evidence-ingest-call": EvidenceIngestToolCall,
    "tool-evidence-ingest-result": SkillResult[EvidenceIngestOutput],
    "tool-rule-retrieve-call": RuleRetrieveToolCall,
    "tool-rule-retrieve-result": SkillResult[RuleRetrieveOutput],
}

CANONICAL_DSSE_BASE64_PATTERN = (
    r"^(?:[A-Za-z0-9+/_-]{4})*(?:[A-Za-z0-9+/_-][AQgw]==|"
    r"[A-Za-z0-9+/_-]{2}[AEIMQUYcgkosw048]=)?$"
)
REMOTE_REFERENCE_SHAPES: tuple[dict[str, str], ...] = (
    {"pattern": "://"},
    {"pattern": "^[Ff][Ii][Ll][Ee]:"},
    {"pattern": "^[Dd][Aa][Tt][Aa]:"},
    {"pattern": "^[Uu][Rr][Nn]:"},
)


def _schema_node(schema: dict[str, Any], title: str) -> dict[str, Any] | None:
    if schema.get("title") == title:
        return schema
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict):
        return None
    node = definitions.get(title)
    return node if isinstance(node, dict) else None


def _properties(node: dict[str, Any]) -> dict[str, Any]:
    properties = node.get("properties")
    if not isinstance(properties, dict):
        raise ValueError(f"schema node has no properties: {node.get('title', '<unknown>')}")
    return properties


def _require_unique_array(node: dict[str, Any], property_name: str) -> None:
    property_schema = _properties(node).get(property_name)
    if not isinstance(property_schema, dict) or property_schema.get("type") != "array":
        raise ValueError(f"expected array schema: {node.get('title')}.{property_name}")
    property_schema["uniqueItems"] = True


def _forbid_remote_reference(property_schema: dict[str, Any]) -> None:
    property_schema.setdefault("allOf", []).append(
        {"not": {"anyOf": list(REMOTE_REFERENCE_SHAPES)}}
    )


def _patch_approval_binding(node: dict[str, Any]) -> None:
    _require_unique_array(node, "approver_principals")
    approver_items = _properties(node)["approver_principals"].get("items")
    if not isinstance(approver_items, dict):
        raise ValueError("ApprovalBinding.approver_principals must have an item schema")
    approver_items.update({"minLength": 1, "maxLength": 128})
    node.setdefault("allOf", []).append(
        {
            "if": {
                "properties": {"required": {"const": True}},
                "required": ["required"],
            },
            "then": {
                "required": [
                    "approval_id",
                    "scope_sha256",
                    "approver_principals",
                    "expires_at",
                ],
                "properties": {
                    "approval_id": {"not": {"type": "null"}},
                    "scope_sha256": {"not": {"type": "null"}},
                    "approver_principals": {"minItems": 1},
                    "expires_at": {"not": {"type": "null"}},
                },
            },
            "else": {
                "properties": {
                    "approval_id": {"type": "null"},
                    "scope_sha256": {"type": "null"},
                    "approver_principals": {"maxItems": 0},
                    "expires_at": {"type": "null"},
                }
            },
        }
    )


def _patch_verification_result(node: dict[str, Any]) -> None:
    _require_unique_array(node, "reason_codes")
    reject_reasons = sorted(reason.value for reason in REJECT_VERIFICATION_REASONS)
    unknown_reasons = sorted(reason.value for reason in UNKNOWN_VERIFICATION_REASONS)
    branches = (
        ("ACCEPT", {"const": True}, {"const": ["ACCEPTED"]}),
        ("REJECT", {"const": False}, {"items": {"enum": reject_reasons}}),
        ("UNKNOWN", {"const": False}, {"items": {"enum": unknown_reasons}}),
    )
    all_of = node.setdefault("allOf", [])
    for status, reserved, reason_codes in branches:
        all_of.append(
            {
                "if": {
                    "properties": {"status": {"const": status}},
                    "required": ["status"],
                },
                "then": {
                    "properties": {
                        "reserved": reserved,
                        "reason_codes": reason_codes,
                    },
                },
            }
        )


def _patch_action_certificate_schema(schema: dict[str, Any]) -> dict[str, Any]:
    approval = _schema_node(schema, "ApprovalBinding")
    if approval is not None:
        _patch_approval_binding(approval)

    result = _schema_node(schema, "ActionCertificateVerificationResult")
    if result is not None:
        _patch_verification_result(result)

    trust_policy = _schema_node(schema, "TrustPolicy")
    if trust_policy is not None:
        for property_name in (
            "allowed_tenants",
            "allowed_human_principals",
            "allowed_workload_principals",
            "allowed_action_issuer_principals",
            "allowed_approval_principals",
            "allowed_execution_observer_principals",
            "allowed_outcome_observer_principals",
            "allowed_outcome_evidence_source_kinds",
            "allowed_outcome_evidence_source_principals",
            "allowed_audiences",
            "allowed_predicate_types",
            "roots",
        ):
            _require_unique_array(trust_policy, property_name)
        trust_policy.setdefault("allOf", []).append(
            {
                "if": {
                    "properties": {"approval_required": {"const": True}},
                    "required": ["approval_required"],
                },
                "then": {
                    "required": ["allowed_approval_principals"],
                    "properties": {"allowed_approval_principals": {"minItems": 1}},
                },
            }
        )
        trust_policy["x-proofflow-runtime-invariants"] = [
            "roots[].root_id values are unique even when the remaining root fields differ"
        ]

    trust_root = _schema_node(schema, "TrustRoot")
    if trust_root is not None:
        for property_name in (
            "keyid_hints",
            "audiences",
            "predicate_types",
            "execution_observer_scopes",
            "outcome_observer_scopes",
            "outcome_evidence_source_kinds",
            "outcome_evidence_source_principals",
        ):
            _require_unique_array(trust_root, property_name)
        root_properties = _properties(trust_root)
        root_properties["public_key_b64"]["pattern"] = r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$"
        keyid_item = root_properties["keyid_hints"].get("items")
        if not isinstance(keyid_item, dict):
            raise ValueError("TrustRoot.keyid_hints must have an item schema")
        _forbid_remote_reference(keyid_item)
        keyid_item["maxLength"] = 128
        source_principal_items = root_properties["outcome_evidence_source_principals"].get("items")
        if not isinstance(source_principal_items, dict):
            raise ValueError("TrustRoot.outcome_evidence_source_principals needs item schema")
        source_principal_items["pattern"] = r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$"
        trust_root.setdefault("allOf", []).append(
            {
                "if": {
                    "properties": {"purpose": {"const": "EXECUTION_OBSERVER"}},
                    "required": ["purpose"],
                },
                "then": {
                    "required": ["execution_observer_scopes"],
                    "properties": {"execution_observer_scopes": {"minItems": 7}},
                },
                "else": {"properties": {"execution_observer_scopes": {"maxItems": 0}}},
            }
        )
        trust_root.setdefault("allOf", []).append(
            {
                "if": {
                    "properties": {"purpose": {"const": "OUTCOME_OBSERVER"}},
                    "required": ["purpose"],
                },
                "then": {
                    "required": ["outcome_observer_scopes"],
                    "properties": {"outcome_observer_scopes": {"minItems": 4}},
                },
                "else": {"properties": {"outcome_observer_scopes": {"maxItems": 0}}},
            }
        )
        trust_root.setdefault("allOf", []).append(
            {
                "if": {
                    "properties": {"purpose": {"const": "OUTCOME_OBSERVER"}},
                    "required": ["purpose"],
                },
                "then": {
                    "required": [
                        "outcome_evidence_source_kinds",
                        "outcome_evidence_source_principals",
                    ],
                    "properties": {
                        "outcome_evidence_source_kinds": {"minItems": 1},
                        "outcome_evidence_source_principals": {"minItems": 1},
                    },
                },
                "else": {
                    "properties": {
                        "outcome_evidence_source_kinds": {"maxItems": 0},
                        "outcome_evidence_source_principals": {"maxItems": 0},
                    }
                },
            }
        )
        trust_root["x-proofflow-runtime-invariants"] = [
            "not_after is later than not_before",
            "revoked_at, when present, is evaluated against the operator verification time",
            "EXECUTION_OBSERVER roots contain all seven v0.1 observer scopes",
            "OUTCOME_OBSERVER roots contain all four v0.1 outcome observer scopes",
        ]

    signature = _schema_node(schema, "DsseSignature")
    if signature is not None:
        signature_properties = _properties(signature)
        signature_properties["sig"]["pattern"] = r"^[A-Za-z0-9+/_-]{85}[AQgw]==$"
        _forbid_remote_reference(signature_properties["keyid"])

    envelope = _schema_node(schema, "DsseEnvelope")
    if envelope is not None:
        payload_schema = _properties(envelope)["payload"]
        payload_schema["pattern"] = CANONICAL_DSSE_BASE64_PATTERN
        maximum_encoded_payload = ((MAX_PAYLOAD_BYTES + 2) // 3) * 4
        payload_schema.setdefault("allOf", []).append(
            {
                "anyOf": [
                    {"maxLength": maximum_encoded_payload - 4},
                    {
                        "minLength": maximum_encoded_payload,
                        "maxLength": maximum_encoded_payload,
                        "pattern": "=$",
                    },
                ]
            }
        )
        envelope["x-proofflow-runtime-invariants"] = [
            f"the raw UTF-8 JSON envelope is at most {MAX_ENVELOPE_BYTES} bytes"
        ]

    in_toto_subject = _schema_node(schema, "InTotoSubject")
    if in_toto_subject is not None:
        _forbid_remote_reference(_properties(in_toto_subject)["name"])

    delegation_hop = _schema_node(schema, "DelegationHop")
    if delegation_hop is not None:
        delegation_hop["x-proofflow-runtime-invariants"] = ["delegator and delegatee differ"]

    policy_binding = _schema_node(schema, "PolicyBinding")
    if policy_binding is not None:
        policy_binding["x-proofflow-runtime-invariants"] = ["expires_at is later than evaluated_at"]

    predicate = _schema_node(schema, "ActionCertificatePredicate")
    if predicate is not None:
        _require_unique_array(predicate, "delegation_chain")
        predicate["x-proofflow-runtime-invariants"] = [
            "issued_at <= not_before < expires_at",
            "policy.evaluated_at <= issued_at and policy.expires_at >= expires_at",
            "approval.expires_at, when present, is >= expires_at",
            (
                "delegation_chain begins at human_principal, is contiguous, and ends at "
                "workload_principal"
            ),
            "distinct human/workload principals require a non-empty delegation_chain",
        ]

    statement = _schema_node(schema, "ActionCertificateStatement")
    if statement is not None:
        _require_unique_array(statement, "subject")
        statement["x-proofflow-runtime-invariants"] = [
            "subject[].name values are unique even when digests differ"
        ]

    revocations = _schema_node(schema, "ApprovalRevocationSnapshot")
    if revocations is not None:
        _require_unique_array(revocations, "entries")
        revocation_properties = _properties(revocations)
        revocation_properties["as_of"]["pattern"] = UTC_RFC3339_Z_PATTERN
        revocation_properties["valid_until"]["pattern"] = UTC_RFC3339_Z_PATTERN
        revocations["x-proofflow-runtime-invariants"] = [
            "valid_until is greater than or equal to as_of",
            (
                "the resolver is current only when as_of <= verification_time <= valid_until; "
                "both boundaries are inclusive"
            ),
            "(tenant_id, approval_id) pairs are unique even when scope or status differs",
        ]
    return schema


def _require_null_when_unknown_and_values_when_observed(
    node: dict[str, Any],
    *,
    status_property: str,
    value_properties: tuple[str, ...],
) -> None:
    node.setdefault("allOf", []).extend(
        (
            {
                "if": {
                    "properties": {status_property: {"const": "UNKNOWN"}},
                    "required": [status_property],
                },
                "then": {
                    "required": list(value_properties),
                    "properties": {
                        property_name: {"type": "null"} for property_name in value_properties
                    },
                },
            },
            {
                "if": {
                    "properties": {status_property: {"const": "OBSERVED"}},
                    "required": [status_property],
                },
                "then": {
                    "required": list(value_properties),
                    "properties": {
                        property_name: {"not": {"type": "null"}}
                        for property_name in value_properties
                    },
                },
            },
        )
    )


def _patch_execution_receipt_schema(schema: dict[str, Any]) -> dict[str, Any]:
    producer = _schema_node(schema, "ProducerDeclaration")
    if producer is not None:
        _require_unique_array(producer, "observer_principals")
        observer_items = _properties(producer)["observer_principals"].get("items")
        if not isinstance(observer_items, dict):
            raise ValueError("ProducerDeclaration.observer_principals must have an item schema")
        observer_items.update({"pattern": r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$"})

    trace = _schema_node(schema, "TraceObservation")
    if trace is not None:
        _require_unique_array(trace, "linked_span_ids")
        trace_properties = _properties(trace)
        trace_properties["trace_id"].setdefault("allOf", []).append({"not": {"const": "0" * 32}})
        for property_name in ("span_id", "parent_span_id"):
            trace_properties[property_name].setdefault("allOf", []).append(
                {"not": {"const": "0" * 16}}
            )
        linked_items = trace_properties["linked_span_ids"].get("items")
        if not isinstance(linked_items, dict):
            raise ValueError("TraceObservation.linked_span_ids needs item schema")
        linked_items.setdefault("allOf", []).append({"not": {"const": "0" * 16}})
        trace["x-proofflow-runtime-invariants"] = [
            "parent_span_id and linked_span_ids never equal span_id"
        ]

    for title, observation_fields in (
        (
            "TokenUsageObservation",
            ("input_tokens", "output_tokens", "total_tokens", "observer_evidence_sha256"),
        ),
        (
            "EffectObservation",
            (
                "provider_result",
                "provider_operation_id",
                "outbox_entry_sha256",
                "inbox_entry_sha256",
                "provider_request_sha256",
                "provider_response_sha256",
                "before_state_sha256",
                "after_state_sha256",
                "provider_event_sha256",
                "observer_evidence_sha256",
            ),
        ),
        (
            "CostObservation",
            (
                "currency",
                "amount_decimal",
                "rate_card_sha256",
                "observer_evidence_sha256",
            ),
        ),
        (
            "DurationObservation",
            (
                "milliseconds",
                "clock",
                "precision_milliseconds",
                "observer_evidence_sha256",
            ),
        ),
    ):
        node = _schema_node(schema, title)
        if node is not None:
            _require_null_when_unknown_and_values_when_observed(
                node,
                status_property="status",
                value_properties=observation_fields,
            )

    usage = _schema_node(schema, "TokenUsageObservation")
    if usage is not None:
        usage["x-proofflow-runtime-invariants"] = [
            "for OBSERVED usage, total_tokens equals input_tokens plus output_tokens"
        ]

    invocation = _schema_node(schema, "ModelInvocationObservation")
    if invocation is not None:
        _require_null_when_unknown_and_values_when_observed(
            invocation,
            status_property="inference_status",
            value_properties=(
                "request_sha256",
                "response_sha256",
                "inference_observer_evidence_sha256",
            ),
        )

    attempt = _schema_node(schema, "AttemptObservation")
    if attempt is not None:
        attempt_properties = _properties(attempt)
        attempt_properties["started_at"]["pattern"] = UTC_RFC3339_Z_PATTERN
        attempt_properties["ended_at"]["pattern"] = UTC_RFC3339_Z_PATTERN
        attempt["x-proofflow-runtime-invariants"] = [
            "ended_at is greater than or equal to started_at"
        ]

    certificate_reference = _schema_node(schema, "ActionCertificateReference")
    if certificate_reference is not None:
        reference_properties = _properties(certificate_reference)
        reference_properties["verification_at"]["pattern"] = UTC_RFC3339_Z_PATTERN
        reference_properties["reserved_at"]["pattern"] = UTC_RFC3339_Z_PATTERN
        certificate_reference["x-proofflow-runtime-invariants"] = [
            "reserved_at is greater than or equal to verification_at"
        ]

    predicate = _schema_node(schema, "ExecutionReceiptPredicate")
    if predicate is not None:
        for property_name in ("inputs", "outputs", "provenance"):
            _require_unique_array(predicate, property_name)
        _properties(predicate)["issued_at"]["pattern"] = UTC_RFC3339_Z_PATTERN
        predicate["x-proofflow-runtime-invariants"] = [
            "input artifact IDs and output artifact IDs are unique and disjoint",
            "COMPLETED attempts have at least one output artifact",
            "issued_at is greater than or equal to attempt.ended_at",
            "certificate_ref.intent_sha256 equals effect.intent_sha256",
            "protocol and operation request/response digests match",
            "LOCAL handler_name and MCP tool_name match operation.name",
            "A2A protocol task_id matches the receipt task_id",
            "an OBSERVED provider request digest matches operation.request_sha256",
        ]

    statement = _schema_node(schema, "ExecutionReceiptStatement")
    if statement is not None:
        _require_unique_array(statement, "subject")
        statement["x-proofflow-runtime-invariants"] = [
            "in-toto subjects exactly match predicate output artifact IDs and SHA-256 digests"
        ]

    expected = _schema_node(schema, "ExpectedExecutionBinding")
    if expected is not None:
        for property_name in (
            "inputs",
            "outputs",
            "executor_workload_key_fingerprints",
            "human_principal_key_fingerprints",
        ):
            _require_unique_array(expected, property_name)
        expected_properties = _properties(expected)
        for property_name in (
            "executor_workload_key_fingerprints",
            "human_principal_key_fingerprints",
        ):
            fingerprint_items = expected_properties[property_name].get("items")
            if not isinstance(fingerprint_items, dict):
                raise ValueError(f"ExpectedExecutionBinding.{property_name} needs item schema")
            fingerprint_items["pattern"] = r"^sha256:[0-9a-f]{64}$"
        expected["x-proofflow-runtime-invariants"] = [
            "input and output artifact IDs are unique within each direction and disjoint"
        ]

    result = _schema_node(schema, "ExecutionReceiptVerificationResult")
    if result is not None:
        _require_unique_array(result, "reason_codes")
        _require_unique_array(result, "verified_execution_observer_roots")
        accept_reasons = ["ALREADY_PRESENT", "APPENDED"]
        reject_reasons = sorted(reason.value for reason in REJECT_RECEIPT_REASONS)
        unknown_reasons = sorted(reason.value for reason in UNKNOWN_RECEIPT_REASONS)
        unknown_observation_properties = {
            property_name: {"const": "UNKNOWN"}
            for property_name in (
                "inference_status",
                "usage_status",
                "effect_status",
                "cost_status",
                "duration_status",
            )
        }
        for status, recorded, reasons, extra_required, extra_properties in (
            (
                "ACCEPT",
                {"const": True},
                {"enum": [[value] for value in accept_reasons]},
                ["receipt_id", "payload_sha256", "verified_execution_observer_roots"],
                {
                    "receipt_id": {"not": {"type": "null"}},
                    "payload_sha256": {"not": {"type": "null"}},
                    "verified_execution_observer_roots": {"minItems": 1},
                },
            ),
            (
                "REJECT",
                {"const": False},
                {"items": {"enum": reject_reasons}},
                [],
                unknown_observation_properties,
            ),
            (
                "UNKNOWN",
                {"const": False},
                {"items": {"enum": unknown_reasons}},
                [],
                unknown_observation_properties,
            ),
        ):
            result.setdefault("allOf", []).append(
                {
                    "if": {
                        "properties": {"status": {"const": status}},
                        "required": ["status"],
                    },
                    "then": {
                        "required": extra_required,
                        "properties": {
                            "recorded": recorded,
                            "reason_codes": reasons,
                            **extra_properties,
                        },
                    },
                }
            )

    for title, reference_fields in (
        ("ProducerDeclaration", ("software_name", "software_version")),
        ("RuntimeObservation", ("runtime_name", "runtime_version")),
        ("LocalProtocolObservation", ("handler_name",)),
        ("McpProtocolObservation", ("server_name", "tool_name")),
        ("A2aProtocolObservation", ("agent_name",)),
        ("ToolOperationObservation", ("name", "version")),
        ("SkillOperationObservation", ("name", "version")),
        ("ModelInvocationObservation", ("provider", "model", "model_revision")),
        ("EffectObservation", ("effect_type", "target")),
        ("ExpectedExecutionBinding", ("effect_type", "effect_target")),
        ("ProvenanceReference", ("name", "media_type")),
        ("ArtifactObservation", ("media_type",)),
    ):
        node = _schema_node(schema, title)
        if node is not None:
            properties = _properties(node)
            for field_name in reference_fields:
                _forbid_remote_reference(properties[field_name])
    return schema


def _patch_outcome_closure_schema(schema: dict[str, Any]) -> dict[str, Any]:
    producer = _schema_node(schema, "OutcomeProducerDeclaration")
    if producer is not None:
        _require_unique_array(producer, "observer_principals")
        observer_items = _properties(producer)["observer_principals"].get("items")
        if not isinstance(observer_items, dict):
            raise ValueError("OutcomeProducerDeclaration.observer_principals needs item schema")
        observer_items["pattern"] = r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$"
        producer["x-proofflow-runtime-invariants"] = [
            "observer principals are unique and must match qualifying OUTCOME_OBSERVER roots"
        ]

    source = _schema_node(schema, "OutcomeEvidenceSource")
    if source is not None:
        source_properties = _properties(source)
        source_properties["observed_at"]["pattern"] = UTC_RFC3339_Z_PATTERN
        source_properties["valid_until"]["pattern"] = UTC_RFC3339_Z_PATTERN
        source["x-proofflow-runtime-invariants"] = [
            "observed_at is no later than valid_until",
            "source_event_sha256 resolves to exact bytes from the operator-controlled resolver",
        ]

    unresolved = _schema_node(schema, "UnresolvedEffectObservation")
    if unresolved is not None:
        unresolved.setdefault("allOf", []).extend(
            (
                {
                    "if": {
                        "properties": {"reason": {"const": "MISSING_EVIDENCE"}},
                        "required": ["reason"],
                    },
                    "then": {
                        "required": ["observer_evidence_sha256"],
                        "properties": {"observer_evidence_sha256": {"type": "null"}},
                    },
                },
                {
                    "if": {
                        "properties": {
                            "reason": {
                                "enum": [
                                    "QUERY_UNAVAILABLE",
                                    "PENDING",
                                    "CONFLICT",
                                ]
                            }
                        },
                        "required": ["reason"],
                    },
                    "then": {
                        "required": ["observer_evidence_sha256"],
                        "properties": {"observer_evidence_sha256": {"not": {"type": "null"}}},
                    },
                },
            )
        )
        unresolved["x-proofflow-runtime-invariants"] = [
            "MISSING_EVIDENCE must carry null observer_evidence_sha256",
            "QUERY_UNAVAILABLE, PENDING, and CONFLICT require observer evidence",
        ]

    reconciliation = _schema_node(schema, "EffectReconciliation")
    if reconciliation is not None:
        _require_unique_array(reconciliation, "attempts")
        _require_unique_array(reconciliation, "unresolved")
        reconciliation["x-proofflow-runtime-invariants"] = [
            "attempt IDs and effect IDs are unique",
            "resolved and unresolved effect IDs are disjoint",
            (
                "every attempt binds the reconciliation effect type, target, intent, and "
                "idempotency key"
            ),
            "unresolved count does not exceed expected_effect_count",
            "provider operation IDs are unique",
        ]

    attempt = _schema_node(schema, "EffectAttemptObservation")
    if attempt is not None:
        attempt.setdefault("allOf", []).extend(
            (
                {
                    "if": {
                        "properties": {"status": {"const": "SUCCEEDED"}},
                        "required": ["status"],
                    },
                    "then": {
                        "required": ["provider_operation_id"],
                        "properties": {
                            "provider_operation_id": {"not": {"type": "null"}},
                            "terminal_result": {"const": "EFFECT_COMMITTED"},
                        },
                    },
                },
                {
                    "if": {
                        "properties": {"status": {"const": "FAILED"}},
                        "required": ["status"],
                    },
                    "then": {
                        "properties": {
                            "terminal_result": {"enum": ["EFFECT_REJECTED", "EFFECT_NOT_APPLIED"]}
                        }
                    },
                },
            )
        )
        attempt["x-proofflow-runtime-invariants"] = [
            "SUCCEEDED requires a provider operation ID and EFFECT_COMMITTED",
            "FAILED requires an authoritative rejection or no-effect terminal result",
        ]

    statement = _schema_node(schema, "OutcomeClosureStatement")
    if statement is not None:
        _require_unique_array(statement, "subject")
        statement["x-proofflow-runtime-invariants"] = [
            "OutcomeClosure subjects are unique; business-state semantics remain verifier-derived"
        ]

    expected = _schema_node(schema, "ExpectedOutcomeBinding")
    if expected is not None:
        for property_name in (
            "human_principal_key_fingerprints",
            "executor_workload_key_fingerprints",
        ):
            _require_unique_array(expected, property_name)
            items = _properties(expected)[property_name].get("items")
            if not isinstance(items, dict):
                raise ValueError(f"{property_name} needs item schema")
            items["pattern"] = r"^sha256:[0-9a-f]{64}$"
        expected["x-proofflow-runtime-invariants"] = [
            "the binding is operator-controlled and must not be derived from the signed closure"
        ]

    predicate = _schema_node(schema, "OutcomeClosurePredicate")
    if predicate is not None:
        predicate_properties = _properties(predicate)
        predicate_properties["issued_at"]["pattern"] = UTC_RFC3339_Z_PATTERN
        predicate["x-proofflow-runtime-invariants"] = [
            (
                "claimed_outcome is informational; PASS/FAIL/UNKNOWN/UNSAFE_SUCCESS is "
                "verifier-derived"
            ),
            "certificate_ref and receipt_ref must bind exact external accepted inputs",
        ]

    result = _schema_node(schema, "OutcomeClosureVerificationResult")
    if result is not None:
        _require_unique_array(result, "reason_codes")
        _require_unique_array(result, "verified_outcome_observer_roots")
        reason_values = sorted(reason.value for reason in OutcomeClosureVerificationReason)
        pass_reasons = sorted(reason.value for reason in PASS_OUTCOME_REASONS)
        fail_reasons = sorted(reason.value for reason in FAIL_OUTCOME_REASONS)
        unknown_reasons = sorted(reason.value for reason in UNKNOWN_OUTCOME_REASONS)
        unsafe_reasons = sorted(reason.value for reason in UNSAFE_OUTCOME_REASONS)
        properties = _properties(result)
        properties["reason_codes"]["items"] = {"enum": reason_values}
        result.setdefault("allOf", []).extend(
            (
                {
                    "if": {
                        "properties": {"status": {"const": "PASS"}},
                        "required": ["status"],
                    },
                    "then": {
                        "properties": {
                            "recorded": {"const": True},
                            "reason_codes": {"enum": [[reason] for reason in pass_reasons]},
                            "closure_id": {"not": {"type": "null"}},
                            "payload_sha256": {"not": {"type": "null"}},
                            "verified_outcome_observer_roots": {"minItems": 1},
                        },
                        "required": [
                            "closure_id",
                            "payload_sha256",
                            "verified_outcome_observer_roots",
                            "expected_effect_count",
                            "observed_success_count",
                            "unresolved_effect_count",
                            "attempt_id",
                            "closure_sequence",
                        ],
                    },
                },
                {
                    "if": {
                        "properties": {"status": {"const": "FAIL"}},
                        "required": ["status"],
                    },
                    "then": {
                        "properties": {
                            "recorded": {"const": True},
                            "reason_codes": {"enum": [[reason] for reason in fail_reasons]},
                            "closure_id": {"not": {"type": "null"}},
                            "payload_sha256": {"not": {"type": "null"}},
                            "verified_outcome_observer_roots": {"minItems": 1},
                        },
                        "required": [
                            "closure_id",
                            "payload_sha256",
                            "verified_outcome_observer_roots",
                            "expected_effect_count",
                            "observed_success_count",
                            "unresolved_effect_count",
                            "attempt_id",
                            "closure_sequence",
                        ],
                    },
                },
                {
                    "if": {
                        "properties": {"status": {"const": "UNKNOWN"}},
                        "required": ["status"],
                    },
                    "then": {
                        "properties": {
                            "recorded": {"const": False},
                            "reason_codes": {"items": {"enum": unknown_reasons}},
                        }
                    },
                },
                {
                    "if": {
                        "properties": {"status": {"const": "UNSAFE_SUCCESS"}},
                        "required": ["status"],
                    },
                    "then": {
                        "properties": {
                            "recorded": {"const": False},
                            "reason_codes": {"items": {"enum": unsafe_reasons}},
                        }
                    },
                },
            )
        )
        result["x-proofflow-runtime-invariants"] = [
            (
                "PASS is only emitted for a recorded exact-byte closure with expected "
                "successes and no unresolved effects"
            ),
            (
                "UNSAFE_SUCCESS is never recorded and signals success-like output without "
                "complete trusted closure evidence"
            ),
        ]
    for title, reference_fields in (
        ("OutcomeProducerDeclaration", ("software_name", "software_version")),
        ("EffectAttemptObservation", ("effect_type", "target")),
        ("EffectReconciliation", ("effect_type", "target")),
        ("ExpectedOutcomeBinding", ("effect_type", "effect_target")),
    ):
        node = _schema_node(schema, title)
        if node is not None:
            properties = _properties(node)
            for field_name in reference_fields:
                _forbid_remote_reference(properties[field_name])
    return schema


def render(model: type[BaseModel]) -> str:
    schema = _patch_action_certificate_schema(model.model_json_schema())
    schema = _patch_execution_receipt_schema(schema)
    schema = _patch_outcome_closure_schema(schema)
    return json.dumps(schema, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    errors: list[str] = []
    if not args.check:
        OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, model in MODELS.items():
        path = OUTPUT / f"{name}.schema.json"
        expected = render(model)
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                errors.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(expected, encoding="utf-8")
    if errors:
        print("stale or missing schemas: " + ", ".join(errors))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
