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
                    }
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
                "then": {"properties": {"allowed_approval_principals": {"minItems": 1}}},
            }
        )
        trust_policy["x-proofflow-runtime-invariants"] = [
            "roots[].root_id values are unique even when the remaining root fields differ"
        ]

    trust_root = _schema_node(schema, "TrustRoot")
    if trust_root is not None:
        for property_name in ("keyid_hints", "audiences", "predicate_types"):
            _require_unique_array(trust_root, property_name)
        root_properties = _properties(trust_root)
        root_properties["public_key_b64"]["pattern"] = r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$"
        keyid_item = root_properties["keyid_hints"].get("items")
        if not isinstance(keyid_item, dict):
            raise ValueError("TrustRoot.keyid_hints must have an item schema")
        _forbid_remote_reference(keyid_item)
        keyid_item["maxLength"] = 128
        trust_root["x-proofflow-runtime-invariants"] = [
            "not_after is later than not_before",
            "revoked_at, when present, is evaluated against the operator verification time",
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


def render(model: type[BaseModel]) -> str:
    schema = _patch_action_certificate_schema(model.model_json_schema())
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
