from __future__ import annotations

import base64
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel, ValidationError

from proofflow.action_certificate import (
    ACTION_CERTIFICATE_PREDICATE_TYPE,
    DSSE_PAYLOAD_TYPE,
    MAX_ENVELOPE_BYTES,
    REJECT_VERIFICATION_REASONS,
    UNKNOWN_VERIFICATION_REASONS,
    ActionBinding,
    ActionCertificatePredicate,
    ActionCertificateStatement,
    ActionCertificateVerificationResult,
    ApprovalBinding,
    ApprovalRevocationEntry,
    ApprovalRevocationSnapshot,
    ApprovalRevocationStatus,
    ContextBinding,
    DelegationHop,
    DsseEnvelope,
    DsseSignature,
    EffectBinding,
    ExpectedBinding,
    InMemoryReplayLedger,
    InTotoSubject,
    PolicyBinding,
    PrincipalBinding,
    ResourceBinding,
    Sha256DigestSet,
    SnapshotApprovalRevocationResolver,
    SubjectBinding,
    TrustPolicy,
    TrustPurpose,
    TrustRoot,
    VerificationReason,
    VerificationStatus,
    approval_scope_sha256,
    dsse_pae,
    expected_binding_for,
    parse_utc_rfc3339_z,
    verify_action_certificate,
)
from proofflow.cli import _parse_verification_time

NOW = datetime(2026, 8, 29, 4, 0, tzinfo=UTC)
ROOT = Path(__file__).parents[2]
ZERO_HASH = "sha256:" + "0" * 64
ONE_HASH = "sha256:" + "1" * 64
TWO_HASH = "sha256:" + "2" * 64


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(private_key.public_key().public_bytes_raw()).decode("ascii")


def statement(*, approval_required: bool = True) -> ActionCertificateStatement:
    approval = ApprovalBinding(
        required=approval_required,
        approval_id="approval-001" if approval_required else None,
        scope_sha256=ZERO_HASH if approval_required else None,
        approver_principals=("reviewer-001",) if approval_required else (),
        expires_at=NOW + timedelta(minutes=20) if approval_required else None,
    )
    predicate = ActionCertificatePredicate(
        version="0.1",
        certificate_id="certificate-001",
        tenant_id="tenant-synthetic",
        human_principal=PrincipalBinding(
            principal_id="requestor-001", identity_issuer="operator.example"
        ),
        workload_principal=PrincipalBinding(
            principal_id="workload-001", identity_issuer="operator.example"
        ),
        audience="proof-executor",
        delegation_chain=(
            DelegationHop(
                delegator="requestor-001", delegatee="workload-001", scope_sha256=ONE_HASH
            ),
        ),
        subject=SubjectBinding(
            subject_type="case", subject_id="case-001", attributes_sha256=ONE_HASH
        ),
        action=ActionBinding(action_name="publish-draft", parameters_sha256=TWO_HASH),
        resource=ResourceBinding(
            resource_type="artifact",
            resource_id="draft-001",
            attributes_sha256=ZERO_HASH,
        ),
        context=ContextBinding(
            request_id="request-001",
            trace_id="trace-001",
            environment="public-synthetic",
            attributes_sha256=ONE_HASH,
        ),
        data_classification="PUBLIC_SYNTHETIC",
        policy=PolicyBinding(
            policy_id="policy-001",
            policy_revision="revision-001",
            policy_sha256=TWO_HASH,
            decision="ALLOW",
            evaluated_at=NOW - timedelta(minutes=2),
            expires_at=NOW + timedelta(minutes=30),
        ),
        approval=approval,
        effect=EffectBinding(
            effect_type="publish-draft",
            target="public-synthetic-draft-store",
            request_sha256=ONE_HASH,
            idempotency_key="idempotency-001",
        ),
        nonce="nonce-001",
        issued_at=NOW - timedelta(minutes=1),
        not_before=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
    )
    value = ActionCertificateStatement(
        _type="https://in-toto.io/Statement/v1",
        subject=(
            InTotoSubject(name="input-artifact-001", digest=Sha256DigestSet(sha256="3" * 64)),
        ),
        predicateType=ACTION_CERTIFICATE_PREDICATE_TYPE,
        predicate=predicate,
    )
    if approval_required:
        scoped = predicate.approval.model_copy(
            update={"scope_sha256": approval_scope_sha256(value)}
        )
        value = value.model_copy(
            update={"predicate": predicate.model_copy(update={"approval": scoped})}
        )
    return value


def root(
    root_id: str,
    key: Ed25519PrivateKey,
    purpose: TrustPurpose,
    principal: str,
    **updates: Any,
) -> TrustRoot:
    value: dict[str, Any] = {
        "root_id": root_id,
        "keyid_hints": (root_id,),
        "algorithm": "Ed25519",
        "purpose": purpose,
        "public_key_b64": public_key_b64(key),
        "tenant_id": "tenant-synthetic",
        "principal_id": principal,
        "audiences": ("proof-executor",),
        "predicate_types": (ACTION_CERTIFICATE_PREDICATE_TYPE,),
        "not_before": NOW - timedelta(days=1),
        "not_after": NOW + timedelta(days=1),
        "revoked_at": None,
    }
    value.update(updates)
    return TrustRoot(**value)


def policy(
    issuer_key: Ed25519PrivateKey,
    approval_key: Ed25519PrivateKey,
    *,
    approval_required: bool = True,
    roots: tuple[TrustRoot, ...] | None = None,
    **updates: Any,
) -> TrustPolicy:
    configured_roots = roots or (
        root("issuer-root", issuer_key, TrustPurpose.ACTION_ISSUER, "issuer-001"),
        root("approval-root", approval_key, TrustPurpose.HUMAN_APPROVAL, "reviewer-001"),
    )
    value: dict[str, Any] = {
        "policy_version": "proofflow.action-certificate-trust/v0.1",
        "allowed_tenants": ("tenant-synthetic",),
        "allowed_human_principals": ("requestor-001",),
        "allowed_workload_principals": ("workload-001",),
        "allowed_action_issuer_principals": ("issuer-001",),
        "allowed_approval_principals": ("reviewer-001",) if approval_required else (),
        "allowed_audiences": ("proof-executor",),
        "allowed_predicate_types": (ACTION_CERTIFICATE_PREDICATE_TYPE,),
        "approval_required": approval_required,
        "action_issuer_threshold": 1,
        "human_approval_threshold": 1,
        "max_certificate_lifetime_seconds": 3600,
        "max_clock_skew_seconds": 0,
        "roots": configured_roots,
    }
    value.update(updates)
    return TrustPolicy(**value)


def payload_bytes(value: ActionCertificateStatement) -> bytes:
    return json.dumps(
        value.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def envelope_bytes(
    payload: bytes,
    signatures: tuple[tuple[str, Ed25519PrivateKey], ...],
    *,
    payload_type: str = DSSE_PAYLOAD_TYPE,
    extra: dict[str, Any] | None = None,
) -> bytes:
    pae = dsse_pae(payload_type, payload)
    envelope: dict[str, Any] = {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {"keyid": keyid, "sig": base64.b64encode(key.sign(pae)).decode()}
            for keyid, key in signatures
        ],
    }
    if extra:
        envelope.update(extra)
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


def active_resolver(
    *,
    as_of: datetime = NOW - timedelta(minutes=1),
    valid_until: datetime = NOW + timedelta(minutes=9),
) -> SnapshotApprovalRevocationResolver:
    return SnapshotApprovalRevocationResolver(
        ApprovalRevocationSnapshot(
            snapshot_version="proofflow.approval-revocations/v0.1",
            as_of=as_of,
            valid_until=valid_until,
            entries=(
                ApprovalRevocationEntry(
                    tenant_id="tenant-synthetic",
                    approval_id="approval-001",
                    approval_scope_sha256=approval_scope_sha256(statement()),
                    status=ApprovalRevocationStatus.ACTIVE,
                ),
            ),
        )
    )


@pytest.fixture
def certificate_fixture() -> dict[str, Any]:
    issuer = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    value = statement()
    payload = payload_bytes(value)
    return {
        "issuer": issuer,
        "approver": approver,
        "statement": value,
        "payload": payload,
        "envelope": envelope_bytes(payload, (("issuer-root", issuer), ("approval-root", approver))),
        "policy": policy(issuer, approver),
        "expected": expected_binding_for(value),
        "resolver": active_resolver(),
    }


def verify(fixture: dict[str, Any], **updates: Any) -> Any:
    arguments: dict[str, Any] = {
        "trust_policy": fixture["policy"],
        "expected_binding": fixture["expected"],
        "replay_ledger": InMemoryReplayLedger(),
        "approval_revocation_resolver": fixture["resolver"],
        "now": NOW,
    }
    arguments.update(updates)
    return verify_action_certificate(fixture["envelope"], **arguments)


def assert_schema_and_model_reject(
    schema_name: str,
    model: type[BaseModel],
    document: dict[str, Any],
) -> None:
    schema = json.loads((ROOT / "schemas" / f"{schema_name}.schema.json").read_text())
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
    with pytest.raises(ValidationError):
        model.model_validate_json(json.dumps(document))


def test_dsse_102_pae_and_valid_thresholds_accept(certificate_fixture: dict[str, Any]) -> None:
    assert dsse_pae("text/plain", b"abc") == b"DSSEv1 10 text/plain 3 abc"

    result = verify(certificate_fixture)

    assert result.status == VerificationStatus.ACCEPT
    assert result.reason_codes == (VerificationReason.ACCEPTED,)
    assert result.reserved is True
    assert result.verified_action_issuer_roots == ("issuer-root",)
    assert result.verified_human_approval_roots == ("approval-root",)

    urlsafe = json.loads(certificate_fixture["envelope"])
    urlsafe["payload"] = base64.urlsafe_b64encode(certificate_fixture["payload"]).decode()
    for signature in urlsafe["signatures"]:
        signature["sig"] = base64.urlsafe_b64encode(base64.b64decode(signature["sig"])).decode()
        signature.pop("keyid")
    result = verify_action_certificate(
        json.dumps(urlsafe).encode(),
        trust_policy=certificate_fixture["policy"],
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.status == VerificationStatus.ACCEPT

    # DSSE 1.0.2 requires verifiers to accept the URL-safe alphabet and an
    # omitted keyid. These bytes force '-'/'_' rather than relying on random
    # signatures to exercise the alternate alphabet.
    urlsafe_shape = DsseEnvelope(
        payloadType=DSSE_PAYLOAD_TYPE,
        payload=base64.urlsafe_b64encode(b"\xfb\xff").decode(),
        signatures=(DsseSignature(sig=base64.urlsafe_b64encode(b"\xfb" * 64).decode()),),
    )
    assert urlsafe_shape.signatures[0].keyid == ""


def test_exported_schemas_are_strict_current_and_validate_public_examples(
    certificate_fixture: dict[str, Any],
) -> None:
    schema_names = {
        "action-certificate-dsse-envelope": json.loads(certificate_fixture["envelope"]),
        "action-certificate-expected-binding": certificate_fixture["expected"].model_dump(
            mode="json"
        ),
        "action-certificate-predicate-v0p1": certificate_fixture["statement"].predicate.model_dump(
            mode="json"
        ),
        "action-certificate-revocation-snapshot": ApprovalRevocationSnapshot(
            snapshot_version="proofflow.approval-revocations/v0.1",
            as_of=NOW - timedelta(minutes=1),
            valid_until=NOW + timedelta(minutes=9),
            entries=(),
        ).model_dump(mode="json"),
        "action-certificate-statement-v0p1": certificate_fixture["statement"].model_dump(
            mode="json", by_alias=True
        ),
        "action-certificate-trust-policy-v0p1": certificate_fixture["policy"].model_dump(
            mode="json"
        ),
        "action-certificate-verification-result-v0p1": (
            ActionCertificateVerificationResult(
                verification_version="proofflow.action-certificate-verification/v0.1",
                status=VerificationStatus.ACCEPT,
                reason_codes=(VerificationReason.ACCEPTED,),
                certificate_id="certificate-001",
                payload_sha256=ZERO_HASH,
                verified_action_issuer_roots=("issuer-root",),
                verified_human_approval_roots=("approval-root",),
                reserved=True,
            ).model_dump(mode="json")
        ),
    }
    for name, instance in schema_names.items():
        schema = json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)
        definitions = [schema, *schema.get("$defs", {}).values()]
        for definition in definitions:
            if definition.get("type") == "object":
                assert definition.get("additionalProperties") is False

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/export_schemas.py"), "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("schema_name", "model", "document_source"),
    [
        (
            "action-certificate-predicate-v0p1",
            ActionCertificatePredicate,
            "predicate",
        ),
        (
            "action-certificate-expected-binding",
            ExpectedBinding,
            "expected",
        ),
        (
            "action-certificate-statement-v0p1",
            ActionCertificateStatement,
            "statement",
        ),
    ],
)
def test_approval_conditional_has_schema_model_parity(
    certificate_fixture: dict[str, Any],
    schema_name: str,
    model: type[BaseModel],
    document_source: str,
) -> None:
    if document_source == "predicate":
        document = certificate_fixture["statement"].predicate.model_dump(mode="json")
        approval = document["approval"]
    elif document_source == "expected":
        document = certificate_fixture["expected"].model_dump(mode="json")
        approval = document["approval"]
    else:
        document = certificate_fixture["statement"].model_dump(mode="json", by_alias=True)
        approval = document["predicate"]["approval"]
    approval["required"] = False

    assert_schema_and_model_reject(schema_name, model, document)


@pytest.mark.parametrize(
    ("status", "reason", "reserved"),
    [
        ("ACCEPT", "SIGNATURE_INVALID", False),
        ("REJECT", "ACCEPTED", False),
        ("UNKNOWN", "SIGNATURE_INVALID", False),
        ("REJECT", "SIGNATURE_INVALID", True),
    ],
)
def test_verification_status_reason_and_reservation_have_schema_model_parity(
    status: str, reason: str, reserved: bool
) -> None:
    document = {
        "verification_version": "proofflow.action-certificate-verification/v0.1",
        "status": status,
        "reason_codes": [reason],
        "certificate_id": "certificate-001",
        "payload_sha256": ZERO_HASH,
        "verified_action_issuer_roots": [],
        "verified_human_approval_roots": [],
        "reserved": reserved,
    }
    assert_schema_and_model_reject(
        "action-certificate-verification-result-v0p1",
        ActionCertificateVerificationResult,
        document,
    )


def test_verification_reason_sets_partition_enum_and_valid_branches_match_schema() -> None:
    assert REJECT_VERIFICATION_REASONS.isdisjoint(UNKNOWN_VERIFICATION_REASONS)
    assert (
        REJECT_VERIFICATION_REASONS | UNKNOWN_VERIFICATION_REASONS | {VerificationReason.ACCEPTED}
    ) == set(VerificationReason)

    schema = json.loads(
        (ROOT / "schemas/action-certificate-verification-result-v0p1.schema.json").read_text()
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for status, reason, reserved in (
        (VerificationStatus.ACCEPT, VerificationReason.ACCEPTED, True),
        (VerificationStatus.REJECT, VerificationReason.SIGNATURE_INVALID, False),
        (
            VerificationStatus.UNKNOWN,
            VerificationReason.APPROVAL_REVOCATION_UNKNOWN,
            False,
        ),
    ):
        result = ActionCertificateVerificationResult(
            verification_version="proofflow.action-certificate-verification/v0.1",
            status=status,
            reason_codes=(reason,),
            reserved=reserved,
        )
        validator.validate(result.model_dump(mode="json"))

    duplicated = {
        "verification_version": "proofflow.action-certificate-verification/v0.1",
        "status": "REJECT",
        "reason_codes": ["SIGNATURE_INVALID", "SIGNATURE_INVALID"],
        "reserved": False,
    }
    assert_schema_and_model_reject(
        "action-certificate-verification-result-v0p1",
        ActionCertificateVerificationResult,
        duplicated,
    )


def test_all_seven_public_schemas_reject_representable_model_invariants(
    certificate_fixture: dict[str, Any],
) -> None:
    dsse = json.loads(certificate_fixture["envelope"])
    dsse["payload"] = "not-base64"
    assert_schema_and_model_reject("action-certificate-dsse-envelope", DsseEnvelope, dsse)

    revocations = ApprovalRevocationSnapshot(
        snapshot_version="proofflow.approval-revocations/v0.1",
        as_of=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(minutes=9),
        entries=(
            ApprovalRevocationEntry(
                tenant_id="tenant-synthetic",
                approval_id="approval-001",
                approval_scope_sha256=ZERO_HASH,
                status=ApprovalRevocationStatus.ACTIVE,
            ),
        ),
    ).model_dump(mode="json")
    revocations["entries"].append(dict(revocations["entries"][0]))
    assert_schema_and_model_reject(
        "action-certificate-revocation-snapshot",
        ApprovalRevocationSnapshot,
        revocations,
    )

    trust_policy = certificate_fixture["policy"].model_dump(mode="json")
    trust_policy["allowed_approval_principals"] = []
    assert_schema_and_model_reject(
        "action-certificate-trust-policy-v0p1",
        TrustPolicy,
        trust_policy,
    )


def test_exported_schemas_inventory_nonrepresentable_runtime_invariants() -> None:
    statement_schema = json.loads(
        (ROOT / "schemas/action-certificate-statement-v0p1.schema.json").read_text()
    )
    predicate_schema = json.loads(
        (ROOT / "schemas/action-certificate-predicate-v0p1.schema.json").read_text()
    )
    trust_schema = json.loads(
        (ROOT / "schemas/action-certificate-trust-policy-v0p1.schema.json").read_text()
    )
    revocation_schema = json.loads(
        (ROOT / "schemas/action-certificate-revocation-snapshot.schema.json").read_text()
    )

    assert statement_schema["x-proofflow-runtime-invariants"] == [
        "subject[].name values are unique even when digests differ"
    ]
    assert (
        "issued_at <= not_before < expires_at" in predicate_schema["x-proofflow-runtime-invariants"]
    )
    assert statement_schema["$defs"]["DelegationHop"]["x-proofflow-runtime-invariants"] == [
        "delegator and delegatee differ"
    ]
    assert statement_schema["$defs"]["PolicyBinding"]["x-proofflow-runtime-invariants"] == [
        "expires_at is later than evaluated_at"
    ]
    assert trust_schema["$defs"]["TrustRoot"]["x-proofflow-runtime-invariants"]
    assert trust_schema["x-proofflow-runtime-invariants"]
    assert revocation_schema["x-proofflow-runtime-invariants"] == [
        "valid_until is greater than or equal to as_of",
        (
            "the resolver is current only when as_of <= verification_time <= valid_until; "
            "both boundaries are inclusive"
        ),
        "(tenant_id, approval_id) pairs are unique even when scope or status differs",
    ]


@pytest.mark.parametrize(
    "value",
    [
        "2026-08-29 04:00:00Z",
        "2026-08-29T04:00:00",
        "2026-08-29T04:00:00+00:00",
        "2026-08-29T12:00:00+08:00",
        "2026-08-29T04:00:00z",
        "2026-08-29T04:00:00.1234567Z",
    ],
)
def test_cli_verification_time_rejects_non_utc_z_profiles(value: str) -> None:
    with pytest.raises(ValueError, match="UTC RFC 3339 with a trailing Z"):
        _parse_verification_time(value)


def test_cli_verification_time_accepts_utc_z_and_fractional_seconds() -> None:
    assert _parse_verification_time("2026-08-29T04:00:00Z") == NOW
    assert _parse_verification_time("2026-08-29T04:00:00.123456Z") == NOW.replace(
        microsecond=123456
    )
    assert parse_utc_rfc3339_z("2026-08-29T04:00:00.1Z", "test") == NOW.replace(microsecond=100000)


def test_revocation_snapshot_utc_z_has_schema_model_parity() -> None:
    valid = {
        "snapshot_version": "proofflow.approval-revocations/v0.1",
        "as_of": "2026-08-29T04:00:00.123456Z",
        "valid_until": "2026-08-29T04:05:00Z",
        "entries": [],
    }
    schema = json.loads(
        (ROOT / "schemas/action-certificate-revocation-snapshot.schema.json").read_text()
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(valid)
    ApprovalRevocationSnapshot.model_validate_json(json.dumps(valid))

    for field in ("as_of", "valid_until"):
        attacked = dict(valid)
        attacked[field] = "2026-08-29T04:00:00+00:00"
        assert_schema_and_model_reject(
            "action-certificate-revocation-snapshot",
            ApprovalRevocationSnapshot,
            attacked,
        )

    reversed_window = dict(valid)
    reversed_window["as_of"] = "2026-08-29T04:06:00Z"
    assert Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(reversed_window)
    with pytest.raises(ValidationError, match="must not precede"):
        ApprovalRevocationSnapshot.model_validate_json(json.dumps(reversed_window))


def test_keyid_is_only_a_hint_but_remote_keyid_and_remote_root_fields_are_rejected(
    certificate_fixture: dict[str, Any],
) -> None:
    envelope = envelope_bytes(
        certificate_fixture["payload"],
        (
            ("wrong-local-hint", certificate_fixture["issuer"]),
            ("also-wrong", certificate_fixture["approver"]),
        ),
    )
    result = verify_action_certificate(
        envelope,
        trust_policy=certificate_fixture["policy"],
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.status == VerificationStatus.ACCEPT

    attacked = json.loads(envelope)
    attacked["signatures"][0]["keyid"] = "https://attacker.invalid/key"
    result = verify_action_certificate(
        json.dumps(attacked).encode(),
        trust_policy=certificate_fixture["policy"],
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.reason_codes == (VerificationReason.ENVELOPE_INVALID,)

    root_dict = certificate_fixture["policy"].roots[0].model_dump(mode="python")
    root_dict["public_key_url"] = "https://attacker.invalid/key"
    with pytest.raises(ValidationError):
        TrustRoot.model_validate(root_dict)


@pytest.mark.parametrize("attack", ["payload-type", "payload", "unknown-envelope-field"])
def test_envelope_and_exact_payload_substitution_reject(
    certificate_fixture: dict[str, Any], attack: str
) -> None:
    envelope = json.loads(certificate_fixture["envelope"])
    if attack == "payload-type":
        envelope["payloadType"] = "application/json"
    elif attack == "payload":
        envelope["payload"] = base64.b64encode(certificate_fixture["payload"] + b" ").decode()
    elif attack == "unknown-envelope-field":
        envelope["jku"] = "https://attacker.invalid/keyset"
    result = verify_action_certificate(
        json.dumps(envelope).encode(),
        trust_policy=certificate_fixture["policy"],
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.status == VerificationStatus.REJECT
    assert result.reserved is False


def test_signed_payload_is_parsed_only_after_exact_bytes_verify(
    certificate_fixture: dict[str, Any],
) -> None:
    duplicate_json = b'{"_type":"x","_type":"y"}'
    signed = envelope_bytes(duplicate_json, (("issuer-root", certificate_fixture["issuer"]),))
    result = verify_action_certificate(
        signed,
        trust_policy=certificate_fixture["policy"],
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.reason_codes == (VerificationReason.PAYLOAD_INVALID,)

    unsigned = envelope_bytes(duplicate_json, (("bad", Ed25519PrivateKey.generate()),))
    result = verify_action_certificate(
        unsigned,
        trust_policy=certificate_fixture["policy"],
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.reason_codes == (VerificationReason.SIGNATURE_INVALID,)


@pytest.mark.parametrize(
    ("root_update", "policy_update"),
    [
        ({"purpose": TrustPurpose.HUMAN_APPROVAL}, {}),
        ({"tenant_id": "tenant-other"}, {}),
        ({"principal_id": "issuer-other"}, {}),
        ({"audiences": ("audience-other",)}, {}),
        ({"not_before": NOW + timedelta(seconds=1)}, {}),
        ({"not_after": NOW - timedelta(seconds=1)}, {}),
        ({"revoked_at": NOW}, {}),
        ({}, {"allowed_action_issuer_principals": ("issuer-other",)}),
    ],
)
def test_root_purpose_tenant_principal_audience_time_and_revocation_reject(
    certificate_fixture: dict[str, Any],
    root_update: dict[str, Any],
    policy_update: dict[str, Any],
) -> None:
    issuer_root = certificate_fixture["policy"].roots[0].model_copy(update=root_update)
    attacked_policy = certificate_fixture["policy"].model_copy(
        update={
            "roots": (issuer_root, certificate_fixture["policy"].roots[1]),
            **policy_update,
        }
    )
    result = verify(certificate_fixture, trust_policy=attacked_policy)
    assert result.status == VerificationStatus.REJECT
    assert VerificationReason.ACTION_ISSUER_THRESHOLD_NOT_MET in result.reason_codes


def test_algorithm_and_unknown_policy_fields_are_schema_rejected(
    certificate_fixture: dict[str, Any],
) -> None:
    root_dict = certificate_fixture["policy"].roots[0].model_dump(mode="python")
    root_dict["algorithm"] = "ECDSA"
    with pytest.raises(ValidationError):
        TrustRoot.model_validate(root_dict)

    policy_dict = certificate_fixture["policy"].model_dump(mode="python")
    policy_dict["allow_any_root"] = True
    with pytest.raises(ValidationError):
        TrustPolicy.model_validate(policy_dict)

    for injected_field in ("trust_roots", "algorithm"):
        document = certificate_fixture["statement"].model_dump(mode="json", by_alias=True)
        document["predicate"][injected_field] = "attacker-controlled"
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        attacked = envelope_bytes(
            payload,
            (
                ("issuer-root", certificate_fixture["issuer"]),
                ("approval-root", certificate_fixture["approver"]),
            ),
        )
        result = verify_action_certificate(
            attacked,
            trust_policy=certificate_fixture["policy"],
            expected_binding=certificate_fixture["expected"],
            replay_ledger=InMemoryReplayLedger(),
            approval_revocation_resolver=certificate_fixture["resolver"],
            now=NOW,
        )
        assert result.reason_codes == (VerificationReason.PAYLOAD_INVALID,)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("subject", "subject_id"), "case-swapped"),
        (("action", "action_name"), "delete-everything"),
        (("resource", "resource_id"), "resource-swapped"),
        (("context", "request_id"), "request-swapped"),
        (("policy", "policy_revision"), "revision-swapped"),
        (("approval", "approval_id"), "approval-swapped"),
        (("effect", "target"), "effect-target-swapped"),
        (("effect", "idempotency_key"), "idempotency-swapped"),
    ],
)
def test_validly_resigned_sarc_policy_approval_effect_and_idempotency_swaps_reject(
    certificate_fixture: dict[str, Any], path: tuple[str, str], value: str
) -> None:
    document = certificate_fixture["statement"].model_dump(mode="json", by_alias=True)
    document["predicate"][path[0]][path[1]] = value
    attacked_payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    attacked_envelope = envelope_bytes(
        attacked_payload,
        (
            ("issuer-root", certificate_fixture["issuer"]),
            ("approval-root", certificate_fixture["approver"]),
        ),
    )
    result = verify_action_certificate(
        attacked_envelope,
        trust_policy=certificate_fixture["policy"],
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.status == VerificationStatus.REJECT
    assert result.reason_codes == (VerificationReason.EXPECTED_BINDING_MISMATCH,)


def test_policy_and_certificate_time_attacks_reject(certificate_fixture: dict[str, Any]) -> None:
    for attacked_now in (
        NOW - timedelta(minutes=2),
        NOW + timedelta(minutes=11),
    ):
        result = verify(certificate_fixture, now=attacked_now)
        assert result.status == VerificationStatus.REJECT
        assert result.reason_codes == (VerificationReason.CERTIFICATE_TIME_INVALID,)


def test_approval_scope_self_approval_and_threshold_fail_closed(
    certificate_fixture: dict[str, Any],
) -> None:
    value = certificate_fixture["statement"]
    bad_approval = value.predicate.approval.model_copy(update={"scope_sha256": ZERO_HASH})
    bad_statement = value.model_copy(
        update={"predicate": value.predicate.model_copy(update={"approval": bad_approval})}
    )
    bad_envelope = envelope_bytes(
        payload_bytes(bad_statement),
        (
            ("issuer-root", certificate_fixture["issuer"]),
            ("approval-root", certificate_fixture["approver"]),
        ),
    )
    result = verify_action_certificate(
        bad_envelope,
        trust_policy=certificate_fixture["policy"],
        expected_binding=expected_binding_for(bad_statement),
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.reason_codes == (VerificationReason.APPROVAL_SCOPE_MISMATCH,)

    missing_approval_signature = envelope_bytes(
        certificate_fixture["payload"],
        (("issuer-root", certificate_fixture["issuer"]),),
    )
    result = verify_action_certificate(
        missing_approval_signature,
        trust_policy=certificate_fixture["policy"],
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.reason_codes == (VerificationReason.HUMAN_APPROVAL_THRESHOLD_NOT_MET,)

    requester_approval_root = root(
        "self-approval-root",
        certificate_fixture["approver"],
        TrustPurpose.HUMAN_APPROVAL,
        "requestor-001",
    )
    self_approval = value.predicate.approval.model_copy(
        update={"approver_principals": ("requestor-001",)}
    )
    self_statement = value.model_copy(
        update={"predicate": value.predicate.model_copy(update={"approval": self_approval})}
    )
    self_approval = self_approval.model_copy(
        update={"scope_sha256": approval_scope_sha256(self_statement)}
    )
    self_statement = self_statement.model_copy(
        update={
            "predicate": self_statement.predicate.model_copy(update={"approval": self_approval})
        }
    )
    self_policy = certificate_fixture["policy"].model_copy(
        update={
            "allowed_approval_principals": ("requestor-001",),
            "roots": (certificate_fixture["policy"].roots[0], requester_approval_root),
        }
    )
    self_envelope = envelope_bytes(
        payload_bytes(self_statement),
        (
            ("issuer-root", certificate_fixture["issuer"]),
            ("self-approval-root", certificate_fixture["approver"]),
        ),
    )
    result = verify_action_certificate(
        self_envelope,
        trust_policy=self_policy,
        expected_binding=expected_binding_for(self_statement),
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.reason_codes == (VerificationReason.SELF_APPROVAL,)


def test_duplicate_signatures_and_duplicate_root_key_do_not_inflate_threshold(
    certificate_fixture: dict[str, Any],
) -> None:
    issuer_duplicate = (
        certificate_fixture["policy"]
        .roots[0]
        .model_copy(
            update={"root_id": "issuer-root-duplicate", "keyid_hints": ("issuer-duplicate",)}
        )
    )
    threshold_policy = certificate_fixture["policy"].model_copy(
        update={
            "action_issuer_threshold": 2,
            "roots": (
                certificate_fixture["policy"].roots[0],
                issuer_duplicate,
                certificate_fixture["policy"].roots[1],
            ),
        }
    )
    attacked_envelope = envelope_bytes(
        certificate_fixture["payload"],
        (
            ("issuer-root", certificate_fixture["issuer"]),
            ("issuer-duplicate", certificate_fixture["issuer"]),
            ("approval-root", certificate_fixture["approver"]),
        ),
    )
    result = verify_action_certificate(
        attacked_envelope,
        trust_policy=threshold_policy,
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.status == VerificationStatus.REJECT
    assert VerificationReason.ACTION_ISSUER_THRESHOLD_NOT_MET in result.reason_codes


def test_multiple_keys_for_one_principal_do_not_inflate_authority_threshold(
    certificate_fixture: dict[str, Any],
) -> None:
    second_key = Ed25519PrivateKey.generate()
    second_root = root(
        "issuer-root-second-key",
        second_key,
        TrustPurpose.ACTION_ISSUER,
        "issuer-001",
    )
    threshold_policy = certificate_fixture["policy"].model_copy(
        update={
            "action_issuer_threshold": 2,
            "roots": (
                certificate_fixture["policy"].roots[0],
                second_root,
                certificate_fixture["policy"].roots[1],
            ),
        }
    )
    attacked_envelope = envelope_bytes(
        certificate_fixture["payload"],
        (
            ("issuer-root", certificate_fixture["issuer"]),
            ("issuer-root-second-key", second_key),
            ("approval-root", certificate_fixture["approver"]),
        ),
    )
    result = verify_action_certificate(
        attacked_envelope,
        trust_policy=threshold_policy,
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.status == VerificationStatus.REJECT
    assert VerificationReason.ACTION_ISSUER_THRESHOLD_NOT_MET in result.reason_codes


def test_revocation_unknown_unavailable_and_revoked_never_reserve(
    certificate_fixture: dict[str, Any],
) -> None:
    ledger = InMemoryReplayLedger()
    unknown = verify(certificate_fixture, replay_ledger=ledger, approval_revocation_resolver=None)
    assert unknown.status == VerificationStatus.UNKNOWN
    assert unknown.reserved is False

    class BrokenResolver:
        def resolve(self, **kwargs: Any) -> ApprovalRevocationStatus:
            del kwargs
            raise TimeoutError

    unavailable = verify(
        certificate_fixture,
        replay_ledger=ledger,
        approval_revocation_resolver=BrokenResolver(),
    )
    assert unavailable.status == VerificationStatus.UNKNOWN
    assert unavailable.reserved is False

    swapped_scope_resolver = SnapshotApprovalRevocationResolver(
        ApprovalRevocationSnapshot(
            snapshot_version="proofflow.approval-revocations/v0.1",
            as_of=NOW - timedelta(minutes=1),
            valid_until=NOW + timedelta(minutes=9),
            entries=(
                ApprovalRevocationEntry(
                    tenant_id="tenant-synthetic",
                    approval_id="approval-001",
                    approval_scope_sha256=ZERO_HASH,
                    status=ApprovalRevocationStatus.ACTIVE,
                ),
            ),
        )
    )
    swapped_scope = verify(
        certificate_fixture,
        replay_ledger=ledger,
        approval_revocation_resolver=swapped_scope_resolver,
    )
    assert swapped_scope.status == VerificationStatus.UNKNOWN
    assert swapped_scope.reserved is False

    revoked_resolver = SnapshotApprovalRevocationResolver(
        ApprovalRevocationSnapshot(
            snapshot_version="proofflow.approval-revocations/v0.1",
            as_of=NOW - timedelta(minutes=1),
            valid_until=NOW + timedelta(minutes=9),
            entries=(
                ApprovalRevocationEntry(
                    tenant_id="tenant-synthetic",
                    approval_id="approval-001",
                    approval_scope_sha256=approval_scope_sha256(certificate_fixture["statement"]),
                    status=ApprovalRevocationStatus.REVOKED,
                ),
            ),
        )
    )
    revoked = verify(
        certificate_fixture,
        replay_ledger=ledger,
        approval_revocation_resolver=revoked_resolver,
    )
    assert revoked.status == VerificationStatus.REJECT
    assert revoked.reserved is False

    accepted = verify(certificate_fixture, replay_ledger=ledger)
    assert accepted.status == VerificationStatus.ACCEPT


def test_revocation_snapshot_window_is_inclusive_and_outside_is_unknown_without_reserve(
    certificate_fixture: dict[str, Any],
) -> None:
    window_start = NOW
    window_end = NOW + timedelta(minutes=5)
    resolver = active_resolver(as_of=window_start, valid_until=window_end)

    before_ledger = InMemoryReplayLedger()
    before = verify(
        certificate_fixture,
        replay_ledger=before_ledger,
        approval_revocation_resolver=resolver,
        now=window_start - timedelta(microseconds=1),
    )
    assert before.status == VerificationStatus.UNKNOWN
    assert before.reason_codes == (VerificationReason.APPROVAL_REVOCATION_UNKNOWN,)
    assert before.reserved is False
    at_start = verify(
        certificate_fixture,
        replay_ledger=before_ledger,
        approval_revocation_resolver=resolver,
        now=window_start,
    )
    assert at_start.status == VerificationStatus.ACCEPT

    after_ledger = InMemoryReplayLedger()
    after = verify(
        certificate_fixture,
        replay_ledger=after_ledger,
        approval_revocation_resolver=resolver,
        now=window_end + timedelta(microseconds=1),
    )
    assert after.status == VerificationStatus.UNKNOWN
    assert after.reason_codes == (VerificationReason.APPROVAL_REVOCATION_UNKNOWN,)
    assert after.reserved is False
    at_end = verify(
        certificate_fixture,
        replay_ledger=after_ledger,
        approval_revocation_resolver=resolver,
        now=window_end,
    )
    assert at_end.status == VerificationStatus.ACCEPT


def test_replay_cross_tenant_and_idempotency_conflict_reject(
    certificate_fixture: dict[str, Any],
) -> None:
    ledger = InMemoryReplayLedger()
    first = verify(certificate_fixture, replay_ledger=ledger)
    second = verify(certificate_fixture, replay_ledger=ledger)
    assert first.status == VerificationStatus.ACCEPT
    assert second.reason_codes == (VerificationReason.REPLAY_DETECTED,)

    cross_tenant_expected = certificate_fixture["expected"].model_copy(
        update={"tenant_id": "tenant-other"}
    )
    cross_tenant_policy = certificate_fixture["policy"].model_copy(
        update={"allowed_tenants": ("tenant-synthetic", "tenant-other")}
    )
    cross_tenant = verify(
        certificate_fixture,
        trust_policy=cross_tenant_policy,
        expected_binding=cross_tenant_expected,
    )
    assert cross_tenant.reason_codes == (VerificationReason.EXPECTED_BINDING_MISMATCH,)

    value = certificate_fixture["statement"]
    retry_predicate = value.predicate.model_copy(
        update={"certificate_id": "certificate-002", "nonce": "nonce-002"}
    )
    retry = value.model_copy(update={"predicate": retry_predicate})
    retry_envelope = envelope_bytes(
        payload_bytes(retry),
        (
            ("issuer-root", certificate_fixture["issuer"]),
            ("approval-root", certificate_fixture["approver"]),
        ),
    )
    replay = verify_action_certificate(
        retry_envelope,
        trust_policy=certificate_fixture["policy"],
        expected_binding=expected_binding_for(retry),
        replay_ledger=ledger,
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert replay.reason_codes == (VerificationReason.REPLAY_DETECTED,)

    different_effect = value.predicate.effect.model_copy(update={"request_sha256": TWO_HASH})
    different_approval = value.predicate.approval.model_copy(update={"approval_id": "approval-002"})
    conflict_predicate = value.predicate.model_copy(
        update={
            "certificate_id": "certificate-003",
            "nonce": "nonce-003",
            "effect": different_effect,
            "approval": different_approval,
        }
    )
    conflict_statement = value.model_copy(update={"predicate": conflict_predicate})
    rescoped_approval = conflict_predicate.approval.model_copy(
        update={"scope_sha256": approval_scope_sha256(conflict_statement)}
    )
    conflict_statement = conflict_statement.model_copy(
        update={"predicate": conflict_predicate.model_copy(update={"approval": rescoped_approval})}
    )
    conflict_envelope = envelope_bytes(
        payload_bytes(conflict_statement),
        (
            ("issuer-root", certificate_fixture["issuer"]),
            ("approval-root", certificate_fixture["approver"]),
        ),
    )
    conflict_resolver = SnapshotApprovalRevocationResolver(
        ApprovalRevocationSnapshot(
            snapshot_version="proofflow.approval-revocations/v0.1",
            as_of=NOW - timedelta(minutes=1),
            valid_until=NOW + timedelta(minutes=9),
            entries=(
                ApprovalRevocationEntry(
                    tenant_id="tenant-synthetic",
                    approval_id="approval-002",
                    approval_scope_sha256=approval_scope_sha256(conflict_statement),
                    status=ApprovalRevocationStatus.ACTIVE,
                ),
            ),
        )
    )
    conflict = verify_action_certificate(
        conflict_envelope,
        trust_policy=certificate_fixture["policy"],
        expected_binding=expected_binding_for(conflict_statement),
        replay_ledger=ledger,
        approval_revocation_resolver=conflict_resolver,
        now=NOW,
    )
    assert conflict.reason_codes == (VerificationReason.IDEMPOTENCY_CONFLICT,)


def test_process_local_reserve_once_is_atomic_under_concurrency(
    certificate_fixture: dict[str, Any],
) -> None:
    ledger = InMemoryReplayLedger()

    def attempt(_: int) -> VerificationStatus:
        return verify(certificate_fixture, replay_ledger=ledger).status

    with ThreadPoolExecutor(max_workers=16) as executor:
        statuses = list(executor.map(attempt, range(64)))
    assert statuses.count(VerificationStatus.ACCEPT) == 1
    assert statuses.count(VerificationStatus.REJECT) == 63


def test_resource_bounds_unknown_fields_and_noncanonical_base64_fail_closed(
    certificate_fixture: dict[str, Any],
) -> None:
    result = verify_action_certificate(
        b"x" * (MAX_ENVELOPE_BYTES + 1),
        trust_policy=certificate_fixture["policy"],
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.reason_codes == (VerificationReason.ENVELOPE_TOO_LARGE,)

    attacked = json.loads(certificate_fixture["envelope"])
    attacked["payload"] = attacked["payload"].rstrip("=")
    result = verify_action_certificate(
        json.dumps(attacked).encode(),
        trust_policy=certificate_fixture["policy"],
        expected_binding=certificate_fixture["expected"],
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=certificate_fixture["resolver"],
        now=NOW,
    )
    assert result.reason_codes == (VerificationReason.ENVELOPE_INVALID,)

    envelope = json.loads(certificate_fixture["envelope"])
    envelope["signatures"] = envelope["signatures"] * 9
    with pytest.raises(ValidationError):
        DsseEnvelope.model_validate(envelope)


def test_cli_is_fail_closed_under_python_optimization(
    certificate_fixture: dict[str, Any], tmp_path: Path
) -> None:
    paths = {
        "envelope": tmp_path / "envelope.json",
        "policy": tmp_path / "policy.json",
        "expected": tmp_path / "expected.json",
        "revocations": tmp_path / "revocations.json",
    }
    paths["envelope"].write_bytes(certificate_fixture["envelope"])
    paths["policy"].write_text(certificate_fixture["policy"].model_dump_json())
    paths["expected"].write_text(certificate_fixture["expected"].model_dump_json())
    snapshot = ApprovalRevocationSnapshot(
        snapshot_version="proofflow.approval-revocations/v0.1",
        as_of=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(minutes=9),
        entries=(
            ApprovalRevocationEntry(
                tenant_id="tenant-synthetic",
                approval_id="approval-001",
                approval_scope_sha256=approval_scope_sha256(certificate_fixture["statement"]),
                status=ApprovalRevocationStatus.ACTIVE,
            ),
        ),
    )
    paths["revocations"].write_text(snapshot.model_dump_json())

    arguments = [
        "-m",
        "proofflow.cli",
        "certificate",
        "verify",
        "--envelope",
        str(paths["envelope"]),
        "--trust-policy",
        str(paths["policy"]),
        "--expected-binding",
        str(paths["expected"]),
        "--approval-revocations",
        str(paths["revocations"]),
        "--at",
        NOW.isoformat().replace("+00:00", "Z"),
    ]
    accepted = subprocess.run(
        [sys.executable, *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    assert accepted.returncode == 0
    assert json.loads(accepted.stdout)["status"] == "ACCEPT"

    non_z_time = subprocess.run(
        [sys.executable, *arguments[:-1], NOW.isoformat()],
        check=False,
        capture_output=True,
        text=True,
    )
    assert non_z_time.returncode == 2
    assert non_z_time.stdout == ""
    assert "UTC RFC 3339 with a trailing Z" in non_z_time.stderr

    expired_snapshot = snapshot.model_copy(
        update={
            "as_of": NOW - timedelta(minutes=3),
            "valid_until": NOW - timedelta(minutes=2),
        }
    )
    paths["revocations"].write_text(expired_snapshot.model_dump_json())
    unknown = subprocess.run(
        [sys.executable, *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    unknown_output = json.loads(unknown.stdout)
    assert unknown.returncode == 3
    assert unknown_output["status"] == "UNKNOWN"
    assert unknown_output["reason_codes"] == ["APPROVAL_REVOCATION_UNKNOWN"]
    assert unknown_output["reserved"] is False

    envelope = json.loads(certificate_fixture["envelope"])
    envelope["unexpected"] = True
    paths["envelope"].write_text(json.dumps(envelope))
    result = subprocess.run(
        [
            sys.executable,
            "-O",
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "REJECT"
    assert result.stderr == ""


def test_no_approval_policy_accepts_issuer_only_without_revocation_lookup() -> None:
    issuer = Ed25519PrivateKey.generate()
    unused_approver = Ed25519PrivateKey.generate()
    value = statement(approval_required=False)
    payload = payload_bytes(value)
    configured_policy = policy(
        issuer,
        unused_approver,
        approval_required=False,
        roots=(root("issuer-root", issuer, TrustPurpose.ACTION_ISSUER, "issuer-001"),),
    )
    result = verify_action_certificate(
        envelope_bytes(payload, (("issuer-root", issuer),)),
        trust_policy=configured_policy,
        expected_binding=expected_binding_for(value),
        replay_ledger=InMemoryReplayLedger(),
        approval_revocation_resolver=None,
        now=NOW,
    )
    assert result.status == VerificationStatus.ACCEPT
