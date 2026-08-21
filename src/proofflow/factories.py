"""Deterministic identifiers and artifact metadata construction."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from proofflow.canonical import sha256_digest
from proofflow.models import ArtifactMeta, DataClassification, SkillContext


def stable_id(prefix: str, value: Any) -> str:
    digest = sha256_digest(value).removeprefix("sha256:")
    return f"{prefix}-{digest[:20]}"


def artifact_meta(
    *,
    prefix: str,
    identity: str,
    context: SkillContext,
    now: datetime,
    payload_for_id: Any,
    source_refs: tuple[str, ...] = (),
    classification: DataClassification = DataClassification.PUBLIC_SYNTHETIC,
) -> ArtifactMeta:
    return ArtifactMeta(
        artifact_id=stable_id(prefix, payload_for_id),
        tenant_id=context.tenant_id,
        case_id=context.case_id,
        producer_identity=identity,
        trace_id=context.trace_id,
        created_at=now,
        source_refs=source_refs,
        classification=classification,
    )
