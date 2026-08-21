"""Shared deterministic Skill helpers."""

from __future__ import annotations

from typing import Any

from proofflow.canonical import sha256_digest
from proofflow.models import Issue, SkillContext, SkillResult, SkillStatus


def denied[T](
    *,
    context: SkillContext,
    request: Any,
    expected_identity: str,
    result_type: type[T],
) -> SkillResult[T] | None:
    del result_type
    if context.caller_identity == expected_identity:
        return None
    return SkillResult[T](
        status=SkillStatus.BLOCKED,
        issues=(
            Issue(
                code="UNAUTHORIZED_CALLER",
                severity="BLOCKER",
                message=(
                    f"{context.caller_identity} cannot execute a Skill owned by {expected_identity}"
                ),
            ),
        ),
        input_hash=sha256_digest(request),
    )


def success[T](request: Any, value: T, emitted_refs: tuple[str, ...]) -> SkillResult[T]:
    return SkillResult[T](
        status=SkillStatus.SUCCESS,
        value=value,
        input_hash=sha256_digest(request),
        output_hash=sha256_digest(value),
        emitted_refs=emitted_refs,
    )
