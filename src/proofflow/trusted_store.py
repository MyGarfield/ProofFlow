"""Bounded in-memory trust registry for locally ingested synthetic Evidence."""

from __future__ import annotations

import threading
from collections.abc import Iterable

from proofflow.canonical import canonical_json
from proofflow.models import (
    DataClassification,
    EvidenceObject,
    FactStatus,
    SkillContext,
)

DEFAULT_TRUSTED_ARTIFACT_CAPACITY = 4096

ArtifactKey = tuple[str, str, str, str, str]


class TrustedArtifactStoreError(RuntimeError):
    """Base class for fail-closed registry errors."""


class TrustedArtifactStoreCapacityError(TrustedArtifactStoreError):
    """Raised atomically when a batch would exceed the configured capacity."""


class TrustedArtifactStoreRegistrationError(TrustedArtifactStoreError):
    """Raised when a caller attempts to register an invalid or conflicting object."""


class TrustedArtifactStore:
    """Thread-safe process-local registry of complete canonical Evidence objects.

    Registration is only intended immediately after trusted local ``evidence_ingest``
    execution. The registry is deliberately non-persistent and does not make hashes
    into signatures or independently authenticate the original uploader.
    """

    def __init__(self, capacity: int = DEFAULT_TRUSTED_ARTIFACT_CAPACITY) -> None:
        if capacity < 1:
            raise ValueError("trusted artifact capacity must be positive")
        self.capacity = capacity
        self._records: dict[ArtifactKey, bytes] = {}
        self._lock = threading.RLock()

    def register_all(self, evidence: Iterable[EvidenceObject]) -> None:
        """Atomically register a batch; identical retries do not consume capacity."""
        pending: dict[ArtifactKey, bytes] = {}
        for item in evidence:
            if (
                not item.verify_hash()
                or item.meta.content_hash is None
                or item.meta.producer_identity != "PF-A2"
                or item.meta.classification != DataClassification.PUBLIC_SYNTHETIC
                or item.fact_status != FactStatus.VERIFIED
            ):
                raise TrustedArtifactStoreRegistrationError(
                    "only verified PF-A2 PUBLIC_SYNTHETIC Evidence can be registered"
                )
            key = self._key_from_artifact(item)
            payload = canonical_json(item)
            if key in pending and pending[key] != payload:
                raise TrustedArtifactStoreRegistrationError(
                    "conflicting canonical Evidence share one registry key"
                )
            pending[key] = payload

        with self._lock:
            for key, payload in pending.items():
                existing = self._records.get(key)
                if existing is not None and existing != payload:
                    raise TrustedArtifactStoreRegistrationError(
                        "registered Evidence cannot be replaced"
                    )
            new_keys = pending.keys() - self._records.keys()
            if len(self._records) + len(new_keys) > self.capacity:
                raise TrustedArtifactStoreCapacityError(
                    "trusted artifact capacity would be exceeded"
                )
            self._records.update(pending)

    def contains(self, context: SkillContext, evidence: EvidenceObject) -> bool:
        """Confirm exact canonical bytes under the caller's tenant/case/trace scope."""
        if evidence.meta.content_hash is None:
            return False
        key: ArtifactKey = (
            context.tenant_id,
            context.case_id,
            context.trace_id,
            evidence.meta.artifact_id,
            evidence.meta.content_hash,
        )
        try:
            payload = canonical_json(evidence)
        except (TypeError, ValueError):
            return False
        with self._lock:
            return self._records.get(key) == payload

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    @staticmethod
    def _key_from_artifact(evidence: EvidenceObject) -> ArtifactKey:
        assert evidence.meta.content_hash is not None
        return (
            evidence.meta.tenant_id,
            evidence.meta.case_id,
            evidence.meta.trace_id,
            evidence.meta.artifact_id,
            evidence.meta.content_hash,
        )
