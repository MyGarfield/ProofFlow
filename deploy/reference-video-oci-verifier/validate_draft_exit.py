"""Fail-closed Draft-exit validation for external image verification evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA = "proofflow.reference-video.draft-exit-report.v1"
EXPECTED_CHILD = "sha256:95098d1231d5cdc8a046e33bad298d5dd85dafaaa1c9a450b82e46f026bf174f"
EXPECTED_CONFIG = "sha256:5e0b838383ca9050d801fe5a95809106fa428bc98c521cfb15fafd8355286ba9"
EXPECTED_TOOLCHAIN = "sha256:f9c4884ce4d3ba693325790329e980c29b40423d1034593e28e8d3231aa82a8f"
EXPECTED_IMAGE_REF = "ghcr.io/mygarfield/proofflow-reference-video-verifier@" + EXPECTED_CHILD
EXPECTED_ARTIFACT_COMMIT = "290ef94caf96cf3f1e4568cf8f19a52a8b460bc0"
EXPECTED_MANIFEST = "sha256:d031c112d517d1a6931c97fed6fc667a7fd2fd29872e04d901829b6bcfe2b92a"
EXPECTED_MANIFEST_SCHEMA = "sha256:3af014e66ce304a5f205e5cb9b2900157d6469b72ff5601e1c7a1d447224c104"
EXPECTED_VALIDATOR = "sha256:bba1e9d75c5694a148da96f77f2e431bc23ce1248e6bac3f3a1db3bca8940051"
CHECK_IDS = (
    "external_publication",
    "public_digest_pull",
    "publisher_attestation",
    "independent_identity",
    "video_receipt_schema",
    "video_receipt_integrity",
    "video_runtime_checks",
    "reproducibility_receipt",
    "cross_receipt_binding",
)
MAX_JSON_BYTES = 4 * 1024 * 1024


class DraftExitFailure(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def strict_json_bytes(raw: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise DraftExitFailure("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                DraftExitFailure("NONFINITE_JSON_NUMBER")
            ),
        )
    except DraftExitFailure:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DraftExitFailure("INVALID_JSON") from error


def read_regular(path: Path) -> tuple[bytes, object]:
    try:
        info = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or not 0 < info.st_size <= MAX_JSON_BYTES
        ):
            raise DraftExitFailure("EVIDENCE_FILE_INVALID")
        raw = path.read_bytes()
    except DraftExitFailure:
        raise
    except OSError as error:
        raise DraftExitFailure("EVIDENCE_FILE_UNREADABLE") from error
    return raw, strict_json_bytes(raw)


def verify_integrity(document: object) -> bool:
    if not isinstance(document, dict):
        return False
    integrity = document.get("integrity")
    if not isinstance(integrity, dict):
        return False
    if integrity.get("algorithm") != "sha256-canonical-json-excluding-integrity":
        return False
    payload = {key: value for key, value in document.items() if key != "integrity"}
    return integrity.get("payload_sha256") == digest_bytes(canonical_json(payload))


def check(check_id: str, passed: bool, pass_code: str, fail_code: str) -> dict[str, str]:
    return {
        "id": check_id,
        "status": "PASS" if passed else "FAIL",
        "code": pass_code if passed else fail_code,
    }


def unknown_checks() -> list[dict[str, str]]:
    return [
        {"id": check_id, "status": "UNKNOWN", "code": "EXTERNAL_VERIFICATION_NOT_EXECUTED"}
        for check_id in CHECK_IDS
    ]


def schema_valid(document: object, schema: dict[str, Any]) -> bool:
    try:
        Draft202012Validator(schema).validate(document)
        return True
    except Exception:
        return False


def evaluate(
    observation: dict[str, Any],
    *,
    attestation_raw: bytes | None,
    identity_raw: bytes | None,
    identity: object | None,
    video_raw: bytes | None,
    video: object | None,
    reproducibility_raw: bytes | None,
    reproducibility: object | None,
    video_schema: dict[str, Any],
    reproducibility_schema: dict[str, Any],
    identity_schema: dict[str, Any],
) -> dict[str, object]:
    evidence = {
        "attestation_evidence_url": observation["publication"]["attestation"]["evidence_url"],
        "attestation_result_sha256": observation["publication"]["attestation"]["raw_result_sha256"],
        "identity_evidence_url": observation["verifier"]["identity_evidence_url"],
        "identity_result_sha256": observation["verifier"]["identity_result_sha256"],
        "video_receipt_file_sha256": observation["verifier"]["video_receipt_file_sha256"],
        "video_receipt_payload_sha256": observation["verifier"]["video_receipt_payload_sha256"],
        "reproducibility_receipt_file_sha256": observation["verifier"][
            "reproducibility_receipt_file_sha256"
        ],
        "reproducibility_receipt_payload_sha256": observation["verifier"][
            "reproducibility_receipt_payload_sha256"
        ],
    }
    if observation["status"] == "NOT_EXECUTED":
        report: dict[str, object] = {
            "schema": SCHEMA,
            "status": "UNKNOWN",
            "decision": "BLOCKED",
            "error_code": "EXTERNAL_VERIFICATION_NOT_EXECUTED",
            "image": observation["image"],
            "checks": unknown_checks(),
            "evidence": evidence,
        }
        report["integrity"] = {
            "algorithm": "sha256-canonical-json-excluding-integrity",
            "payload_sha256": digest_bytes(canonical_json(report)),
        }
        return report

    publication = observation["publication"]
    verifier = observation["verifier"]
    attestation = publication["attestation"]
    checks: list[dict[str, str]] = []
    checks.append(
        check(
            "external_publication",
            publication["registry"] == "ghcr.io"
            and publication["external_push_observed"]
            and observation["image"]["ref"] == EXPECTED_IMAGE_REF,
            "EXTERNAL_PUBLICATION_VERIFIED",
            "EXTERNAL_PUBLICATION_MISSING",
        )
    )
    checks.append(
        check(
            "public_digest_pull",
            publication["public_pull_observed"] and verifier["pull_by_digest_observed"],
            "PUBLIC_DIGEST_PULL_VERIFIED",
            "PUBLIC_DIGEST_PULL_MISSING",
        )
    )
    attestation_ok = (
        attestation_raw is not None
        and attestation["verified"]
        and attestation["subject_digest"] == EXPECTED_CHILD
        and digest_bytes(attestation_raw) == attestation["raw_result_sha256"]
    )
    checks.append(
        check(
            "publisher_attestation",
            attestation_ok,
            "PUBLISHER_ATTESTATION_VERIFIED",
            "PUBLISHER_ATTESTATION_INVALID",
        )
    )
    identity_ok = False
    if isinstance(identity, dict):
        identity_ok = (
            identity_raw is not None
            and schema_valid(identity, identity_schema)
            and verify_integrity(identity)
            and identity.get("trust_domain") == verifier["trust_domain"]
            and identity.get("publisher_trust_domain") == verifier["publisher_trust_domain"]
            and identity.get("trust_domain") != identity.get("publisher_trust_domain")
            and identity.get("evidence_url") == verifier["identity_evidence_url"]
            and identity.get("image_ref") == EXPECTED_IMAGE_REF
            and identity.get("pull_by_digest_observed") is True
            and identity.get("video_receipt_file_sha256") == verifier["video_receipt_file_sha256"]
            and identity.get("reproducibility_receipt_file_sha256")
            == verifier["reproducibility_receipt_file_sha256"]
            and isinstance(identity.get("attestation"), dict)
            and identity["attestation"].get("verified") is True
            and digest_bytes(identity_raw) == verifier["identity_result_sha256"]
        )
    identity_ok = identity_ok and verifier["independent"]
    checks.append(
        check(
            "independent_identity",
            identity_ok,
            "INDEPENDENT_IDENTITY_VERIFIED",
            "INDEPENDENT_IDENTITY_INVALID",
        )
    )

    video_schema_ok = video is not None and schema_valid(video, video_schema)
    video_integrity_ok = video_schema_ok and verify_integrity(video)
    checks.append(
        check(
            "video_receipt_schema",
            video_schema_ok,
            "VIDEO_RECEIPT_SCHEMA_VALID",
            "VIDEO_RECEIPT_SCHEMA_INVALID",
        )
    )
    checks.append(
        check(
            "video_receipt_integrity",
            bool(video_integrity_ok),
            "VIDEO_RECEIPT_INTEGRITY_VALID",
            "VIDEO_RECEIPT_INTEGRITY_INVALID",
        )
    )
    video_runtime_ok = False
    if isinstance(video, dict):
        expectations = video.get("expectations")
        image = video.get("image")
        runtime_checks = video.get("checks")
        video_runtime_ok = (
            video_schema_ok
            and video_integrity_ok
            and video.get("overall_status") == "PASS"
            and isinstance(runtime_checks, list)
            and len(runtime_checks) == 19
            and all(
                isinstance(item, dict) and item.get("status") == "PASS" for item in runtime_checks
            )
            and isinstance(expectations, dict)
            and expectations.get("artifact_commit") == EXPECTED_ARTIFACT_COMMIT
            and expectations.get("manifest_sha256") == EXPECTED_MANIFEST
            and expectations.get("schema_sha256") == EXPECTED_MANIFEST_SCHEMA
            and expectations.get("validator_sha256") == EXPECTED_VALIDATOR
            and expectations.get("verification_toolchain_sha256") == EXPECTED_TOOLCHAIN
            and isinstance(image, dict)
            and image.get("child_digest") == EXPECTED_CHILD
            and image.get("config_digest") == EXPECTED_CONFIG
        )
    checks.append(
        check(
            "video_runtime_checks",
            video_runtime_ok,
            "VIDEO_RUNTIME_19_PASS",
            "VIDEO_RUNTIME_EVIDENCE_INVALID",
        )
    )

    reproducibility_ok = False
    if isinstance(reproducibility, dict):
        builds = reproducibility.get("builds")
        reproducibility_ok = (
            schema_valid(reproducibility, reproducibility_schema)
            and verify_integrity(reproducibility)
            and reproducibility.get("status") == "PASS"
            and isinstance(builds, list)
            and len(builds) == 2
            and all(
                isinstance(item, dict)
                and item.get("child_digest") == EXPECTED_CHILD
                and item.get("config_digest") == EXPECTED_CONFIG
                for item in builds
            )
        )
    checks.append(
        check(
            "reproducibility_receipt",
            reproducibility_ok,
            "REPRODUCIBILITY_RECEIPT_VALID",
            "REPRODUCIBILITY_RECEIPT_INVALID",
        )
    )

    file_hashes_ok = (
        video_raw is not None
        and reproducibility_raw is not None
        and digest_bytes(video_raw) == verifier["video_receipt_file_sha256"]
        and digest_bytes(reproducibility_raw) == verifier["reproducibility_receipt_file_sha256"]
        and isinstance(video, dict)
        and isinstance(reproducibility, dict)
        and isinstance(video.get("integrity"), dict)
        and isinstance(reproducibility.get("integrity"), dict)
        and video["integrity"].get("payload_sha256") == verifier["video_receipt_payload_sha256"]
        and reproducibility["integrity"].get("payload_sha256")
        == verifier["reproducibility_receipt_payload_sha256"]
    )
    checks.append(
        check(
            "cross_receipt_binding",
            file_hashes_ok and video_runtime_ok and reproducibility_ok,
            "CROSS_RECEIPT_BINDING_VALID",
            "CROSS_RECEIPT_BINDING_INVALID",
        )
    )

    passed = all(item["status"] == "PASS" for item in checks)
    report = {
        "schema": SCHEMA,
        "status": "PASS" if passed else "FAIL",
        "decision": "READY" if passed else "BLOCKED",
        "error_code": None if passed else "DRAFT_EXIT_EVIDENCE_INCOMPLETE_OR_INVALID",
        "image": observation["image"],
        "checks": checks,
        "evidence": evidence,
    }
    report["integrity"] = {
        "algorithm": "sha256-canonical-json-excluding-integrity",
        "payload_sha256": digest_bytes(canonical_json(report)),
    }
    return report


def write_once(path: Path, report: dict[str, object]) -> None:
    try:
        parent = path.parent
        parent_info = parent.lstat()
        if parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode):
            raise DraftExitFailure("OUTPUT_PARENT_INVALID")
        if path.exists() or path.is_symlink():
            raise DraftExitFailure("OUTPUT_ALREADY_EXISTS")
        payload = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n"
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except DraftExitFailure:
        raise
    except OSError as error:
        raise DraftExitFailure("OUTPUT_WRITE_FAILED") from error


def optional_evidence(path: Path | None) -> tuple[bytes | None, object | None]:
    if path is None:
        return None, None
    return read_regular(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observation", required=True, type=Path)
    parser.add_argument("--attestation-result", type=Path)
    parser.add_argument("--identity-result", type=Path)
    parser.add_argument("--video-receipt", type=Path)
    parser.add_argument("--reproducibility-receipt", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    try:
        _, observation_document = read_regular(args.observation)
        if not isinstance(observation_document, dict):
            raise DraftExitFailure("OBSERVATION_INVALID")
        observation_schema = strict_json_bytes(
            (root / "external-verification-observation.schema.json").read_bytes()
        )
        report_schema = strict_json_bytes((root / "draft-exit-report.schema.json").read_bytes())
        video_schema = strict_json_bytes((root / "receipt.schema.json").read_bytes())
        reproducibility_schema = strict_json_bytes(
            (root / "build-reproducibility.schema.json").read_bytes()
        )
        identity_schema = strict_json_bytes(
            (root / "external-verifier-identity.schema.json").read_bytes()
        )
        if not all(
            isinstance(item, dict)
            for item in (
                observation_schema,
                report_schema,
                video_schema,
                reproducibility_schema,
                identity_schema,
            )
        ):
            raise DraftExitFailure("SCHEMA_INVALID")
        Draft202012Validator(observation_schema).validate(observation_document)
        attestation_raw = (
            read_regular(args.attestation_result)[0] if args.attestation_result else None
        )
        identity_raw, identity = optional_evidence(args.identity_result)
        video_raw, video = optional_evidence(args.video_receipt)
        reproducibility_raw, reproducibility = optional_evidence(args.reproducibility_receipt)
        report = evaluate(
            observation_document,
            attestation_raw=attestation_raw,
            identity_raw=identity_raw,
            identity=identity,
            video_raw=video_raw,
            video=video,
            reproducibility_raw=reproducibility_raw,
            reproducibility=reproducibility,
            video_schema=video_schema,
            reproducibility_schema=reproducibility_schema,
            identity_schema=identity_schema,
        )
        Draft202012Validator(report_schema).validate(report)
        write_once(args.output, report)
    except Exception as error:
        print("proofflow Draft exit: CLOSED_FAILURE", file=__import__("sys").stderr)
        raise SystemExit(2) from error
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
