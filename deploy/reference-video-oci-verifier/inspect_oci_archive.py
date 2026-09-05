"""Inspect a downloaded, immutable OCI image archive without extracting it.

The archive is attacker-controlled input.  No member is extracted to disk;
all names, links, sizes and duplicate entries are checked before the three
required OCI objects are read.  Failure output is intentionally path-free.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import tarfile
from pathlib import Path, PurePosixPath

SCHEMA_ID = "proofflow.reference-runtime-oci-verifier.archive-inspection.v1"
PLATFORM = "linux/amd64"
OCI_LAYOUT = "oci-layout"
INDEX = "index.json"
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_UNPACKED_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 16384
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
ZERO = "sha256:" + "0" * 64


class InspectionFailure(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def strict_json(payload: bytes) -> object:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise InspectionFailure("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda value: (_ for _ in ()).throw(
                InspectionFailure("NONFINITE_JSON_NUMBER")
            ),
        )
    except InspectionFailure:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InspectionFailure("INVALID_ARCHIVE_JSON") from error


def validate_digest(value: str, field: str) -> str:
    if len(value) != 71 or not value.startswith("sha256:"):
        raise InspectionFailure("INVALID_" + field.upper())
    if any(char not in "0123456789abcdef" for char in value[7:]):
        raise InspectionFailure("INVALID_" + field.upper())
    return value


def validate_archive_path(name: str) -> str:
    if not name or "\\" in name or name.startswith("/"):
        raise InspectionFailure("ARCHIVE_PATH_TRAVERSAL")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise InspectionFailure("ARCHIVE_PATH_TRAVERSAL")
    return path.as_posix()


def read_member(tar: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if member.size < 0 or member.size > limit:
        raise InspectionFailure("ARCHIVE_MEMBER_OVERSIZE")
    if not member.isreg() or member.issym() or member.islnk() or member.isdev():
        raise InspectionFailure("ARCHIVE_LINK_OR_SPECIAL_MEMBER")
    stream = tar.extractfile(member)
    if stream is None:
        raise InspectionFailure("ARCHIVE_MEMBER_UNREADABLE")
    payload = stream.read(limit + 1)
    if len(payload) != member.size or len(payload) > limit:
        raise InspectionFailure("ARCHIVE_MEMBER_READ_LIMIT")
    return payload


def index_descriptor(index: object, expected_child: str) -> dict[str, object]:
    if not isinstance(index, dict) or index.get("schemaVersion") != 2:
        raise InspectionFailure("OCI_INDEX_INVALID")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise InspectionFailure("OCI_INDEX_MANIFEST_COUNT")
    descriptor = manifests[0]
    if not isinstance(descriptor, dict):
        raise InspectionFailure("OCI_DESCRIPTOR_INVALID")
    if descriptor.get("digest") != expected_child:
        raise InspectionFailure("OCI_CHILD_DIGEST_MISMATCH")
    if descriptor.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE:
        raise InspectionFailure("OCI_CHILD_MEDIA_TYPE_MISMATCH")
    platform = descriptor.get("platform")
    if platform is not None and platform != {"architecture": "amd64", "os": "linux"}:
        raise InspectionFailure("OCI_CHILD_PLATFORM_MISMATCH")
    return descriptor


def inspect_archive(archive: Path, expected_child: str, expected_config: str) -> dict[str, object]:
    expected_child = validate_digest(expected_child, "child_digest")
    expected_config = validate_digest(expected_config, "config_digest")
    try:
        archive_stat = archive.stat()
    except OSError as error:
        raise InspectionFailure("ARCHIVE_UNREADABLE") from error
    if not stat.S_ISREG(archive_stat.st_mode) or archive.is_symlink():
        raise InspectionFailure("ARCHIVE_NOT_REGULAR")
    if archive_stat.st_size > MAX_ARCHIVE_BYTES:
        raise InspectionFailure("ARCHIVE_OVERSIZE")

    members: dict[str, tarfile.TarInfo] = {}
    total_size = 0
    try:
        with tarfile.open(archive, mode="r:*") as tar:
            for member in tar:
                if len(members) >= MAX_ENTRIES:
                    raise InspectionFailure("ARCHIVE_ENTRY_LIMIT")
                name = validate_archive_path(member.name)
                if name in members:
                    raise InspectionFailure("ARCHIVE_DUPLICATE_MEMBER")
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise InspectionFailure("ARCHIVE_MEMBER_OVERSIZE")
                if member.isdir():
                    members[name] = member
                    continue
                if not member.isreg():
                    raise InspectionFailure("ARCHIVE_LINK_OR_SPECIAL_MEMBER")
                total_size += member.size
                if total_size > MAX_UNPACKED_BYTES:
                    raise InspectionFailure("ARCHIVE_UNPACKED_LIMIT")
                members[name] = member
            if OCI_LAYOUT not in members or INDEX not in members:
                raise InspectionFailure("OCI_LAYOUT_OR_INDEX_MISSING")
            layout = strict_json(read_member(tar, members[OCI_LAYOUT], 4096))
            if not isinstance(layout, dict) or layout.get("imageLayoutVersion") != "1.0.0":
                raise InspectionFailure("OCI_LAYOUT_INVALID")
            index = strict_json(read_member(tar, members[INDEX], 1024 * 1024))
            descriptor = index_descriptor(index, expected_child)
            manifest_name = "blobs/sha256/" + expected_child[7:]
            if manifest_name not in members:
                raise InspectionFailure("OCI_MANIFEST_BLOB_MISSING")
            manifest_blob = read_member(tar, members[manifest_name], 4 * 1024 * 1024)
            if digest_bytes(manifest_blob) != expected_child:
                raise InspectionFailure("OCI_MANIFEST_BLOB_DIGEST_MISMATCH")
            if len(manifest_blob) != descriptor.get("size"):
                raise InspectionFailure("OCI_MANIFEST_BLOB_SIZE_MISMATCH")
            manifest = strict_json(manifest_blob)
            if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
                raise InspectionFailure("OCI_MANIFEST_INVALID")
            if manifest.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE:
                raise InspectionFailure("OCI_MANIFEST_MEDIA_TYPE_MISMATCH")
            config = manifest.get("config")
            if not isinstance(config, dict):
                raise InspectionFailure("OCI_CONFIG_DESCRIPTOR_INVALID")
            if config.get("mediaType") != OCI_CONFIG_MEDIA_TYPE:
                raise InspectionFailure("OCI_CONFIG_MEDIA_TYPE_MISMATCH")
            if config.get("digest") != expected_config:
                raise InspectionFailure("OCI_CONFIG_DIGEST_MISMATCH")
            config_name = "blobs/sha256/" + expected_config[7:]
            if config_name not in members:
                raise InspectionFailure("OCI_CONFIG_BLOB_MISSING")
            config_blob = read_member(tar, members[config_name], MAX_MEMBER_BYTES)
            if digest_bytes(config_blob) != expected_config:
                raise InspectionFailure("OCI_CONFIG_BLOB_DIGEST_MISMATCH")
            if len(config_blob) != config.get("size"):
                raise InspectionFailure("OCI_CONFIG_BLOB_SIZE_MISMATCH")
            image_config = strict_json(config_blob)
            if not isinstance(image_config, dict):
                raise InspectionFailure("OCI_CONFIG_INVALID")
            if image_config.get("architecture") != "amd64" or image_config.get("os") != "linux":
                raise InspectionFailure("OCI_CONFIG_PLATFORM_MISMATCH")
            config_section = image_config.get("config")
            if not isinstance(config_section, dict):
                raise InspectionFailure("OCI_CONFIG_SECTION_INVALID")
            if config_section.get("User") not in {"65532", "65532:65532"}:
                raise InspectionFailure("OCI_CONFIG_USER_MISMATCH")
            result: dict[str, object] = {
                "schema": SCHEMA_ID,
                "status": "PASS",
                "error_code": None,
                "platform": PLATFORM,
                "expected_child_digest": expected_child,
                "observed_child_digest": digest_bytes(manifest_blob),
                "manifest_media_type": manifest.get("mediaType"),
                "expected_config_digest": expected_config,
                "observed_config_digest": digest_bytes(config_blob),
                "config_media_type": config.get("mediaType"),
                "config_blob_sha256": digest_bytes(config_blob),
                "config_size": len(config_blob),
                "archive_entries": len(members),
            }
            validate_receipt(result)
            return result
    except InspectionFailure:
        raise
    except (OSError, tarfile.TarError) as error:
        raise InspectionFailure("ARCHIVE_PARSE_FAILED") from error


def validate_receipt(receipt: dict[str, object]) -> None:
    required = {
        "schema",
        "status",
        "error_code",
        "platform",
        "expected_child_digest",
        "observed_child_digest",
        "manifest_media_type",
        "expected_config_digest",
        "observed_config_digest",
        "config_media_type",
        "config_blob_sha256",
        "config_size",
        "archive_entries",
    }
    if set(receipt) != required:
        raise InspectionFailure("ARCHIVE_RECEIPT_SCHEMA_INVALID")
    if receipt["schema"] != SCHEMA_ID or receipt["status"] not in {"PASS", "FAIL"}:
        raise InspectionFailure("ARCHIVE_RECEIPT_SCHEMA_INVALID")
    if receipt["error_code"] is not None and not isinstance(receipt["error_code"], str):
        raise InspectionFailure("ARCHIVE_RECEIPT_SCHEMA_INVALID")
    for name in (
        "expected_child_digest",
        "observed_child_digest",
        "expected_config_digest",
        "observed_config_digest",
        "config_blob_sha256",
    ):
        value = receipt[name]
        if not isinstance(value, str) or not _is_digest(value):
            raise InspectionFailure("ARCHIVE_RECEIPT_SCHEMA_INVALID")
    if receipt["platform"] != PLATFORM:
        raise InspectionFailure("ARCHIVE_RECEIPT_SCHEMA_INVALID")
    if receipt["manifest_media_type"] != OCI_MANIFEST_MEDIA_TYPE:
        raise InspectionFailure("ARCHIVE_RECEIPT_SCHEMA_INVALID")
    if receipt["config_media_type"] != OCI_CONFIG_MEDIA_TYPE:
        raise InspectionFailure("ARCHIVE_RECEIPT_SCHEMA_INVALID")
    if not isinstance(receipt["config_size"], int) or receipt["config_size"] < 0:
        raise InspectionFailure("ARCHIVE_RECEIPT_SCHEMA_INVALID")
    if not isinstance(receipt["archive_entries"], int) or receipt["archive_entries"] < 3:
        raise InspectionFailure("ARCHIVE_RECEIPT_SCHEMA_INVALID")


def failure_receipt(code: str, expected_child: str, expected_config: str) -> dict[str, object]:
    child = expected_child if _is_digest(expected_child) else ZERO
    config = expected_config if _is_digest(expected_config) else ZERO
    return {
        "schema": SCHEMA_ID,
        "status": "FAIL",
        "error_code": code,
        "platform": PLATFORM,
        "expected_child_digest": child,
        "observed_child_digest": ZERO,
        "manifest_media_type": OCI_MANIFEST_MEDIA_TYPE,
        "expected_config_digest": config,
        "observed_config_digest": ZERO,
        "config_media_type": OCI_CONFIG_MEDIA_TYPE,
        "config_blob_sha256": ZERO,
        "config_size": 0,
        "archive_entries": 3,
    }


def _is_digest(value: str) -> bool:
    return (
        len(value) == 71
        and value.startswith("sha256:")
        and all(char in "0123456789abcdef" for char in value[7:])
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-child-digest", required=True)
    parser.add_argument("--expected-config-digest", required=True)
    args = parser.parse_args()
    try:
        result = inspect_archive(
            args.archive, args.expected_child_digest, args.expected_config_digest
        )
        status = 0
    except InspectionFailure as error:
        result = failure_receipt(
            error.code, args.expected_child_digest, args.expected_config_digest
        )
        status = 1
    try:
        validate_receipt(result)
    except InspectionFailure:
        result = failure_receipt(
            "ARCHIVE_RECEIPT_SCHEMA_INVALID",
            args.expected_child_digest,
            args.expected_config_digest,
        )
        status = 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    raise SystemExit(status)


if __name__ == "__main__":
    main()
