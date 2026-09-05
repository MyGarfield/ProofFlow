"""Validate the exact wheel set used by the network-disabled image build."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any

SCHEMA = "proofflow.reference-video.python-wheel-closure.v1"
BASE_IMAGE_DIGEST = "sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb"
MAX_FILES = 32
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
WHEEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.whl$")


class WheelFailure(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _strict_json(raw: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise WheelFailure("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                WheelFailure("NONFINITE_JSON_NUMBER")
            ),
        )
    except WheelFailure:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WheelFailure("INVALID_LOCK_JSON") from error


def _exact_keys(value: object, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise WheelFailure(code)
    return value


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise WheelFailure("WHEEL_UNREADABLE") from error
    return "sha256:" + digest.hexdigest()


def validate_lock(document: object) -> dict[str, Any]:
    lock = _exact_keys(
        document,
        {
            "schema",
            "base_image",
            "python_version",
            "platform",
            "availability",
            "file_count",
            "total_bytes",
            "files",
        },
        "LOCK_KEYSET_INVALID",
    )
    if lock["schema"] != SCHEMA:
        raise WheelFailure("LOCK_SCHEMA_INVALID")
    if lock["base_image"] != BASE_IMAGE_DIGEST:
        raise WheelFailure("BASE_IMAGE_DIGEST_MISMATCH")
    if lock["python_version"] != "3.12" or lock["platform"] != "linux/amd64-musllinux_1_2":
        raise WheelFailure("LOCK_PLATFORM_INVALID")
    if lock["availability"] != "UNKNOWN":
        raise WheelFailure("AVAILABILITY_MUST_REMAIN_UNKNOWN")
    files = lock["files"]
    if not isinstance(files, list) or not files or len(files) > MAX_FILES:
        raise WheelFailure("WHEEL_COUNT_LIMIT")
    if lock["file_count"] != len(files):
        raise WheelFailure("WHEEL_COUNT_MISMATCH")
    filenames: set[str] = set()
    projects: set[str] = set()
    total = 0
    last = ""
    for raw_file in files:
        wheel = _exact_keys(
            raw_file,
            {"project", "version", "filename", "size", "sha256"},
            "WHEEL_KEYSET_INVALID",
        )
        filename = wheel["filename"]
        if not isinstance(filename, str) or WHEEL_RE.fullmatch(filename) is None:
            raise WheelFailure("WHEEL_FILENAME_INVALID")
        if filename in filenames or filename <= last:
            raise WheelFailure("WHEEL_FILENAME_ORDER_OR_DUPLICATE")
        filenames.add(filename)
        last = filename
        project = wheel["project"]
        version = wheel["version"]
        if not isinstance(project, str) or not project or project in projects:
            raise WheelFailure("WHEEL_PROJECT_INVALID")
        projects.add(project)
        if not isinstance(version, str) or not version:
            raise WheelFailure("WHEEL_VERSION_INVALID")
        size = wheel["size"]
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_FILE_BYTES:
            raise WheelFailure("WHEEL_SIZE_INVALID")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise WheelFailure("WHEEL_TOTAL_SIZE_LIMIT")
        digest = wheel["sha256"]
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise WheelFailure("WHEEL_DIGEST_INVALID")
    if lock["total_bytes"] != total:
        raise WheelFailure("WHEEL_TOTAL_SIZE_MISMATCH")
    return lock


def load_lock(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise WheelFailure("LOCK_FILE_INVALID")
        return validate_lock(_strict_json(path.read_bytes()))
    except WheelFailure:
        raise
    except OSError as error:
        raise WheelFailure("LOCK_FILE_UNREADABLE") from error


def verify(directory: Path, lock: dict[str, Any]) -> None:
    expected = {item["filename"] for item in lock["files"]}
    actual: set[str] = set()
    try:
        for path in directory.iterdir():
            if path.is_symlink() or not path.is_file():
                raise WheelFailure("WHEEL_MEMBER_NOT_REGULAR")
            actual.add(path.name)
    except WheelFailure:
        raise
    except OSError as error:
        raise WheelFailure("WHEEL_DIRECTORY_UNREADABLE") from error
    if actual != expected:
        raise WheelFailure("WHEEL_MEMBER_SET_MISMATCH")
    records = {item["filename"]: item for item in lock["files"]}
    for filename in sorted(actual):
        path = directory / filename
        record = records[filename]
        if path.stat().st_size != record["size"] or _digest(path) != record["sha256"]:
            raise WheelFailure("WHEEL_BYTES_MISMATCH")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    try:
        lock = load_lock(args.lock)
        verify(args.directory, lock)
        result = {
            "schema": SCHEMA,
            "status": "PASS",
            "file_count": lock["file_count"],
            "total_bytes": lock["total_bytes"],
            "availability": "UNKNOWN",
        }
        status = 0
    except WheelFailure as error:
        result = {"schema": SCHEMA, "status": "FAIL", "error_code": error.code}
        status = 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    raise SystemExit(status)


if __name__ == "__main__":
    main()
