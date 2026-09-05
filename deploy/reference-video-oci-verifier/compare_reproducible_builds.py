"""Write a closed, integrity-bound receipt for two clean image builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

SCHEMA = "proofflow.reference-video.build-reproducibility.v1"
SOURCE_DATE_EPOCH = 1788519180
REPOSITORY = "localhost:5000/proofflow-reference-video-verifier"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FRONTEND = "sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
BUILDKIT_IMAGE = "sha256:57269d1784e49b46228c45a1a1b870fbe40e0a639ab60b37b032d83af5bccdfc"
EXPORTER = (
    "type=image,rewrite-timestamp=true,unpack=false,oci-mediatypes=false,"
    "compression=gzip,force-compression=true,compatibility-version=30,provenance=false"
)


class ComparisonFailure(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _digest(value: str) -> str:
    if DIGEST_RE.fullmatch(value) is None:
        raise ComparisonFailure("DIGEST_INVALID")
    return value


def _text(value: str, limit: int) -> str:
    if not value or len(value) > limit or any(ord(char) < 32 for char in value):
        raise ComparisonFailure("BUILDER_IDENTITY_INVALID")
    return value


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def make_receipt(
    *,
    child_a: str,
    config_a: str,
    child_b: str,
    config_b: str,
    docker_client: str,
    docker_server: str,
    buildx: str,
    buildkit: str,
) -> dict[str, object]:
    child_a = _digest(child_a)
    config_a = _digest(config_a)
    child_b = _digest(child_b)
    config_b = _digest(config_b)
    if child_a == config_a or child_b == config_b:
        raise ComparisonFailure("IMAGE_DIGEST_CONFIG_COLLISION")
    matches = child_a == child_b and config_a == config_b
    receipt: dict[str, object] = {
        "schema": SCHEMA,
        "status": "PASS" if matches else "FAIL",
        "error_code": None if matches else "IMAGE_REPRODUCIBILITY_MISMATCH",
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "builds": [
            {
                "name": "a",
                "image_ref": f"{REPOSITORY}@{child_a}",
                "child_digest": child_a,
                "config_digest": config_a,
            },
            {
                "name": "b",
                "image_ref": f"{REPOSITORY}@{child_b}",
                "child_digest": child_b,
                "config_digest": config_b,
            },
        ],
        "builder": {
            "docker_client": _text(docker_client, 200),
            "docker_server": _text(docker_server, 200),
            "buildx": _text(buildx, 300),
            "buildkit": _text(buildkit, 100),
            "buildkit_image": BUILDKIT_IMAGE,
            "dockerfile_frontend": FRONTEND,
            "exporter": EXPORTER,
        },
    }
    receipt["integrity"] = {
        "algorithm": "sha256-canonical-json-excluding-integrity",
        "payload_sha256": "sha256:" + hashlib.sha256(canonical_json(receipt)).hexdigest(),
    }
    return receipt


def write_once(path: Path, receipt: dict[str, object]) -> None:
    try:
        parent = path.parent
        parent_info = parent.lstat()
        if parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode):
            raise ComparisonFailure("OUTPUT_PARENT_INVALID")
        if path.exists() or path.is_symlink():
            raise ComparisonFailure("OUTPUT_ALREADY_EXISTS")
        payload = json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n"
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except ComparisonFailure:
        raise
    except OSError as error:
        raise ComparisonFailure("OUTPUT_WRITE_FAILED") from error


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--child-a", required=True)
    parser.add_argument("--config-a", required=True)
    parser.add_argument("--child-b", required=True)
    parser.add_argument("--config-b", required=True)
    parser.add_argument("--docker-client", required=True)
    parser.add_argument("--docker-server", required=True)
    parser.add_argument("--buildx", required=True)
    parser.add_argument("--buildkit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = make_receipt(
            child_a=args.child_a,
            config_a=args.config_a,
            child_b=args.child_b,
            config_b=args.config_b,
            docker_client=args.docker_client,
            docker_server=args.docker_server,
            buildx=args.buildx,
            buildkit=args.buildkit,
        )
        write_once(args.output, receipt)
    except ComparisonFailure as error:
        print(f"proofflow reproducibility: {error.code}", file=__import__("sys").stderr)
        raise SystemExit(2) from error
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if receipt["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
