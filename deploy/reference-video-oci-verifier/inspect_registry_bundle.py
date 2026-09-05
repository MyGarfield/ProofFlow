"""Inspect an image manifest/config bundle served by a localhost Registry v2."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from http.client import HTTPMessage
from typing import IO, cast
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

SCHEMA_ID = "proofflow.reference-runtime-oci-verifier.registry-bundle-inspection.v1"
PLATFORM = "linux/amd64"
ZERO = "sha256:" + "0" * 64
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024 * 1024
MAX_LAYERS = 512
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
CONFIG_MEDIA_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}


class BundleFailure(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def strict_json(raw: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise BundleFailure("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                BundleFailure("NONFINITE_JSON_NUMBER")
            ),
        )
    except BundleFailure:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BundleFailure("INVALID_BUNDLE_JSON") from error


def digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise BundleFailure(code)
    return value


def validate_endpoint(endpoint: str, repository: str) -> str:
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path.rstrip("/") != "/v2"
    ):
        raise BundleFailure("REGISTRY_ENDPOINT_NOT_LOOPBACK")
    parts = repository.split("/")
    if (
        parsed.query
        or parsed.fragment
        or "//" in repository
        or any(part in {"", ".", ".."} for part in parts)
        or not REPOSITORY_RE.fullmatch(repository)
    ):
        raise BundleFailure("REGISTRY_REPOSITORY_INVALID")
    return endpoint.rstrip("/") + "/" + repository


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        raise BundleFailure("REGISTRY_REDIRECT_FORBIDDEN")


def fetch_bytes(url: str, limit: int, expected_content_types: set[str]) -> bytes:
    opener = build_opener(ProxyHandler({}), _NoRedirect)
    try:
        with opener.open(
            Request(url, headers={"Accept": ", ".join(MANIFEST_MEDIA_TYPES)}), timeout=20
        ) as response:
            if response.status != 200:
                raise BundleFailure("REGISTRY_HTTP_STATUS")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip()
            if content_type not in expected_content_types:
                raise BundleFailure("REGISTRY_CONTENT_TYPE_INVALID")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > limit:
                raise BundleFailure("REGISTRY_OUTPUT_LIMIT")
            body = cast(bytes, response.read(limit + 1))
    except BundleFailure:
        raise
    except Exception as error:
        raise BundleFailure("REGISTRY_FETCH_FAILED") from error
    if len(body) > limit:
        raise BundleFailure("REGISTRY_OUTPUT_LIMIT")
    return body


def inspect_registry_bundle(
    endpoint: str, repository: str, expected_child: str, expected_config: str
) -> dict[str, object]:
    expected_child = require_digest(expected_child, "INVALID_CHILD_DIGEST")
    expected_config = require_digest(expected_config, "INVALID_CONFIG_DIGEST")
    base = validate_endpoint(endpoint, repository)
    manifest_body = fetch_bytes(
        f"{base}/manifests/{expected_child}", MAX_MANIFEST_BYTES, MANIFEST_MEDIA_TYPES
    )
    if digest_bytes(manifest_body) != expected_child:
        raise BundleFailure("MANIFEST_DIGEST_MISMATCH")
    manifest = strict_json(manifest_body)
    if not isinstance(manifest, dict):
        raise BundleFailure("MANIFEST_NOT_OBJECT")
    required = {"schemaVersion", "mediaType", "config", "layers"}
    allowed = required | {"annotations", "artifactType", "subject"}
    if set(manifest) - allowed or not required <= set(manifest) or manifest["schemaVersion"] != 2:
        raise BundleFailure("MANIFEST_KEYSET_INVALID")
    media_type = manifest["mediaType"]
    if media_type not in MANIFEST_MEDIA_TYPES:
        raise BundleFailure("MANIFEST_MEDIA_TYPE_INVALID")
    config_descriptor = manifest["config"]
    if not isinstance(config_descriptor, dict) or set(config_descriptor) - {
        "mediaType",
        "digest",
        "size",
        "annotations",
    }:
        raise BundleFailure("CONFIG_DESCRIPTOR_KEYSET_INVALID")
    if config_descriptor.get("mediaType") not in CONFIG_MEDIA_TYPES:
        raise BundleFailure("CONFIG_MEDIA_TYPE_INVALID")
    if config_descriptor.get("digest") != expected_config:
        raise BundleFailure("CONFIG_DIGEST_MISMATCH")
    if not isinstance(config_descriptor.get("size"), int) or config_descriptor["size"] < 0:
        raise BundleFailure("CONFIG_SIZE_INVALID")
    layers = manifest["layers"]
    if not isinstance(layers, list):
        raise BundleFailure("LAYER_LIST_INVALID")
    if len(layers) > MAX_LAYERS:
        raise BundleFailure("LAYER_COUNT_LIMIT")
    layer_digests: list[str] = []
    for layer in layers:
        if not isinstance(layer, dict) or set(layer) - {
            "mediaType",
            "digest",
            "size",
            "annotations",
        }:
            raise BundleFailure("LAYER_DESCRIPTOR_KEYSET_INVALID")
        if layer.get("mediaType") not in LAYER_MEDIA_TYPES:
            raise BundleFailure("LAYER_MEDIA_TYPE_INVALID")
        layer_digests.append(require_digest(layer.get("digest"), "LAYER_DIGEST_INVALID"))
        if not isinstance(layer.get("size"), int) or layer["size"] < 0:
            raise BundleFailure("LAYER_SIZE_INVALID")
    if len(set(layer_digests)) != len(layer_digests):
        raise BundleFailure("LAYER_DUPLICATE_DIGEST")
    if config_descriptor["size"] > MAX_CONFIG_BYTES:
        raise BundleFailure("CONFIG_SIZE_LIMIT")
    config_body = fetch_bytes(
        f"{base}/blobs/{expected_config}",
        MAX_CONFIG_BYTES,
        CONFIG_MEDIA_TYPES | {"application/octet-stream"},
    )
    if digest_bytes(config_body) != expected_config:
        raise BundleFailure("CONFIG_BLOB_DIGEST_MISMATCH")
    if len(config_body) != config_descriptor["size"]:
        raise BundleFailure("CONFIG_BLOB_SIZE_MISMATCH")
    image_config = strict_json(config_body)
    if (
        not isinstance(image_config, dict)
        or image_config.get("architecture") != "amd64"
        or image_config.get("os") != "linux"
    ):
        raise BundleFailure("CONFIG_PLATFORM_MISMATCH")
    config_section = image_config.get("config")
    if not isinstance(config_section, dict) or config_section.get("User") not in {
        "65532",
        "65532:65532",
    }:
        raise BundleFailure("CONFIG_USER_MISMATCH")
    return {
        "schema": SCHEMA_ID,
        "status": "PASS",
        "error_code": None,
        "platform": PLATFORM,
        "expected_child_digest": expected_child,
        "observed_child_digest": digest_bytes(manifest_body),
        "manifest_media_type": media_type,
        "expected_config_digest": expected_config,
        "observed_config_digest": digest_bytes(config_body),
        "config_media_type": config_descriptor["mediaType"],
        "config_size": len(config_body),
        "layer_count": len(layer_digests),
    }


def failure_receipt(code: str) -> dict[str, object]:
    return {
        "schema": SCHEMA_ID,
        "status": "FAIL",
        "error_code": code,
        "platform": PLATFORM,
        "expected_child_digest": ZERO,
        "observed_child_digest": ZERO,
        "manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
        "expected_config_digest": ZERO,
        "observed_config_digest": ZERO,
        "config_media_type": "application/vnd.oci.image.config.v1+json",
        "config_size": 0,
        "layer_count": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--expected-child-digest", required=True)
    parser.add_argument("--expected-config-digest", required=True)
    args = parser.parse_args()
    try:
        result = inspect_registry_bundle(
            args.registry, args.repository, args.expected_child_digest, args.expected_config_digest
        )
        status = 0
    except BundleFailure as error:
        result = failure_receipt(error.code)
        status = 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    raise SystemExit(status)


if __name__ == "__main__":
    main()
