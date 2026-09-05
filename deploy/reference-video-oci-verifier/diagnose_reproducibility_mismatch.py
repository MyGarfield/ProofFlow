"""Emit path-free, value-free diagnostics for two local-registry images."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

from inspect_registry_bundle import (
    CONFIG_MEDIA_TYPES,
    MANIFEST_MEDIA_TYPES,
    MAX_CONFIG_BYTES,
    MAX_MANIFEST_BYTES,
    digest_bytes,
    fetch_bytes,
    require_digest,
    strict_json,
)

REGISTRY = "http://127.0.0.1:5000/v2/proofflow-reference-video-verifier"


def canonical_digest(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def differing_indexes(left: object, right: object) -> list[int]:
    if not isinstance(left, list) or not isinstance(right, list):
        return [-1]
    maximum = max(len(left), len(right))
    return [
        index
        for index in range(maximum)
        if index >= len(left) or index >= len(right) or left[index] != right[index]
    ]


def fetch_image(child: str, config: str) -> tuple[dict[str, Any], dict[str, Any]]:
    child = require_digest(child, "CHILD_DIGEST_INVALID")
    config = require_digest(config, "CONFIG_DIGEST_INVALID")
    manifest_body = fetch_bytes(
        f"{REGISTRY}/manifests/{child}", MAX_MANIFEST_BYTES, MANIFEST_MEDIA_TYPES
    )
    if digest_bytes(manifest_body) != child:
        raise ValueError("manifest digest mismatch")
    manifest = strict_json(manifest_body)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("config"), dict):
        raise ValueError("manifest invalid")
    if manifest["config"].get("digest") != config:
        raise ValueError("config descriptor mismatch")
    config_body = fetch_bytes(
        f"{REGISTRY}/blobs/{config}",
        MAX_CONFIG_BYTES,
        CONFIG_MEDIA_TYPES | {"application/octet-stream"},
    )
    if digest_bytes(config_body) != config:
        raise ValueError("config digest mismatch")
    config_document = strict_json(config_body)
    if not isinstance(config_document, dict):
        raise ValueError("config invalid")
    return manifest, config_document


def summarize(
    manifest_a: dict[str, Any],
    config_a: dict[str, Any],
    manifest_b: dict[str, Any],
    config_b: dict[str, Any],
) -> dict[str, object]:
    keys = sorted(set(config_a) | set(config_b))
    differing_keys = [key for key in keys if config_a.get(key) != config_b.get(key)]
    field_hashes = {
        key: {"a": canonical_digest(config_a.get(key)), "b": canonical_digest(config_b.get(key))}
        for key in differing_keys
    }
    rootfs_a = config_a.get("rootfs")
    rootfs_b = config_b.get("rootfs")
    diff_ids_a = rootfs_a.get("diff_ids") if isinstance(rootfs_a, dict) else None
    diff_ids_b = rootfs_b.get("diff_ids") if isinstance(rootfs_b, dict) else None
    return {
        "schema": "proofflow.reference-video.build-reproducibility-diagnostic.v1",
        "manifest_layer_indexes": differing_indexes(
            manifest_a.get("layers"), manifest_b.get("layers")
        ),
        "config_keys": differing_keys,
        "config_field_hashes": field_hashes,
        "rootfs_diff_id_indexes": differing_indexes(diff_ids_a, diff_ids_b),
        "history_indexes": differing_indexes(config_a.get("history"), config_b.get("history")),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--child-a", required=True)
    parser.add_argument("--config-a", required=True)
    parser.add_argument("--child-b", required=True)
    parser.add_argument("--config-b", required=True)
    args = parser.parse_args()
    try:
        manifest_a, config_a = fetch_image(args.child_a, args.config_a)
        manifest_b, config_b = fetch_image(args.child_b, args.config_b)
        result = summarize(manifest_a, config_a, manifest_b, config_b)
    except Exception as error:
        print("proofflow reproducibility diagnostic: CLOSED_FAILURE", file=sys.stderr)
        raise SystemExit(2) from error
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
