from __future__ import annotations

import hashlib
import http.server
import io
import json
import re
import stat
import sys
import tarfile
import threading
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

OCI = Path(__file__).parents[2] / "deploy/reference-video-oci-verifier"
sys.path.insert(0, str(OCI))

import build_identity  # noqa: E402
import compare_reproducible_builds  # noqa: E402
import fetch_apk_closure  # noqa: E402
import inspect_oci_archive  # noqa: E402
import inspect_registry_bundle  # noqa: E402
import runner  # noqa: E402
import verify_wheel_closure  # noqa: E402
import write_receipt  # noqa: E402

EVIDENCE = Path(__file__).parents[2] / "reference-video/evidence"
sys.path.insert(0, str(EVIDENCE))
from policy import (  # noqa: E402
    CGROUP_LIMITS,
    FIXED_PATH,
    INTERNAL_PATHS,
    validate_image_metadata,
    validate_mount_contract,
    validate_runtime_contract,
    validate_tool_paths,
)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def test_dockerfile_pins_current_amd64_child_and_build_inputs() -> None:
    dockerfile = (OCI / "Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.startswith(
        "# syntax=docker/dockerfile:1.7@sha256:"
        "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
    )
    assert "FROM --platform=linux/amd64 python:3.12-alpine@sha256:78e987" in dockerfile
    assert "ARG ARTIFACT_COMMIT=290ef94caf96cf3f1e4568cf8f19a52a8b460bc0" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "ALPINE_PACKAGES.lock" in dockerfile
    assert "APK_CLOSURE_LOCK_SHA256" in dockerfile
    assert "WHEEL_CLOSURE_LOCK_SHA256" in dockerfile
    assert "from=verifier_inputs" in dockerfile
    assert "apk --no-network add" in dockerfile
    assert "--no-index" in dockerfile
    assert "/opt/proofflow-inputs/v3.24/main/x86_64/*.apk" in dockerfile
    assert "/opt/proofflow-inputs/v3.24/community/x86_64/*.apk" in dockerfile
    assert "APKINDEX" not in dockerfile
    assert "dl-cdn.alpinelinux.org" not in dockerfile
    assert "--allow-untrusted" not in dockerfile
    assert "ARG SOURCE_DATE_EPOCH=1788519180" in dockerfile
    assert "--no-compile" in dockerfile
    assert "rm -f /var/log/apk.log /var/cache/fontconfig/*" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["/usr/local/bin/python3.12", "/opt/proofflow/runner.py"]' in dockerfile
    assert "COPY deploy/reference-video-oci-verifier/receipt.schema.json" in dockerfile
    launcher = (OCI / "run.sh").read_text(encoding="utf-8")
    assert "{{.Descriptor.digest}}" not in launcher
    assert "RepoDigests" in launcher
    assert "save --platform linux/amd64" in launcher
    assert 'image inspect "$IMAGE_REF"' in launcher
    assert "image inspect --platform" not in launcher
    assert "IMAGE_REPO_DIGEST_NOT_CONFIRMED" in launcher
    assert "IMAGE_ARCHIVE_PIN_MISMATCH" in launcher
    assert "IMAGE_REGISTRY_BUNDLE_PIN_MISMATCH" in launcher
    assert "REGISTRY_BUNDLE_ARGUMENTS_MUST_BE_PAIRED" in launcher
    assert "IMAGE_ID_INVALID" in launcher
    assert "IMAGE_STORE_IDENTITY_DIGEST_MISMATCH" in launcher
    assert '"$IMAGE_ID" != "$EXPECTED_IMAGE_CONFIG_DIGEST"' in launcher
    assert '"$IMAGE_ID" != "$EXPECTED_IMAGE_DIGEST"' in launcher
    assert "REPO_DIGEST_MATCH=false" in launcher
    assert 'case "$IMAGE_REPO_DIGESTS" in *"$IMAGE_REF"*' not in launcher
    result = __import__("subprocess").run(
        [
            "/bin/sh",
            str(OCI / "run.sh"),
            "--image",
            "localhost:5000/fixture@sha256:" + "a" * 64,
            "--registry-bundle-url",
            "http://127.0.0.1:5000/v2",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "REGISTRY_BUNDLE_ARGUMENTS_MUST_BE_PAIRED" in result.stderr


def test_launcher_has_all_fail_closed_docker_options() -> None:
    launcher = (OCI / "run.sh").read_text(encoding="utf-8")
    for option in (
        "--platform linux/amd64",
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges:true",
        "--user 65532:65532",
        "--cpus 1",
        "--memory 536870912",
        "--memory-swap 536870912",
        "--pids-limit 128",
        "--ulimit nofile=1024:1024",
        "dst=/input/reference-video,ro",
        "dst=/input/repo,ro",
        "--pull=never",
    ):
        assert option in launcher
    assert "docker.sock" not in launcher
    assert "--privileged" not in launcher
    assert "--security-opt seccomp=default" not in launcher
    assert "/bin/rm -rf" in launcher
    assert "/bin/cat" in launcher


def test_runner_executes_ocr_only_through_the_trusted_validator() -> None:
    source = (OCI / "runner.py").read_text(encoding="utf-8")
    assert "VALIDATOR_TIMEOUT_SECONDS = 420" in source
    assert "def ocr_check" not in source
    assert '"code": "OCR_EXECUTION_OBSERVED"' in source
    assert '"ocr_parity": "UNKNOWN"' in source


def test_github_oci_workflow_is_pinned_local_only_and_path_filtered() -> None:
    workflow = (Path(__file__).parents[2] / ".github/workflows/reference-video-oci.yml").read_text(
        encoding="utf-8"
    )
    uses = re.findall(r"uses:\s+([^\s#]+)", workflow)
    assert uses
    assert all(re.search(r"@[0-9a-f]{40}$", value) for value in uses)
    assert "fetch-depth: 0" in workflow
    assert "persist-credentials: false" in workflow
    assert '"reference-video/**"' in workflow
    assert '"deploy/reference-video-oci-verifier/**"' in workflow
    assert (
        "registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
        in workflow
    )
    assert "localhost:5000" in workflow
    assert "docker login" not in workflow
    assert "ghcr.io" not in workflow
    assert "secrets." not in workflow
    assert "retention-days: 3" in workflow
    assert "docker rm --force" in workflow
    assert "prepare_verifier_inputs.sh" in workflow
    assert "--network=none" in workflow
    assert '--build-context verifier_inputs="$PROOFFLOW_VERIFIER_INPUTS"' in workflow
    assert "docker buildx build --no-cache --provenance=false" in workflow
    assert "SOURCE_DATE_EPOCH=1788519180" in workflow
    assert "rewrite-timestamp=true" in workflow
    assert (
        "uv run python deploy/reference-video-oci-verifier/compare_reproducible_builds.py"
        in workflow
    )
    assert "repro-a" in workflow and "repro-b" in workflow
    assert "proofflow-reference-video-build-reproducibility-${{ github.run_id }}" in workflow
    assert "git clone --no-local --no-hardlinks" in workflow
    assert "checkout --detach" in workflow
    assert "rev-parse HEAD" in workflow
    assert 'git -C "$DETACHED_REPO" status --porcelain' in workflow
    assert 'sudo chown -R -- 65532:65532 "$DETACHED_REPO"' in workflow
    assert "stat -c '%u:%g' \"$DETACHED_REPO\"" in workflow
    assert "PROOFFLOW_REPO_ROOT" in workflow
    assert "sudo rm -rf --" in workflow
    assert '"$RUNNER_TEMP/proofflow-detached-repo"' in workflow
    assert '"$RUNNER_TEMP/proofflow-build-reproducibility.json"' in workflow
    assert '"$RUNNER_TEMP/proofflow-verifier-input-parent"' in workflow


def test_mutable_tag_is_not_an_image_reference() -> None:
    import policy

    with pytest.raises(ValueError, match="sha256 child digest"):
        policy.parse_image_reference("registry.invalid/proofflow:latest")
    with pytest.raises(ValueError, match="sha256 child digest"):
        policy.parse_image_reference("registry.invalid/proofflow:0.1.0@sha256:" + "a" * 64)


def test_wrong_child_architecture_and_local_image_without_repo_digest_fail() -> None:
    metadata = {
        "Architecture": "arm64",
        "Os": "linux",
        "Id": "sha256:" + "a" * 64,
        "Descriptor.digest": "sha256:" + "a" * 64,
        "Config.User": "65532:65532",
        "RepoDigests": ["ghcr.io/mygarfield/proofflow@sha256:" + "a" * 64],
    }
    with pytest.raises(ValueError, match="architecture"):
        validate_image_metadata(
            metadata,
            image_ref="ghcr.io/mygarfield/proofflow@sha256:" + "a" * 64,
            expected_image_digest="sha256:" + "a" * 64,
            expected_config_digest="sha256:" + "b" * 64,
        )
    metadata["Architecture"] = "amd64"
    metadata["RepoDigests"] = []
    with pytest.raises(ValueError, match="RepoDigests"):
        validate_image_metadata(
            metadata,
            image_ref="ghcr.io/mygarfield/proofflow@sha256:" + "a" * 64,
            expected_image_digest="sha256:" + "a" * 64,
            expected_config_digest="sha256:" + "b" * 64,
        )
    with pytest.raises(ValueError, match="separate"):
        validate_image_metadata(
            {**metadata, "RepoDigests": ["ghcr.io/mygarfield/proofflow@sha256:" + "a" * 64]},
            image_ref="ghcr.io/mygarfield/proofflow@sha256:" + "a" * 64,
            expected_image_digest="sha256:" + "a" * 64,
            expected_config_digest="sha256:" + "a" * 64,
        )


def _mountinfo(*, writable: bool = False) -> str:
    root_mode = "rw" if writable else "ro"
    return "\n".join(
        (
            f"36 29 0:32 / / {root_mode},relatime - overlay overlay rw",
            "37 36 0:33 / /input/reference-video ro,relatime - bind /dev/sda ro",
            "38 36 0:34 / /input/repo ro,relatime - bind /dev/sdb ro",
        )
    )


def test_writable_root_or_artifact_mount_is_rejected() -> None:
    with pytest.raises(ValueError, match="read-only"):
        validate_mount_contract(_mountinfo(writable=True))
    with pytest.raises(ValueError, match="read-only"):
        validate_mount_contract(
            _mountinfo().replace("/input/reference-video ro", "/input/reference-video rw")
        )


def test_root_caps_nnp_network_and_resource_drift_are_rejected() -> None:
    kwargs = {
        "uid": 65532,
        "gid": 65532,
        "path": FIXED_PATH,
        "no_docker_socket": True,
        "rootfs_read_only": True,
        "cap_drop_all": True,
        "no_new_privileges": True,
        "network_none": True,
        "limits": CGROUP_LIMITS,
    }
    validate_runtime_contract(**kwargs)
    for field, value in (
        ("uid", 0),
        ("cap_drop_all", False),
        ("no_new_privileges", False),
        ("network_none", False),
        ("limits", {**CGROUP_LIMITS, "pids": "max"}),
    ):
        changed = {**kwargs, field: value}
        with pytest.raises(ValueError):
            validate_runtime_contract(**changed)


def test_capability_masks_accept_leading_zero_hex_values_only_when_numeric_zero() -> None:
    assert runner.capability_mask_is_zero("0000000000000000")
    assert runner.capability_mask_is_zero("0000000000000001") is False
    assert runner.capability_mask_is_zero("not-hex") is False


def test_validator_requires_external_identity_and_digest_as_a_pair() -> None:
    command = [
        sys.executable,
        str(EVIDENCE / "validate_manifest.py"),
        "--expected-schema-sha256",
        "sha256:" + "a" * 64,
        "--expected-validator-sha256",
        "sha256:" + "b" * 64,
        "--expected-artifact-commit",
        "a" * 40,
        "--trusted-git-root",
        "/tmp",
        "--git-binary",
        "/usr/bin/git",
        "--ffprobe",
        "/usr/bin/ffprobe",
        "--ffmpeg",
        "/usr/bin/ffmpeg",
        "--tesseract",
        "/usr/bin/tesseract",
        "--verification-toolchain-identity",
        "/tmp/toolchain.json",
    ]
    result = __import__("subprocess").run(command, capture_output=True, text=True)
    assert result.returncode != 0
    assert "must be provided together" in result.stderr


def test_fake_tools_and_host_path_lookup_are_rejected() -> None:
    with pytest.raises(ValueError, match="fixed absolute"):
        validate_tool_paths({**INTERNAL_PATHS, "ffmpeg": "ffmpeg"})
    with pytest.raises(ValueError, match="fixed absolute"):
        validate_tool_paths({**INTERNAL_PATHS, "tesseract": "/tmp/fake-tesseract"})


@pytest.mark.skipif(not Path("/usr/bin/git").is_file(), reason="fixed Git path is unavailable")
def test_git_tool_version_uses_double_dash_version() -> None:
    version = runner.tool_version("git", "/usr/bin/git")
    assert version.startswith("git version ")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("PROOFFLOW_EXPECTED_ARTIFACT_COMMIT", "f" * 39 + "g"),
        ("PROOFFLOW_EXPECTED_SCHEMA_SHA256", "sha256:" + "g" * 64),
        ("PROOFFLOW_EXPECTED_VALIDATOR_SHA256", "sha256:" + "g" * 64),
    ],
)
def test_wrong_commit_schema_or_validator_pin_is_rejected(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    values = {
        "PROOFFLOW_EXPECTED_ARTIFACT_COMMIT": "a" * 40,
        "PROOFFLOW_EXPECTED_MANIFEST_SHA256": "sha256:" + "b" * 64,
        "PROOFFLOW_EXPECTED_SCHEMA_SHA256": "sha256:" + "c" * 64,
        "PROOFFLOW_EXPECTED_VALIDATOR_SHA256": "sha256:" + "d" * 64,
        "PROOFFLOW_EXPECTED_IMAGE_DIGEST": "sha256:" + "e" * 64,
        "PROOFFLOW_EXPECTED_IMAGE_CONFIG_DIGEST": "sha256:" + "f" * 64,
    }
    for key, expected in values.items():
        monkeypatch.setenv(key, expected)
    monkeypatch.setenv(name, value)
    with pytest.raises(runner.RunnerFailure, match="EXPECTED_PIN_INVALID"):
        runner.required_env()


def test_bounded_runner_kills_timeout_and_output_exhaustion() -> None:
    timeout = runner.bounded_run(
        [sys.executable, "-c", "import time; time.sleep(5)"], timeout=1, max_bytes=1024
    )
    assert timeout["status"] == "FAIL"
    assert timeout["code"] == "TIMEOUT"
    output = runner.bounded_run(
        [sys.executable, "-c", "print('x' * 10000)"], timeout=5, max_bytes=1024
    )
    assert output["status"] == "FAIL"
    assert output["code"] == "OUTPUT_LIMIT_EXCEEDED"


def test_receipt_schema_is_closed_and_tamper_integrity_is_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema_path = OCI / "receipt.schema.json"
    monkeypatch.setattr(runner, "RECEIPT_SCHEMA_PATH", schema_path)
    monkeypatch.setattr(runner, "RECEIPT_SCHEMA_SHA256", digest(schema_path))
    receipt = runner.safe_failure_receipt("EXPECTED_PIN_INVALID")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(receipt)
    assert runner.verify_receipt(receipt)
    tampered = json.loads(json.dumps(receipt))
    tampered["overall_status"] = "PASS"
    assert not runner.verify_receipt(tampered)
    tampered["unknown"] = "attacker"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(tampered)


def test_receipt_has_no_host_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    schema_path = OCI / "receipt.schema.json"
    monkeypatch.setattr(runner, "RECEIPT_SCHEMA_PATH", schema_path)
    monkeypatch.setattr(runner, "RECEIPT_SCHEMA_SHA256", digest(schema_path))
    receipt = runner.safe_failure_receipt("CONTAINER_NOT_STARTED")
    serialized = json.dumps(receipt)
    assert "/Users/" not in serialized
    assert "/home/" not in serialized
    assert "docker.sock" not in serialized


def test_font_identity_fixture_requires_exact_four_nonempty_files(tmp_path: Path) -> None:
    font_root = tmp_path / "noto"
    font_root.mkdir()
    for name in (
        "NotoSansCJK-Bold.ttc",
        "NotoSansCJK-Regular.ttc",
        "NotoSerifCJK-Bold.ttc",
        "NotoSerifCJK-Regular.ttc",
    ):
        (font_root / name).write_bytes(name.encode())
    inventory = build_identity.fixed_font_inventory(str(font_root))
    assert inventory["root"] == str(font_root)
    assert inventory["file_count"] == 4
    assert inventory["sha256"] != "sha256:" + "0" * 64
    (font_root / "unexpected.ttc").write_bytes(b"drift")
    with pytest.raises(RuntimeError, match="font inventory"):
        build_identity.fixed_font_inventory(str(font_root))


def test_receipt_install_is_no_overwrite_and_no_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    destination = tmp_path / "receipt.json"
    source.write_bytes(b'{"overall_status":"FAIL"}\n')
    write_receipt.install(source, destination)
    assert destination.read_bytes() == source.read_bytes()
    with pytest.raises(FileExistsError):
        write_receipt.install(source, destination)
    linked_target = tmp_path / "linked-target.json"
    linked_target.write_bytes(b"attacker")
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(linked_target)
    with pytest.raises(FileExistsError):
        write_receipt.install(source, symlink)


def test_committed_blocked_build_receipt_is_explicitly_non_passing() -> None:
    receipt_path = OCI / "blocked-build-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    schema = json.loads((OCI / "receipt.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(receipt)
    assert receipt["error_code"] == "BLOCKED_BY_IMAGE_BUILD"
    assert receipt["overall_status"] == "FAIL"
    assert receipt["checks"] == [
        {"code": "BLOCKED_BY_IMAGE_BUILD", "id": "runner", "status": "FAIL"}
    ]
    assert runner.verify_receipt(receipt)


def _oci_archive(
    path: Path,
    *,
    include_manifest: bool = True,
    include_config: bool = True,
    duplicate_index: bool = False,
    traversal_name: str | None = None,
    oversized: bool = False,
) -> tuple[str, str]:
    config_bytes = json.dumps(
        {"architecture": "amd64", "os": "linux", "config": {"User": "65532:65532"}},
        separators=(",", ":"),
    ).encode()
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    manifest_bytes = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": inspect_oci_archive.OCI_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": inspect_oci_archive.OCI_CONFIG_MEDIA_TYPE,
                "digest": config_digest,
                "size": len(config_bytes),
            },
            "layers": [],
        },
        separators=(",", ":"),
    ).encode()
    child_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    index_bytes = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": inspect_oci_archive.OCI_MANIFEST_MEDIA_TYPE,
                    "digest": child_digest,
                    "size": len(manifest_bytes),
                    "platform": {"architecture": "amd64", "os": "linux"},
                }
            ],
        },
        separators=(",", ":"),
    ).encode()
    entries: list[tuple[str, bytes]] = [
        ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
        ("index.json", index_bytes),
    ]
    if include_manifest:
        entries.append((f"blobs/sha256/{child_digest[7:]}", manifest_bytes))
    if include_config:
        entries.append((f"blobs/sha256/{config_digest[7:]}", config_bytes))
    if duplicate_index:
        entries.append(("index.json", index_bytes))
    if traversal_name is not None:
        entries.append((traversal_name, b"escape"))
    with tarfile.open(path, "w") as archive:
        for name, payload in entries:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        if oversized:
            info = tarfile.TarInfo("blobs/sha256/oversized")
            info.size = inspect_oci_archive.MAX_MEMBER_BYTES + 1
            archive.addfile(info)
    return child_digest, config_digest


def test_oci_archive_inspector_binds_child_manifest_and_config(tmp_path: Path) -> None:
    archive = tmp_path / "image.tar"
    child, config = _oci_archive(archive)
    receipt = inspect_oci_archive.inspect_archive(archive, child, config)
    assert receipt["status"] == "PASS"
    assert receipt["observed_child_digest"] == child
    assert receipt["observed_config_digest"] == config
    assert inspect_oci_archive._is_digest(receipt["observed_config_digest"])


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"include_manifest": False}, "OCI_MANIFEST_BLOB_MISSING"),
        ({"include_config": False}, "OCI_CONFIG_BLOB_MISSING"),
        ({"duplicate_index": True}, "ARCHIVE_DUPLICATE_MEMBER"),
        ({"traversal_name": "../escape"}, "ARCHIVE_PATH_TRAVERSAL"),
        ({"oversized": True}, "ARCHIVE_MEMBER_OVERSIZE"),
    ],
)
def test_oci_archive_attacks_fail_closed(
    tmp_path: Path, kwargs: dict[str, object], code: str
) -> None:
    archive = tmp_path / "attacker.tar"
    child, config = _oci_archive(archive, **kwargs)
    with pytest.raises(inspect_oci_archive.InspectionFailure, match=code):
        inspect_oci_archive.inspect_archive(archive, child, config)


def test_oci_archive_wrong_child_or_config_digest_fails_closed(tmp_path: Path) -> None:
    archive = tmp_path / "image.tar"
    child, config = _oci_archive(archive)
    with pytest.raises(inspect_oci_archive.InspectionFailure, match="CHILD_DIGEST"):
        inspect_oci_archive.inspect_archive(archive, "sha256:" + "a" * 64, config)
    with pytest.raises(inspect_oci_archive.InspectionFailure, match="CONFIG_DIGEST"):
        inspect_oci_archive.inspect_archive(archive, child, "sha256:" + "b" * 64)


def _registry_payloads() -> tuple[str, str, dict[str, bytes]]:
    config = json.dumps(
        {"architecture": "amd64", "os": "linux", "config": {"User": "65532:65532"}},
        separators=(",", ":"),
    ).encode()
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:" + "a" * 64,
                    "size": 1,
                }
            ],
        },
        separators=(",", ":"),
    ).encode()
    child_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    return child_digest, config_digest, {"manifest": manifest, "config": config}


def test_registry_bundle_binds_manifest_and_config(monkeypatch: pytest.MonkeyPatch) -> None:
    child, config, payloads = _registry_payloads()

    def fetch(url: str, _limit: int, _types: set[str]) -> bytes:
        return payloads["manifest"] if "/manifests/" in url else payloads["config"]

    monkeypatch.setattr(inspect_registry_bundle, "fetch_bytes", fetch)
    receipt = inspect_registry_bundle.inspect_registry_bundle(
        "http://127.0.0.1:5000/v2", "fixture", child, config
    )
    assert receipt["status"] == "PASS"
    assert receipt["observed_child_digest"] == child
    assert receipt["observed_config_digest"] == config


@pytest.mark.parametrize("attack", ["manifest_media", "config_digest", "layer_media", "duplicate"])
def test_registry_bundle_attacks_fail_closed(monkeypatch: pytest.MonkeyPatch, attack: str) -> None:
    child, config, payloads = _registry_payloads()
    manifest = json.loads(payloads["manifest"])
    if attack == "manifest_media":
        manifest["mediaType"] = "application/octet-stream"
        payloads["manifest"] = json.dumps(manifest, separators=(",", ":")).encode()
        child = "sha256:" + hashlib.sha256(payloads["manifest"]).hexdigest()
    elif attack == "config_digest":
        manifest["config"]["digest"] = "sha256:" + "b" * 64
        payloads["manifest"] = json.dumps(manifest, separators=(",", ":")).encode()
        child = "sha256:" + hashlib.sha256(payloads["manifest"]).hexdigest()
    elif attack == "layer_media":
        manifest["layers"][0]["mediaType"] = "application/octet-stream"
        payloads["manifest"] = json.dumps(manifest, separators=(",", ":")).encode()
        child = "sha256:" + hashlib.sha256(payloads["manifest"]).hexdigest()
    else:
        payloads["manifest"] = b'{"schemaVersion":2,"schemaVersion":2}'
        child = "sha256:" + hashlib.sha256(payloads["manifest"]).hexdigest()

    def fetch(url: str, _limit: int, _types: set[str]) -> bytes:
        return payloads["manifest"] if "/manifests/" in url else payloads["config"]

    monkeypatch.setattr(inspect_registry_bundle, "fetch_bytes", fetch)
    with pytest.raises(inspect_registry_bundle.BundleFailure):
        inspect_registry_bundle.inspect_registry_bundle(
            "http://127.0.0.1:5000/v2", "fixture", child, config
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:5000/v2",
        "http://localhost:5000/v2",
        "http://127.0.0.1:5000/v3",
        "http://user:pass@127.0.0.1:5000/v2",
    ],
)
def test_registry_endpoint_is_loopback_v2_without_redirect_or_userinfo(endpoint: str) -> None:
    with pytest.raises(inspect_registry_bundle.BundleFailure):
        inspect_registry_bundle.validate_endpoint(endpoint, "fixture")
    for repository in ("fixture//nested", "fixture/../escape", "fixture/./nested"):
        with pytest.raises(inspect_registry_bundle.BundleFailure):
            inspect_registry_bundle.validate_endpoint("http://127.0.0.1:5000/v2", repository)


@pytest.mark.parametrize("field", ["architecture", "user"])
def test_registry_config_platform_and_user_fail_closed(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    child, _config, payloads = _registry_payloads()
    bad_config = {"architecture": "amd64", "os": "linux", "config": {"User": "65532:65532"}}
    bad_config["architecture" if field == "architecture" else "os"] = "arm64"
    if field == "user":
        bad_config["architecture"] = "amd64"
        bad_config["os"] = "linux"
        bad_config["config"]["User"] = "0"
    config_body = json.dumps(bad_config, separators=(",", ":")).encode()
    bad_config_digest = "sha256:" + hashlib.sha256(config_body).hexdigest()
    manifest = json.loads(payloads["manifest"])
    manifest["config"]["digest"] = bad_config_digest
    payloads["config"] = config_body
    payloads["manifest"] = json.dumps(manifest, separators=(",", ":")).encode()
    child = "sha256:" + hashlib.sha256(payloads["manifest"]).hexdigest()

    def fetch(url: str, _limit: int, _types: set[str]) -> bytes:
        return payloads["manifest"] if "/manifests/" in url else payloads["config"]

    monkeypatch.setattr(inspect_registry_bundle, "fetch_bytes", fetch)
    with pytest.raises(inspect_registry_bundle.BundleFailure):
        inspect_registry_bundle.inspect_registry_bundle(
            "http://127.0.0.1:5000/v2", "fixture", child, bad_config_digest
        )


def test_registry_bundle_rejects_nan_and_redirects() -> None:
    with pytest.raises(inspect_registry_bundle.BundleFailure, match="NONFINITE"):
        inspect_registry_bundle.strict_json(b'{"value":NaN}')

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "https://evil.invalid/redirect")
            self.end_headers()

        def log_message(self, *_args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(inspect_registry_bundle.BundleFailure, match="REDIRECT"):
            inspect_registry_bundle.fetch_bytes(
                f"http://127.0.0.1:{server.server_port}/v2/x",
                1024,
                inspect_registry_bundle.MANIFEST_MEDIA_TYPES,
            )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.mark.parametrize("attack", ["blob", "size", "duplicate-layer", "layer-count"])
def test_registry_bundle_blob_and_layer_attacks_fail_closed(
    monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    child, config, payloads = _registry_payloads()
    manifest = json.loads(payloads["manifest"])
    if attack == "blob":
        payloads["config"] = payloads["config"] + b"tamper"
    elif attack == "size":
        manifest["config"]["size"] += 1
        payloads["manifest"] = json.dumps(manifest, separators=(",", ":")).encode()
        child = "sha256:" + hashlib.sha256(payloads["manifest"]).hexdigest()
    elif attack == "duplicate-layer":
        manifest["layers"].append(dict(manifest["layers"][0]))
        payloads["manifest"] = json.dumps(manifest, separators=(",", ":")).encode()
        child = "sha256:" + hashlib.sha256(payloads["manifest"]).hexdigest()
    else:
        manifest["layers"] = [dict(manifest["layers"][0]) for _ in range(513)]
        payloads["manifest"] = json.dumps(manifest, separators=(",", ":")).encode()
        child = "sha256:" + hashlib.sha256(payloads["manifest"]).hexdigest()

    def fetch(url: str, _limit: int, _types: set[str]) -> bytes:
        return payloads["manifest"] if "/manifests/" in url else payloads["config"]

    monkeypatch.setattr(inspect_registry_bundle, "fetch_bytes", fetch)
    with pytest.raises(inspect_registry_bundle.BundleFailure):
        inspect_registry_bundle.inspect_registry_bundle(
            "http://127.0.0.1:5000/v2", "fixture", child, config
        )


def test_apk_closure_lock_is_complete_sorted_and_unknown() -> None:
    lock = fetch_apk_closure.load_lock(OCI / "apk-closure.lock.json")
    assert lock["schema"] == fetch_apk_closure.SCHEMA
    assert lock["package_count"] == 141
    assert len(lock["packages"]) == 141
    assert lock["availability"] == "UNKNOWN"
    assert lock["base_image"] == (
        "sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb"
    )
    assert [item["filename"] for item in lock["packages"]] == sorted(
        item["filename"] for item in lock["packages"]
    )
    roots = [
        line.strip()
        for line in (OCI / "ALPINE_PACKAGES.lock").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert lock["root_packages"] == roots
    assert lock["total_package_bytes"] == sum(item["size"] for item in lock["packages"])
    assert {item["architecture"] for item in lock["packages"]} == {"noarch", "x86_64"}
    assert not list(OCI.rglob("*.apk"))
    assert not list(OCI.rglob("*.whl"))


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda lock: lock.update(availability="PASS"), "AVAILABILITY"),
        (lambda lock: lock.update(extra=True), "KEYSET"),
        (lambda lock: lock["packages"][0].update(url="http://dl-cdn.alpinelinux.org/x"), "URL"),
        (lambda lock: lock["packages"][0].update(url="https://evil.invalid/x"), "URL"),
        (
            lambda lock: lock["packages"][0].update(url=lock["packages"][0]["url"] + "?redirect=1"),
            "URL",
        ),
        (
            lambda lock: lock["packages"][1].update(name=lock["packages"][0]["name"]),
            "DUPLICATE_PACKAGE_NAME",
        ),
        (lambda lock: lock.update(package_count=140), "PACKAGE_COUNT_MISMATCH"),
        (lambda lock: lock.update(total_package_bytes=1), "TOTAL_PACKAGE_SIZE_MISMATCH"),
        (lambda lock: lock.update(base_image="sha256:" + "0" * 64), "BASE_IMAGE"),
        (
            lambda lock: lock["packages"][0].update(signature_key="../../escape.rsa.pub"),
            "SIGNATURE_KEY",
        ),
        (lambda lock: lock["root_packages"].append("missing=1.0-r0"), "ROOT_PACKAGE"),
    ],
)
def test_apk_closure_lock_attacks_fail_closed(mutation, code: str) -> None:
    lock = json.loads((OCI / "apk-closure.lock.json").read_text(encoding="utf-8"))
    mutation(lock)
    with pytest.raises(fetch_apk_closure.ClosureFailure, match=code):
        fetch_apk_closure.validate_lock(lock)


def test_apk_closure_strict_json_rejects_duplicate_and_nonfinite() -> None:
    with pytest.raises(fetch_apk_closure.ClosureFailure, match="DUPLICATE"):
        fetch_apk_closure._strict_json(b'{"schema":1,"schema":2}')
    with pytest.raises(fetch_apk_closure.ClosureFailure, match="NONFINITE"):
        fetch_apk_closure._strict_json(b'{"size":NaN}')


def _fake_signed_archive(path: Path, *, pkginfo: bytes | None = None) -> None:
    with tarfile.open(path, "w:gz") as archive:
        signature = tarfile.TarInfo(".SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub")
        signature.size = 1
        archive.addfile(signature, io.BytesIO(b"x"))
        if pkginfo is not None:
            metadata = tarfile.TarInfo(".PKGINFO")
            metadata.size = len(pkginfo)
            archive.addfile(metadata, io.BytesIO(pkginfo))


def test_apk_package_metadata_signature_and_bytes_are_bound(tmp_path: Path) -> None:
    path = tmp_path / "fixture-1.0-r0.apk"
    pkginfo = b"\n".join(
        (
            b"pkgname = fixture",
            b"pkgver = 1.0-r0",
            b"origin = fixture",
            b"commit = " + b"a" * 40,
            b"arch = x86_64",
        )
    )
    _fake_signed_archive(path, pkginfo=pkginfo)
    package = {
        "name": "fixture",
        "version": "1.0-r0",
        "origin": "fixture",
        "build_commit": "a" * 40,
        "architecture": "x86_64",
        "size": path.stat().st_size,
        "sha256": digest(path),
        "signature_key": "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub",
    }
    fetch_apk_closure.verify_package(path, package)
    package["build_commit"] = "b" * 40
    with pytest.raises(fetch_apk_closure.ClosureFailure, match="METADATA"):
        fetch_apk_closure.verify_package(path, package)
    package["build_commit"] = "a" * 40
    package["sha256"] = "sha256:" + "0" * 64
    with pytest.raises(fetch_apk_closure.ClosureFailure, match="BYTES"):
        fetch_apk_closure.verify_package(path, package)


def test_apk_closure_does_not_depend_on_mutable_repository_indexes() -> None:
    lock = fetch_apk_closure.load_lock(OCI / "apk-closure.lock.json")
    assert all("index_url" not in repository for repository in lock["repositories"])
    assert all("index_content_sha256" not in repository for repository in lock["repositories"])
    assert len(fetch_apk_closure.expected_paths(lock)) == 141
    assert all(path.name != "APKINDEX.tar.gz" for path in fetch_apk_closure.expected_paths(lock))
    source = (OCI / "fetch_apk_closure.py").read_text(encoding="utf-8")
    assert "INDEX_CONTENT_DIGEST_MISMATCH" not in source


def test_apk_bundle_rejects_missing_extra_and_symlink_members(tmp_path: Path) -> None:
    lock = fetch_apk_closure.load_lock(OCI / "apk-closure.lock.json")
    with pytest.raises(fetch_apk_closure.ClosureFailure, match="MEMBER_SET"):
        fetch_apk_closure.verify_directory(tmp_path, lock)
    extra = tmp_path / "extra.apk"
    extra.write_bytes(b"x")
    with pytest.raises(fetch_apk_closure.ClosureFailure, match="MEMBER_SET"):
        fetch_apk_closure.verify_directory(tmp_path, lock)
    extra.unlink()
    (tmp_path / "escape").symlink_to(tmp_path / "outside")
    with pytest.raises(fetch_apk_closure.ClosureFailure, match="SYMLINK"):
        fetch_apk_closure.verify_directory(tmp_path, lock)


def test_apk_download_redirect_is_forbidden_and_part_is_removed(tmp_path: Path) -> None:
    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", "https://evil.invalid/payload.apk")
            self.end_headers()

        def log_message(self, *_args) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    destination = tmp_path / "payload.apk"
    try:
        with pytest.raises(fetch_apk_closure.ClosureFailure, match="REDIRECT"):
            fetch_apk_closure._download(
                f"http://127.0.0.1:{server.server_port}/payload.apk",
                destination,
                1,
                "sha256:" + "0" * 64,
            )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert not destination.exists()
    assert not destination.with_name("payload.apk.part").exists()


def test_verifier_input_preparation_has_bounded_network_phase() -> None:
    script = (OCI / "prepare_verifier_inputs.sh").read_text(encoding="utf-8")
    assert "python:3.12-alpine@sha256:78e987" in script
    assert "--network bridge" in script
    assert "--read-only" in script
    assert "--cap-drop ALL" in script
    assert "--security-opt no-new-privileges:true" in script
    assert '--user "$HOST_UID:$HOST_GID"' in script
    assert "fetch_apk_closure.py" in script
    assert "verify_wheel_closure.py" in script
    assert "OUTPUT_PARENT_MUST_BE_DEDICATED_EMPTY_DIRECTORY" in script
    assert "--require-hashes" in script
    assert "--only-binary=:all:" in script
    assert "--allow-untrusted" not in script
    assert "secrets." not in script


def test_verifier_input_preparation_rejects_shared_output_parent(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    (parent / "unrelated").write_text("must not be mounted", encoding="utf-8")
    result = __import__("subprocess").run(
        [
            "/bin/sh",
            str(OCI / "prepare_verifier_inputs.sh"),
            "--docker-bin",
            "/bin/sh",
            "--repo-root",
            str(Path(__file__).parents[2]),
            "--output",
            str(parent / "verifier-inputs"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "OUTPUT_PARENT_MUST_BE_DEDICATED_EMPTY_DIRECTORY" in result.stderr


def test_wheel_closure_lock_is_exact_and_unknown() -> None:
    lock = verify_wheel_closure.load_lock(OCI / "wheel-closure.lock.json")
    assert lock["file_count"] == 6
    assert lock["availability"] == "UNKNOWN"
    assert lock["total_bytes"] == 821982
    assert [item["filename"] for item in lock["files"]] == sorted(
        item["filename"] for item in lock["files"]
    )


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda lock: lock.update(availability="PASS"), "AVAILABILITY"),
        (lambda lock: lock.update(extra=True), "KEYSET"),
        (lambda lock: lock.update(base_image="sha256:" + "0" * 64), "BASE_IMAGE"),
        (lambda lock: lock.update(file_count=7), "WHEEL_COUNT"),
        (lambda lock: lock.update(total_bytes=1), "WHEEL_TOTAL_SIZE"),
        (
            lambda lock: lock["files"][1].update(filename=lock["files"][0]["filename"]),
            "WHEEL_FILENAME",
        ),
    ],
)
def test_wheel_closure_lock_attacks_fail_closed(mutation, code: str) -> None:
    lock = json.loads((OCI / "wheel-closure.lock.json").read_text(encoding="utf-8"))
    mutation(lock)
    with pytest.raises(verify_wheel_closure.WheelFailure, match=code):
        verify_wheel_closure.validate_lock(lock)


def test_wheel_directory_rejects_missing_extra_symlink_and_tamper(tmp_path: Path) -> None:
    payload = b"wheel"
    filename = "fixture-1.0-py3-none-any.whl"
    path = tmp_path / filename
    path.write_bytes(payload)
    lock = {
        "files": [
            {
                "filename": filename,
                "size": len(payload),
                "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            }
        ]
    }
    verify_wheel_closure.verify(tmp_path, lock)
    path.write_bytes(payload + b"tamper")
    with pytest.raises(verify_wheel_closure.WheelFailure, match="BYTES"):
        verify_wheel_closure.verify(tmp_path, lock)
    path.unlink()
    with pytest.raises(verify_wheel_closure.WheelFailure, match="MEMBER_SET"):
        verify_wheel_closure.verify(tmp_path, lock)
    path.symlink_to(tmp_path / "outside")
    with pytest.raises(verify_wheel_closure.WheelFailure, match="NOT_REGULAR"):
        verify_wheel_closure.verify(tmp_path, lock)


def test_build_reproducibility_receipt_pass_and_mismatch() -> None:
    digest_a = "sha256:" + "a" * 64
    digest_b = "sha256:" + "b" * 64
    receipt = compare_reproducible_builds.make_receipt(
        child_a=digest_a,
        config_a=digest_b,
        child_b=digest_a,
        config_b=digest_b,
        docker_client="29.0.0",
        docker_server="29.0.0",
        buildx="github.com/docker/buildx v0.34.1",
    )
    schema = json.loads((OCI / "build-reproducibility.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(receipt)
    assert receipt["status"] == "PASS"
    payload = {key: value for key, value in receipt.items() if key != "integrity"}
    assert receipt["integrity"]["payload_sha256"] == (
        "sha256:" + hashlib.sha256(compare_reproducible_builds.canonical_json(payload)).hexdigest()
    )
    mismatch = compare_reproducible_builds.make_receipt(
        child_a=digest_a,
        config_a=digest_b,
        child_b="sha256:" + "c" * 64,
        config_b=digest_b,
        docker_client="29.0.0",
        docker_server="29.0.0",
        buildx="github.com/docker/buildx v0.34.1",
    )
    Draft202012Validator(schema).validate(mismatch)
    assert mismatch["status"] == "FAIL"
    assert mismatch["error_code"] == "IMAGE_REPRODUCIBILITY_MISMATCH"


def test_build_reproducibility_receipt_rejects_invalid_inputs_and_overwrite(
    tmp_path: Path,
) -> None:
    with pytest.raises(compare_reproducible_builds.ComparisonFailure, match="DIGEST"):
        compare_reproducible_builds.make_receipt(
            child_a="latest",
            config_a="sha256:" + "b" * 64,
            child_b="sha256:" + "a" * 64,
            config_b="sha256:" + "b" * 64,
            docker_client="29.0.0",
            docker_server="29.0.0",
            buildx="buildx",
        )
    with pytest.raises(compare_reproducible_builds.ComparisonFailure, match="BUILDER"):
        compare_reproducible_builds.make_receipt(
            child_a="sha256:" + "a" * 64,
            config_a="sha256:" + "b" * 64,
            child_b="sha256:" + "a" * 64,
            config_b="sha256:" + "b" * 64,
            docker_client="29.0.0\nforged",
            docker_server="29.0.0",
            buildx="buildx",
        )
    with pytest.raises(compare_reproducible_builds.ComparisonFailure, match="COLLISION"):
        compare_reproducible_builds.make_receipt(
            child_a="sha256:" + "a" * 64,
            config_a="sha256:" + "a" * 64,
            child_b="sha256:" + "b" * 64,
            config_b="sha256:" + "c" * 64,
            docker_client="29.0.0",
            docker_server="29.0.0",
            buildx="buildx",
        )
    receipt = compare_reproducible_builds.make_receipt(
        child_a="sha256:" + "a" * 64,
        config_a="sha256:" + "b" * 64,
        child_b="sha256:" + "a" * 64,
        config_b="sha256:" + "b" * 64,
        docker_client="29.0.0",
        docker_server="29.0.0",
        buildx="buildx",
    )
    output = tmp_path / "receipt.json"
    compare_reproducible_builds.write_once(output, receipt)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(compare_reproducible_builds.ComparisonFailure, match="ALREADY_EXISTS"):
        compare_reproducible_builds.write_once(output, receipt)
