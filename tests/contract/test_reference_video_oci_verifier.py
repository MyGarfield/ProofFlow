from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

OCI = Path(__file__).parents[2] / "deploy/reference-video-oci-verifier"
sys.path.insert(0, str(OCI))

import runner  # noqa: E402
import write_receipt  # noqa: E402
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
    assert "FROM --platform=linux/amd64 python:3.12-alpine@sha256:78e987" in dockerfile
    assert "ARG ARTIFACT_COMMIT=69faa8ae7884c6cf69e583488e39afac4b9cd052" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "ALPINE_PACKAGES.lock" in dockerfile
    assert "MAIN_APKINDEX_SHA256" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["/usr/local/bin/python3.12", "/opt/proofflow/runner.py"]' in dockerfile
    assert "COPY deploy/reference-video-oci-verifier/receipt.schema.json" in dockerfile


def test_launcher_has_all_fail_closed_docker_options() -> None:
    launcher = (OCI / "run.sh").read_text(encoding="utf-8")
    for option in (
        "--platform linux/amd64",
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges:true",
        "--security-opt seccomp=default",
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
        "Id": "sha256:" + "b" * 64,
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


def test_fake_tools_and_host_path_lookup_are_rejected() -> None:
    with pytest.raises(ValueError, match="fixed absolute"):
        validate_tool_paths({**INTERNAL_PATHS, "ffmpeg": "ffmpeg"})
    with pytest.raises(ValueError, match="fixed absolute"):
        validate_tool_paths({**INTERNAL_PATHS, "tesseract": "/tmp/fake-tesseract"})


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
