from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

OCI = Path(__file__).parents[2] / "deploy/reference-video-oci-verifier"
sys.path.insert(0, str(OCI))

import build_identity  # noqa: E402
import inspect_oci_archive  # noqa: E402
import runner  # noqa: E402
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
    assert "FROM --platform=linux/amd64 python:3.12-alpine@sha256:78e987" in dockerfile
    assert "ARG ARTIFACT_COMMIT=81af263aa612529b487e5f13540f19716a20fa58" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "ALPINE_PACKAGES.lock" in dockerfile
    assert "MAIN_APKINDEX_SHA256" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["/usr/local/bin/python3.12", "/opt/proofflow/runner.py"]' in dockerfile
    assert "COPY deploy/reference-video-oci-verifier/receipt.schema.json" in dockerfile
    assert r"printf '%s\n%s\n'" in dockerfile
    assert "printf '%s\\\\n%s\\\\n'" not in dockerfile
    launcher = (OCI / "run.sh").read_text(encoding="utf-8")
    assert "{{.Descriptor.digest}}" in launcher
    assert "save --platform linux/amd64" in launcher


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
