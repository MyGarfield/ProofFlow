"""Fixed-environment runner for the reference-runtime evidence package.

This process is intentionally unable to create a PASS from a missing or
untrusted input.  Docker isolation is asserted by the launcher and checked
again here through Linux process, mount and cgroup observations.  The runner
uses absolute image paths and an empty subprocess environment; host PATH and
host tool binaries are never consulted.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import resource
import selectors
import signal
import subprocess
import time
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator
from policy import (
    CGROUP_LIMITS,
    FIXED_PATH,
    INTERNAL_PATHS,
    require_commit,
    require_sha256,
    validate_mount_contract,
    validate_no_host_paths,
    validate_runtime_contract,
    validate_tool_paths,
)

VERSION = "1.0.0"
RECEIPT_SCHEMA_ID = "proofflow.reference-runtime-oci-verifier.receipt.v1"
ARTIFACT_ROOT = Path("/input/reference-video")
GIT_ROOT = Path("/input/repo")
IDENTITY_PATH = Path("/etc/proofflow/toolchain.json")
RUNNER_PATH = Path("/opt/proofflow/runner.py")
RECEIPT_SCHEMA_PATH = Path("/opt/proofflow/receipt.schema.json")
RECEIPT_SCHEMA_SHA256 = "sha256:abb75dcd686275faff26a54dc7da8e0f5bfdc0a41b9547e109f21f7257307c7a"
SCHEMA_PATH = ARTIFACT_ROOT / "evidence/manifest.schema.json"
VALIDATOR_PATH = ARTIFACT_ROOT / "evidence/validate_manifest.py"
MANIFEST_PATH = ARTIFACT_ROOT / "manifest.json"
VIDEO_PATH = ARTIFACT_ROOT / "renders/reference-runtime-evidence.mp4"
VIDEO_FRAMEMD5_PATH = ARTIFACT_ROOT / "evidence/video-frames.framemd5"
AUDIO_FRAMEMD5_PATH = ARTIFACT_ROOT / "evidence/audio-pcm.framemd5"
SNAPSHOT_PATHS = (
    ARTIFACT_ROOT / "snapshots/frame-00-at-5s.png",
    ARTIFACT_ROOT / "snapshots/frame-01-at-18s.png",
    ARTIFACT_ROOT / "snapshots/frame-02-at-33s.png",
    ARTIFACT_ROOT / "snapshots/frame-03-at-49s.png",
    ARTIFACT_ROOT / "snapshots/frame-04-at-62s.png",
    ARTIFACT_ROOT / "snapshots/frame-05-at-70s.png",
    ARTIFACT_ROOT / "snapshots/frame-06-at-84s.png",
)
MAX_TOOL_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_ERROR_OUTPUT_BYTES = 64 * 1024
TIMEOUT_SECONDS = 120
BASE_ENV = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": FIXED_PATH,
    "PYTHONNOUSERSITE": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TZ": "UTC",
}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class RunnerFailure(Exception):
    """An expected, closed-set runner failure without path-bearing details."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except (OSError, ValueError) as error:
        raise RunnerFailure("REQUIRED_INPUT_UNREADABLE") from error
    return "sha256:" + digest.hexdigest()


def capability_mask_is_zero(value: str) -> bool:
    try:
        return int(value.strip(), 16) == 0
    except ValueError:
        return False


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def receipt_payload(receipt: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in receipt.items() if key != "integrity"}


def receipt_integrity(receipt: dict[str, object]) -> str:
    return digest_bytes(canonical_json(receipt_payload(receipt)))


def verify_receipt(receipt: dict[str, object]) -> bool:
    integrity = receipt.get("integrity")
    if not isinstance(integrity, dict):
        return False
    if integrity.get("algorithm") != "sha256-canonical-json-excluding-integrity":
        return False
    return integrity.get("payload_sha256") == receipt_integrity(receipt)


def validate_receipt_schema(receipt: dict[str, object]) -> None:
    try:
        schema = strict_json(RECEIPT_SCHEMA_PATH)
        if (
            not isinstance(schema, dict)
            or digest_file(RECEIPT_SCHEMA_PATH) != RECEIPT_SCHEMA_SHA256
        ):
            raise RunnerFailure("RECEIPT_SCHEMA_PIN_MISMATCH")
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(receipt)
    except RunnerFailure:
        raise
    except Exception as error:
        raise RunnerFailure("RECEIPT_SCHEMA_INVALID") from error


def strict_json(path: Path) -> object:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        output: dict[str, object] = {}
        for key, value in pairs:
            if key in output:
                raise RunnerFailure("DUPLICATE_JSON_KEY")
            output[key] = value
        return output

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate)
    except RunnerFailure:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RunnerFailure("REQUIRED_JSON_INVALID") from error


def required_env() -> dict[str, str]:
    names = (
        "PROOFFLOW_EXPECTED_ARTIFACT_COMMIT",
        "PROOFFLOW_EXPECTED_MANIFEST_SHA256",
        "PROOFFLOW_EXPECTED_SCHEMA_SHA256",
        "PROOFFLOW_EXPECTED_VALIDATOR_SHA256",
        "PROOFFLOW_EXPECTED_IMAGE_DIGEST",
        "PROOFFLOW_EXPECTED_IMAGE_CONFIG_DIGEST",
    )
    values: dict[str, str] = {}
    for name in names:
        value = os.environ.get(name, "")
        if not value or any(character in value for character in "\r\n\x00"):
            raise RunnerFailure("EXPECTED_PIN_MISSING")
        values[name] = value
    try:
        require_commit(values["PROOFFLOW_EXPECTED_ARTIFACT_COMMIT"], "artifact commit")
        for name in names[1:]:
            require_sha256(values[name], name)
    except ValueError as error:
        raise RunnerFailure("EXPECTED_PIN_INVALID") from error
    if (
        values["PROOFFLOW_EXPECTED_IMAGE_DIGEST"]
        == values["PROOFFLOW_EXPECTED_IMAGE_CONFIG_DIGEST"]
    ):
        raise RunnerFailure("IMAGE_DIGEST_CONFIG_COLLISION")
    return values


def tool_version(name: str, path: str) -> str:
    if name == "python":
        return platform.python_version()
    args = [path, "--version" if name in {"git", "tesseract"} else "-version"]
    completed = bounded_run(args, timeout=10, max_bytes=MAX_ERROR_OUTPUT_BYTES)
    if completed["status"] != "PASS" or not completed["stdout"]:
        raise RunnerFailure("TOOL_VERSION_UNAVAILABLE")
    stdout = cast(str, completed["stdout"])
    first = next((line.strip() for line in stdout.splitlines() if line.strip()), "")
    if not first:
        raise RunnerFailure("TOOL_VERSION_UNAVAILABLE")
    return first


def live_toolchain(identity: dict[str, object]) -> dict[str, object]:
    try:
        validate_tool_paths(INTERNAL_PATHS)
    except ValueError as error:
        raise RunnerFailure("TOOL_PATH_POLICY_DRIFT") from error
    declared_tools = identity.get("tools")
    if not isinstance(declared_tools, dict):
        raise RunnerFailure("IMAGE_IDENTITY_INVALID")
    result: dict[str, object] = {}
    for name, path in INTERNAL_PATHS.items():
        file_path = Path(path)
        if not file_path.is_file() or file_path.is_symlink():
            raise RunnerFailure("FIXED_TOOL_MISSING")
        observed = {
            "path": path,
            "sha256": digest_file(file_path),
            "version": tool_version(name, path),
        }
        declared = declared_tools.get(name)
        if not isinstance(declared, dict) or declared != observed:
            raise RunnerFailure("IMAGE_TOOL_IDENTITY_DRIFT")
        result[name] = observed
    declared_schema = identity.get("jsonschema_version")
    observed_schema = importlib.metadata.version("jsonschema")
    if declared_schema != observed_schema:
        raise RunnerFailure("JSONSCHEMA_IDENTITY_DRIFT")
    result["jsonschema"] = observed_schema
    result["locale"] = "C.UTF-8"
    tessdata = identity.get("tessdata")
    if not isinstance(tessdata, list) or len(tessdata) != 2:
        raise RunnerFailure("TESSDATA_IDENTITY_INVALID")
    observed_tessdata = []
    for item in tessdata:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise RunnerFailure("TESSDATA_IDENTITY_INVALID")
        path = item.get("path")
        if not isinstance(path, str) or not path.startswith("/usr/share/tessdata/"):
            raise RunnerFailure("TESSDATA_IDENTITY_INVALID")
        observed_item = {"path": path, "sha256": digest_file(Path(path))}
        if item != observed_item:
            raise RunnerFailure("TESSDATA_IDENTITY_DRIFT")
        observed_tessdata.append(observed_item)
    result["tessdata"] = observed_tessdata
    fonts = identity.get("font_inventory")
    if not isinstance(fonts, dict) or set(fonts) != {"root", "file_count", "sha256"}:
        raise RunnerFailure("FONT_IDENTITY_INVALID")
    if fonts.get("root") != "/usr/share/fonts/noto":
        raise RunnerFailure("FONT_IDENTITY_INVALID")
    if fonts.get("file_count") != 4:
        raise RunnerFailure("FONT_IDENTITY_INVALID")
    if not isinstance(fonts.get("sha256"), str) or fonts["sha256"] == "sha256:" + "0" * 64:
        raise RunnerFailure("FONT_IDENTITY_INVALID")
    result["fonts"] = fonts
    return result


def bounded_run(command: list[str], *, timeout: int, max_bytes: int) -> dict[str, object]:
    """Run an absolute-path command with bounded output and a process-group timeout."""

    if not command or not command[0].startswith("/"):
        return {"status": "FAIL", "code": "ABSOLUTE_TOOL_REQUIRED", "stdout": "", "stderr": ""}
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/tmp",
            env=dict(BASE_ENV),
            start_new_session=True,
        )
    except (OSError, ValueError):
        return {"status": "FAIL", "code": "TOOL_START_FAILED", "stdout": "", "stderr": ""}
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    started = time.monotonic()
    code = "PROCESS_FAILED"
    try:
        while selector.get_map():
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                code = "TIMEOUT"
                os.killpg(process.pid, signal.SIGKILL)
                break
            for key, _events in selector.select(min(0.25, remaining)):
                fileobj = cast(Any, key.fileobj)
                chunk = fileobj.read(4096)
                if chunk:
                    buffer = buffers[key.data]
                    buffer.extend(chunk)
                    if len(buffer) > max_bytes:
                        code = "OUTPUT_LIMIT_EXCEEDED"
                        os.killpg(process.pid, signal.SIGKILL)
                        selector.close()
                        process.wait(timeout=5)
                        return {
                            "status": "FAIL",
                            "code": code,
                            "stdout": buffers["stdout"].decode("utf-8", "replace")[:max_bytes],
                            "stderr": buffers["stderr"].decode("utf-8", "replace")[:max_bytes],
                        }
                else:
                    selector.unregister(key.fileobj)
                    fileobj.close()
        process.wait(timeout=5)
        if code != "TIMEOUT" and code != "OUTPUT_LIMIT_EXCEEDED":
            code = "PASS" if process.returncode == 0 else "PROCESS_FAILED"
    except (OSError, subprocess.TimeoutExpired):
        with suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        code = "TIMEOUT"
    finally:
        selector.close()
    return {
        "status": "PASS" if code == "PASS" else "FAIL",
        "code": code,
        "stdout": buffers["stdout"].decode("utf-8", "replace"),
        "stderr": buffers["stderr"].decode("utf-8", "replace"),
    }


def check_runtime() -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    try:
        status = Path("/proc/self/status").read_text(encoding="ascii")
        cap_eff = next(
            line.split(":", 1)[1].strip()
            for line in status.splitlines()
            if line.startswith("CapEff:")
        )
        cap_bnd = next(
            line.split(":", 1)[1].strip()
            for line in status.splitlines()
            if line.startswith("CapBnd:")
        )
        no_new_privs = next(
            line.split(":", 1)[1].strip()
            for line in status.splitlines()
            if line.startswith("NoNewPrivs:")
        )
        seccomp = next(
            line.split(":", 1)[1].strip()
            for line in status.splitlines()
            if line.startswith("Seccomp:")
        )
        cap_drop = capability_mask_is_zero(cap_eff) and capability_mask_is_zero(cap_bnd)
        nnp = no_new_privs == "1"
    except (OSError, StopIteration):
        cap_drop = False
        nnp = False
        seccomp = "unavailable"
    socket_absent = not any(
        Path(path).exists() for path in ("/var/run/docker.sock", "/run/docker.sock")
    )
    route_empty = False
    try:
        routes = Path("/proc/net/route").read_text(encoding="ascii").splitlines()
        route_empty = len(routes) <= 1
    except OSError:
        pass
    try:
        mountinfo = Path("/proc/self/mountinfo").read_text(encoding="ascii")
        validate_mount_contract(mountinfo)
        mounts = "PASS"
        tmpfs = "PASS" if _tmpfs_is_fixed(mountinfo) else "FAIL"
    except (OSError, ValueError):
        mounts = "FAIL"
        tmpfs = "FAIL"
    limits = {"tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=64m"}
    try:
        cgroup = Path("/sys/fs/cgroup")
        limits.update(
            {
                "cpus": (cgroup / "cpu.max").read_text(encoding="ascii").strip(),
                "memory": (cgroup / "memory.max").read_text(encoding="ascii").strip(),
                "memory_swap": (cgroup / "memory.swap.max").read_text(encoding="ascii").strip(),
                "pids": (cgroup / "pids.max").read_text(encoding="ascii").strip(),
            }
        )
    except OSError:
        limits.update(
            {
                "cpus": "unavailable",
                "memory": "unavailable",
                "memory_swap": "unavailable",
                "pids": "unavailable",
            }
        )
    try:
        nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
        limits["nofile"] = f"{nofile[0]}:{nofile[1]}"
    except (ValueError, OSError):
        limits["nofile"] = "unavailable"
    try:
        validate_runtime_contract(
            uid=os.getuid(),
            gid=os.getgid(),
            path=os.environ.get("PATH", ""),
            no_docker_socket=socket_absent,
            rootfs_read_only=mounts == "PASS",
            cap_drop_all=cap_drop,
            no_new_privileges=nnp,
            network_none=route_empty,
            limits=limits,
        )
        runtime = "PASS"
    except ValueError:
        runtime = "FAIL"
    checks.extend(
        [
            {
                "id": "runtime_identity",
                "status": runtime,
                "code": "NON_ROOT_FIXED_UID" if runtime == "PASS" else "RUNTIME_PROFILE_DRIFT",
            },
            {
                "id": "mounts",
                "status": mounts,
                "code": "READ_ONLY_MOUNTS" if mounts == "PASS" else "MOUNT_POLICY_DRIFT",
            },
            {
                "id": "capabilities",
                "status": "PASS" if cap_drop else "FAIL",
                "code": "CAP_DROP_ALL" if cap_drop else "CAPABILITIES_PRESENT",
            },
            {
                "id": "no_new_privileges",
                "status": "PASS" if nnp else "FAIL",
                "code": "NO_NEW_PRIVILEGES" if nnp else "NO_NEW_PRIVILEGES_MISSING",
            },
            {
                "id": "network",
                "status": "PASS" if route_empty else "FAIL",
                "code": "NETWORK_NONE" if route_empty else "NETWORK_ROUTE_PRESENT",
            },
            {
                "id": "docker_socket",
                "status": "PASS" if socket_absent else "FAIL",
                "code": "DOCKER_SOCKET_ABSENT" if socket_absent else "DOCKER_SOCKET_PRESENT",
            },
            {
                "id": "seccomp",
                "status": "PASS" if seccomp == "2" else "FAIL",
                "code": "SECCOMP_DEFAULT" if seccomp == "2" else "SECCOMP_DRIFT",
            },
            {
                "id": "tmpfs",
                "status": tmpfs,
                "code": "TMPFS_FIXED" if tmpfs == "PASS" else "TMPFS_DRIFT",
            },
            {
                "id": "resources",
                "status": "PASS" if limits == CGROUP_LIMITS else "FAIL",
                "code": "RESOURCE_LIMITS_FIXED"
                if limits == CGROUP_LIMITS
                else "RESOURCE_LIMITS_DRIFT",
            },
        ]
    )
    return checks


def _tmpfs_is_fixed(mountinfo: str) -> bool:
    for line in mountinfo.splitlines():
        fields = line.split(" - ", 1)
        if len(fields) != 2:
            continue
        left = fields[0].split()
        right = fields[1].split()
        if len(left) < 6 or len(right) < 3:
            continue
        mountpoint = left[4].replace("\\040", " ")
        if mountpoint != "/tmp" or right[0] != "tmpfs":
            continue
        options = set(left[5].split(",")) | set(right[2].split(","))
        return {"rw", "noexec", "nosuid", "nodev"}.issubset(options) and any(
            option in options for option in ("size=64m", "size=65536k")
        )
    return False


def check_pin_bindings(pins: dict[str, str], manifest: dict[str, Any]) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    if digest_file(MANIFEST_PATH) != pins["PROOFFLOW_EXPECTED_MANIFEST_SHA256"]:
        checks.append(
            {"id": "manifest_digest", "status": "FAIL", "code": "MANIFEST_DIGEST_MISMATCH"}
        )
    else:
        checks.append({"id": "manifest_digest", "status": "PASS", "code": "MANIFEST_DIGEST_MATCH"})
    for key, path, expected, code in (
        (
            "schema_sha256",
            SCHEMA_PATH,
            pins["PROOFFLOW_EXPECTED_SCHEMA_SHA256"],
            "SCHEMA_DIGEST_MATCH",
        ),
        (
            "validator_sha256",
            VALIDATOR_PATH,
            pins["PROOFFLOW_EXPECTED_VALIDATOR_SHA256"],
            "VALIDATOR_DIGEST_MATCH",
        ),
    ):
        actual = digest_file(path)
        checks.append(
            {
                "id": key.removesuffix("_sha256"),
                "status": "PASS" if actual == expected else "FAIL",
                "code": code if actual == expected else code.replace("MATCH", "MISMATCH"),
            }
        )
    if manifest.get("recorded_source_commit") != "b63eeb60d1072c73d2d0d1d6061b3c8f800487a4":
        checks.append(
            {"id": "recorded_source", "status": "FAIL", "code": "RECORDED_SOURCE_COMMIT_DRIFT"}
        )
    else:
        checks.append(
            {"id": "recorded_source", "status": "PASS", "code": "RECORDED_SOURCE_COMMIT_MATCH"}
        )
    try:
        resolved = bounded_run(
            [
                INTERNAL_PATHS["git"],
                "--no-replace-objects",
                "-C",
                str(GIT_ROOT),
                "rev-parse",
                f"{pins['PROOFFLOW_EXPECTED_ARTIFACT_COMMIT']}^{{commit}}",
            ],
            timeout=10,
            max_bytes=MAX_ERROR_OUTPUT_BYTES,
        )
        commit_ok = (
            resolved["status"] == "PASS"
            and resolved["stdout"].strip() == pins["PROOFFLOW_EXPECTED_ARTIFACT_COMMIT"]
        )
    except RunnerFailure:
        commit_ok = False
    checks.append(
        {
            "id": "artifact_commit",
            "status": "PASS" if commit_ok else "FAIL",
            "code": "ARTIFACT_COMMIT_MATCH" if commit_ok else "ARTIFACT_COMMIT_MISMATCH",
        }
    )
    return checks


def media_checks(manifest: dict[str, Any]) -> tuple[list[dict[str, str]], str | None, str | None]:
    checks: list[dict[str, str]] = []
    ffprobe_result = bounded_run(
        [
            INTERNAL_PATHS["ffprobe"],
            "-v",
            "error",
            "-show_entries",
            "format=duration,format_name:stream=index,codec_name,codec_type,width,height,pix_fmt,r_frame_rate,channels,sample_rate",
            "-of",
            "json",
            str(VIDEO_PATH),
        ],
        timeout=TIMEOUT_SECONDS,
        max_bytes=MAX_TOOL_OUTPUT_BYTES,
    )
    ffprobe_match = False
    if ffprobe_result["status"] == "PASS":
        try:
            ffprobe_match = json.loads(str(ffprobe_result["stdout"])) == manifest.get("ffprobe")
        except json.JSONDecodeError:
            ffprobe_match = False
    checks.append(
        {
            "id": "linux_ffprobe",
            "status": "PASS" if ffprobe_match else "FAIL",
            "code": "FFPROBE_MATCH" if ffprobe_match else "FFPROBE_DIFFERS",
        }
    )
    outputs: dict[str, str | None] = {"video": None, "audio": None}
    commands = {
        "video": [
            INTERNAL_PATHS["ffmpeg"],
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(VIDEO_PATH),
            "-map",
            "0:v:0",
            "-an",
            "-vf",
            "scale=96:54:flags=bilinear,format=gray",
            "-f",
            "framemd5",
            "pipe:1",
        ],
        "audio": [
            INTERNAL_PATHS["ffmpeg"],
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(VIDEO_PATH),
            "-map",
            "0:a:0",
            "-vn",
            "-af",
            "aformat=sample_fmts=s16:sample_rates=48000:channel_layouts=stereo",
            "-f",
            "framemd5",
            "pipe:1",
        ],
    }
    expected_paths = {"video": VIDEO_FRAMEMD5_PATH, "audio": AUDIO_FRAMEMD5_PATH}
    for name in ("video", "audio"):
        result = bounded_run(
            commands[name], timeout=TIMEOUT_SECONDS, max_bytes=MAX_TOOL_OUTPUT_BYTES
        )
        actual = (
            digest_bytes(str(result["stdout"]).encode("utf-8"))
            if result["status"] == "PASS"
            else None
        )
        outputs[name] = actual
        match = (
            result["status"] == "PASS"
            and str(result["stdout"]).encode("utf-8") == expected_paths[name].read_bytes()
        )
        checks.append(
            {
                "id": f"linux_{name}_framemd5",
                "status": "PASS" if match else "FAIL",
                "code": f"{name.upper()}_FRAMEMD5_MATCH"
                if match
                else f"{name.upper()}_FRAMEMD5_DIFFERS",
            }
        )
    return checks, outputs["video"], outputs["audio"]


def ocr_check() -> tuple[dict[str, str], str | None]:
    outputs: list[bytes] = []
    for path in SNAPSHOT_PATHS:
        result = bounded_run(
            [INTERNAL_PATHS["tesseract"], str(path), "stdout", "--psm", "6", "-l", "eng+chi_sim"],
            timeout=30,
            max_bytes=MAX_ERROR_OUTPUT_BYTES,
        )
        if result["status"] != "PASS":
            return {
                "id": "linux_ocr",
                "status": "FAIL",
                "code": "OCR_EXECUTION_FAILED",
            }, None
        outputs.append(str(result["stdout"]).encode("utf-8"))
    # The macOS manifest does not carry an OCR output digest. Execution is
    # observed, but cross-toolchain parity remains a separate UNKNOWN field.
    aggregate = hashlib.sha256()
    for output in outputs:
        aggregate.update(len(output).to_bytes(8, "big"))
        aggregate.update(output)
    return {
        "id": "linux_ocr",
        "status": "PASS",
        "code": "OCR_EXECUTION_OBSERVED",
    }, "sha256:" + aggregate.hexdigest()


def make_receipt(
    pins: dict[str, str],
    identity: dict[str, object],
    toolchain: dict[str, object],
    checks: list[dict[str, str]],
    *,
    identity_digest: str,
    ocr_sha256: str | None,
    error_code: str | None = None,
) -> dict[str, object]:
    statuses = [item["status"] for item in checks]
    if "FAIL" in statuses:
        overall = "FAIL"
    elif "UNKNOWN" in statuses or "SKIP" in statuses:
        overall = "UNKNOWN"
    else:
        overall = "PASS"
    receipt: dict[str, object] = {
        "schema": RECEIPT_SCHEMA_ID,
        "verifier": {
            "version": VERSION,
            "source_sha256": digest_file(RUNNER_PATH),
            "platform": "linux/amd64",
            "receipt_schema_sha256": RECEIPT_SCHEMA_SHA256,
        },
        "image": {
            "child_digest": pins["PROOFFLOW_EXPECTED_IMAGE_DIGEST"],
            "config_digest": pins["PROOFFLOW_EXPECTED_IMAGE_CONFIG_DIGEST"],
            "platform": "linux/amd64",
        },
        "expectations": {
            "artifact_commit": pins["PROOFFLOW_EXPECTED_ARTIFACT_COMMIT"],
            "manifest_sha256": pins["PROOFFLOW_EXPECTED_MANIFEST_SHA256"],
            "schema_sha256": pins["PROOFFLOW_EXPECTED_SCHEMA_SHA256"],
            "validator_sha256": pins["PROOFFLOW_EXPECTED_VALIDATOR_SHA256"],
            "verification_toolchain_sha256": identity_digest,
        },
        "toolchain": toolchain,
        "observed": {
            "manifest_sha256": digest_file(MANIFEST_PATH),
            "video_sha256": digest_file(VIDEO_PATH),
            "verification_toolchain_sha256": identity_digest,
            "ocr_sha256": ocr_sha256,
            "ocr_parity": "UNKNOWN",
            "mounts": {"artifact": "ro", "git": "ro", "rootfs": "ro"},
            "resource_limits": dict(CGROUP_LIMITS),
        },
        "constraints": {
            "uid": 65532,
            "gid": 65532,
            "network": "none",
            "rootfs": "read-only",
            "artifact_mount": "read-only",
            "git_mount": "read-only",
            "docker_socket": False,
            "capabilities": "drop-all",
            "no_new_privileges": True,
            "seccomp": "default",
            "path_source": "image-fixed-absolute",
        },
        "checks": checks,
        "overall_status": overall,
        "error_code": error_code,
    }
    validate_no_host_paths(receipt)
    receipt["integrity"] = {
        "algorithm": "sha256-canonical-json-excluding-integrity",
        "payload_sha256": receipt_integrity(receipt),
    }
    validate_receipt_schema(receipt)
    return receipt


def safe_failure_receipt(code: str) -> dict[str, object]:
    zeros = "sha256:" + "0" * 64
    receipt: dict[str, object] = {
        "schema": RECEIPT_SCHEMA_ID,
        "verifier": {
            "version": VERSION,
            "source_sha256": zeros,
            "platform": "linux/amd64",
            "receipt_schema_sha256": RECEIPT_SCHEMA_SHA256,
        },
        "image": {"child_digest": zeros, "config_digest": zeros, "platform": "linux/amd64"},
        "expectations": {
            "artifact_commit": "0" * 40,
            "manifest_sha256": zeros,
            "schema_sha256": zeros,
            "validator_sha256": zeros,
            "verification_toolchain_sha256": zeros,
        },
        "toolchain": {
            "git": {"path": "/usr/bin/git", "sha256": zeros, "version": "unavailable"},
            "python": {
                "path": "/usr/local/bin/python3.12",
                "sha256": zeros,
                "version": "unavailable",
            },
            "ffmpeg": {"path": "/usr/bin/ffmpeg", "sha256": zeros, "version": "unavailable"},
            "ffprobe": {"path": "/usr/bin/ffprobe", "sha256": zeros, "version": "unavailable"},
            "tesseract": {"path": "/usr/bin/tesseract", "sha256": zeros, "version": "unavailable"},
            "jsonschema": "0.0.0",
            "locale": "C.UTF-8",
            "tessdata": [
                {"path": "/usr/share/tessdata/eng.traineddata", "sha256": zeros},
                {"path": "/usr/share/tessdata/chi_sim.traineddata", "sha256": zeros},
            ],
            "fonts": {
                "root": "/usr/share/fonts/noto",
                "file_count": 4,
                "sha256": "sha256:" + "1" * 64,
            },
        },
        "observed": {
            "manifest_sha256": zeros,
            "video_sha256": zeros,
            "verification_toolchain_sha256": zeros,
            "ocr_sha256": None,
            "ocr_parity": "UNKNOWN",
            "mounts": {"artifact": "ro", "git": "ro", "rootfs": "ro"},
            "resource_limits": dict(CGROUP_LIMITS),
        },
        "constraints": {
            "uid": 65532,
            "gid": 65532,
            "network": "none",
            "rootfs": "read-only",
            "artifact_mount": "read-only",
            "git_mount": "read-only",
            "docker_socket": False,
            "capabilities": "drop-all",
            "no_new_privileges": True,
            "seccomp": "default",
            "path_source": "image-fixed-absolute",
        },
        "checks": [{"id": "runner", "status": "FAIL", "code": code}],
        "overall_status": "FAIL",
        "error_code": code,
    }
    receipt["integrity"] = {
        "algorithm": "sha256-canonical-json-excluding-integrity",
        "payload_sha256": receipt_integrity(receipt),
    }
    validate_receipt_schema(receipt)
    return receipt


def run() -> dict[str, object]:
    pins = required_env()
    if os.getuid() == 0 or os.getgid() == 0:
        raise RunnerFailure("ROOT_IDENTITY_FORBIDDEN")
    validate_tool_paths(INTERNAL_PATHS)
    if (
        not ARTIFACT_ROOT.is_dir()
        or ARTIFACT_ROOT.is_symlink()
        or not GIT_ROOT.is_dir()
        or GIT_ROOT.is_symlink()
    ):
        raise RunnerFailure("MOUNT_ROOT_INVALID")
    identity_digest = digest_file(IDENTITY_PATH)
    identity = strict_json(IDENTITY_PATH)
    if not isinstance(identity, dict) or identity.get("platform") != "linux/amd64":
        raise RunnerFailure("IMAGE_IDENTITY_INVALID")
    build_inputs = identity.get("build_inputs")
    if not isinstance(build_inputs, dict):
        raise RunnerFailure("IMAGE_IDENTITY_INVALID")
    expected_inputs = {
        "artifact_commit": pins["PROOFFLOW_EXPECTED_ARTIFACT_COMMIT"],
        "manifest_sha256": pins["PROOFFLOW_EXPECTED_MANIFEST_SHA256"],
        "schema_sha256": pins["PROOFFLOW_EXPECTED_SCHEMA_SHA256"],
        "validator_sha256": pins["PROOFFLOW_EXPECTED_VALIDATOR_SHA256"],
    }
    if any(build_inputs.get(key) != value for key, value in expected_inputs.items()):
        raise RunnerFailure("IMAGE_BUILD_INPUT_DRIFT")
    identity_base = identity.get("base_image")
    if (
        not isinstance(identity_base, dict)
        or identity_base.get("child_digest")
        != "sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb"
    ):
        raise RunnerFailure("IMAGE_BASE_DIGEST_DRIFT")
    toolchain = live_toolchain(identity)
    manifest = strict_json(MANIFEST_PATH)
    if not isinstance(manifest, dict):
        raise RunnerFailure("MANIFEST_INVALID")
    checks = check_runtime()
    checks.extend(check_pin_bindings(pins, manifest))
    media, _video_md5, _audio_md5 = media_checks(manifest)
    checks.extend(media)
    ocr, ocr_sha256 = ocr_check()
    checks.append(ocr)
    validator_result = bounded_run(
        [
            INTERNAL_PATHS["python"],
            "-O",
            str(VALIDATOR_PATH),
            "--manifest",
            str(MANIFEST_PATH),
            "--video-root",
            str(ARTIFACT_ROOT),
            "--expected-schema-sha256",
            pins["PROOFFLOW_EXPECTED_SCHEMA_SHA256"],
            "--expected-validator-sha256",
            pins["PROOFFLOW_EXPECTED_VALIDATOR_SHA256"],
            "--expected-artifact-commit",
            pins["PROOFFLOW_EXPECTED_ARTIFACT_COMMIT"],
            "--trusted-git-root",
            str(GIT_ROOT),
            "--git-binary",
            INTERNAL_PATHS["git"],
            "--ffprobe",
            INTERNAL_PATHS["ffprobe"],
            "--ffmpeg",
            INTERNAL_PATHS["ffmpeg"],
            "--tesseract",
            INTERNAL_PATHS["tesseract"],
            "--verification-toolchain-identity",
            str(IDENTITY_PATH),
            "--expected-verification-toolchain-sha256",
            identity_digest,
        ],
        timeout=TIMEOUT_SECONDS,
        max_bytes=MAX_ERROR_OUTPUT_BYTES,
    )
    checks.append(
        {
            "id": "trusted_validator",
            "status": "FAIL" if validator_result["status"] == "FAIL" else "PASS",
            "code": "VALIDATOR_FAILED"
            if validator_result["status"] == "FAIL"
            else "VALIDATOR_PASS",
        }
    )
    return make_receipt(
        pins,
        identity,
        toolchain,
        checks,
        identity_digest=identity_digest,
        ocr_sha256=ocr_sha256,
    )


def main() -> None:
    try:
        receipt = run()
    except RunnerFailure as error:
        receipt = safe_failure_receipt(error.code)
    except Exception:
        receipt = safe_failure_receipt("RUNNER_INTERNAL_FAILURE")
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    if receipt.get("overall_status") != "PASS" or not verify_receipt(receipt):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
