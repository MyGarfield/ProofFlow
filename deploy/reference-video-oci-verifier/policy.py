"""Pure policy checks shared by the OCI launcher and its contract tests.

The launcher is deliberately boring: all security-sensitive values are
allowlisted here, so a mutable image tag, a different child architecture, a
host tool lookup, or a relaxed Docker option cannot silently become a valid
verification run.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import PurePosixPath

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
IMAGE_REF_RE = re.compile(r"^(?P<name>[A-Za-z0-9._/-]+)@(?P<digest>sha256:[0-9a-f]{64})$")

PLATFORM = {"os": "linux", "architecture": "amd64"}
CONTAINER_UID = 65532
CONTAINER_GID = 65532
FIXED_PATH = "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
LAUNCHER_LIMITS = {
    "cpus": "1",
    "memory": "536870912",
    "memory_swap": "536870912",
    "pids": "128",
    "nofile": "1024:1024",
    "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=64m",
}
CGROUP_LIMITS = {
    "cpus": "100000 100000",
    "memory": "536870912",
    "memory_swap": "0",
    "pids": "128",
    "nofile": "1024:1024",
    "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=64m",
}
INTERNAL_PATHS = {
    "git": "/usr/bin/git",
    "python": "/usr/local/bin/python3.12",
    "ffmpeg": "/usr/bin/ffmpeg",
    "ffprobe": "/usr/bin/ffprobe",
    "tesseract": "/usr/bin/tesseract",
}
FORBIDDEN_HOST_PATHS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/lib/docker",
)


def require_sha256(value: str, field: str) -> str:
    if not SHA256_RE.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def require_commit(value: str, field: str = "commit") -> str:
    if not COMMIT_RE.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def parse_image_reference(value: str) -> tuple[str, str]:
    """Return an immutable image name and digest; reject all mutable refs."""

    match = IMAGE_REF_RE.fullmatch(value)
    if not match:
        raise ValueError("image must be pinned by a sha256 child digest")
    return match.group("name"), match.group("digest")


def validate_image_metadata(
    metadata: Mapping[str, object],
    *,
    image_ref: str,
    expected_image_digest: str,
    expected_config_digest: str,
) -> None:
    _, ref_digest = parse_image_reference(image_ref)
    require_sha256(expected_image_digest, "expected image digest")
    require_sha256(expected_config_digest, "expected image config digest")
    if expected_image_digest == expected_config_digest:
        raise ValueError("image child and config digests must remain separate")
    if ref_digest != expected_image_digest:
        raise ValueError("image digest differs from expected child digest")
    if metadata.get("Architecture") != PLATFORM["architecture"]:
        raise ValueError("image child architecture is not amd64")
    if metadata.get("Os") != PLATFORM["os"]:
        raise ValueError("image child operating system is not linux")
    if metadata.get("Id") != expected_config_digest:
        raise ValueError("image config digest differs from expected digest")
    if metadata.get("Config.User") not in {"65532", "65532:65532"}:
        raise ValueError("image user is not the fixed non-root identity")
    repo_digests = metadata.get("RepoDigests")
    if not isinstance(repo_digests, list) or image_ref not in repo_digests:
        raise ValueError("image inspect RepoDigests did not confirm the pinned child digest")


def validate_mount_contract(
    mountinfo: str,
    *,
    artifact_mount: str = "/input/reference-video",
    git_mount: str = "/input/repo",
) -> None:
    """Require read-only root, artifact and Git mounts from Linux mountinfo."""

    if not mountinfo:
        raise ValueError("mount contract unavailable")
    mounts: dict[str, set[str]] = {}
    for line in mountinfo.splitlines():
        fields = line.split(" - ", 1)
        if len(fields) != 2:
            continue
        left = fields[0].split()
        if len(left) < 6:
            continue
        mountpoint = left[4].replace("\\040", " ").replace("\\011", "\t")
        mounts[mountpoint] = set(left[5].split(","))
    for path in ("/", artifact_mount, git_mount):
        options = mounts.get(path)
        if not options or "ro" not in options:
            raise ValueError(f"mount is not read-only: {path}")


def validate_runtime_contract(
    *,
    uid: int,
    gid: int,
    path: str,
    no_docker_socket: bool,
    rootfs_read_only: bool,
    cap_drop_all: bool,
    no_new_privileges: bool,
    network_none: bool,
    limits: Mapping[str, str],
) -> None:
    if uid != CONTAINER_UID or gid != CONTAINER_GID:
        raise ValueError("runtime identity is not non-root")
    if path != FIXED_PATH:
        raise ValueError("PATH is not the fixed image path")
    if not no_docker_socket:
        raise ValueError("Docker socket is available")
    if not rootfs_read_only or not cap_drop_all or not no_new_privileges or not network_none:
        raise ValueError("container security options drifted")
    if dict(limits) != CGROUP_LIMITS:
        raise ValueError("container resource limits drifted")


def validate_tool_paths(paths: Mapping[str, str]) -> None:
    if dict(paths) != INTERNAL_PATHS:
        raise ValueError("tool paths are not fixed absolute image paths")
    if any(".." in PurePosixPath(path).parts for path in paths.values()):
        raise ValueError("tool path escapes the image")


def validate_no_host_paths(value: object) -> None:
    """Reject host mount paths or Docker socket references in receipt data."""

    text = repr(value)
    if any(path in text for path in FORBIDDEN_HOST_PATHS):
        raise ValueError("receipt contains a host Docker path")
    if "/Users/" in text or "/home/" in text or "\\Users\\" in text:
        raise ValueError("receipt contains a host filesystem path")
