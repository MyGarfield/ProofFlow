"""Install the frozen public-synthetic CLI demo from package resources."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class DemoInitializationResult:
    """A path-independent receipt for one initialized demo bundle."""

    classification: str
    files: tuple[str, ...]


class DemoInitializationError(RuntimeError):
    """An expected, safely serializable init-demo failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message


@dataclass(frozen=True)
class _PinnedDirectory:
    name: str
    parent_fd: int
    fd: int
    device: int
    inode: int


@dataclass(frozen=True)
class _PinnedFile:
    name: str
    parent: _PinnedDirectory
    fd: int
    device: int
    inode: int
    expected_payload: bytes


DEMO_ASSET_FILES = (
    "README.md",
    "case/contract.json",
    "case/manifest.json",
    "case/payroll.json",
    "case/termination_notice.json",
    "rules/cn_labor_contract_law.catalog.json",
)
DEMO_ASSET_DIGESTS = {
    "README.md": "sha256:d554efb6eddbf754282fb02f0c41595d159fe6cd23184cf73177c17c9f6747e1",
    "case/contract.json": (
        "sha256:f17e64030475d0a6de6d0f0c340cab223ea64f9addca2789c523fcc3513914ff"
    ),
    "case/manifest.json": (
        "sha256:c659dee0e33e0e63a5d51f82476a9b98d7287388a2dd13a2798f1543ca102c30"
    ),
    "case/payroll.json": (
        "sha256:2979d172f73d3bc83cc7c3a673e39a12b68026afa05424bcf7877cbe7c3300f5"
    ),
    "case/termination_notice.json": (
        "sha256:529aa937fdd04b08e6fdb87c2dc0dbb0eac8c27b4b373f03b001ad5bbf489eca"
    ),
    "rules/cn_labor_contract_law.catalog.json": (
        "sha256:27686c904451870dd5953ec6e47c155a395b2f279995e50f68aea984e6bf91de"
    ),
}


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _resource_bytes(relative_path: str) -> bytes:
    resource = files("proofflow").joinpath("demo_assets")
    for part in PurePosixPath(relative_path).parts:
        resource = resource.joinpath(part)
    try:
        if not resource.is_file():
            raise DemoInitializationError(
                "DEMO_ASSET_MISSING",
                "the installed demo asset bundle is incomplete",
            )
        return resource.read_bytes()
    except DemoInitializationError:
        raise
    except (OSError, UnicodeError) as exc:
        raise DemoInitializationError(
            "DEMO_ASSET_UNREADABLE",
            "the installed demo asset bundle cannot be read",
        ) from exc


def _load_and_validate_assets() -> dict[str, bytes]:
    payloads = {relative_path: _resource_bytes(relative_path) for relative_path in DEMO_ASSET_FILES}
    if set(payloads) != set(DEMO_ASSET_DIGESTS) or any(
        _sha256(payload) != DEMO_ASSET_DIGESTS[relative_path]
        for relative_path, payload in payloads.items()
    ):
        raise DemoInitializationError(
            "DEMO_ASSET_INVALID",
            "the installed demo asset bundle failed its integrity contract",
        )
    try:
        manifest = json.loads(payloads["case/manifest.json"])
        rules = json.loads(payloads["rules/cn_labor_contract_law.catalog.json"])
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DemoInitializationError(
            "DEMO_ASSET_INVALID",
            "the installed demo asset bundle failed its integrity contract",
        ) from exc

    if (
        not isinstance(manifest, dict)
        or manifest.get("fixture_status") != "SYNTHETIC"
        or not isinstance(manifest.get("documents"), list)
        or not isinstance(rules, dict)
        or rules.get("status") != "CURATED_REFERENCE_ONLY"
        or rules.get("legal_advice") is not False
    ):
        raise DemoInitializationError(
            "DEMO_ASSET_INVALID",
            "the installed demo asset bundle failed its integrity contract",
        )

    declared_documents: dict[str, str] = {}
    for document in manifest["documents"]:
        if not isinstance(document, dict):
            raise DemoInitializationError(
                "DEMO_ASSET_INVALID",
                "the installed demo asset bundle failed its integrity contract",
            )
        path = document.get("path")
        digest = document.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str):
            raise DemoInitializationError(
                "DEMO_ASSET_INVALID",
                "the installed demo asset bundle failed its integrity contract",
            )
        declared_documents[path] = digest

    expected_documents = {"contract.json", "payroll.json", "termination_notice.json"}
    if set(declared_documents) != expected_documents:
        raise DemoInitializationError(
            "DEMO_ASSET_INVALID",
            "the installed demo asset bundle failed its integrity contract",
        )
    for document_name, declared_digest in declared_documents.items():
        if _sha256(payloads[f"case/{document_name}"]) != declared_digest:
            raise DemoInitializationError(
                "DEMO_ASSET_INVALID",
                "the installed demo asset bundle failed its integrity contract",
            )
    return payloads


def _require_descriptor_safe_platform() -> None:
    required = (os.open, os.mkdir, os.stat, os.unlink, os.rmdir)
    if (
        not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or any(operation not in os.supports_dir_fd for operation in required)
        or os.stat not in os.supports_follow_symlinks
    ):
        raise DemoInitializationError(
            "DEMO_PLATFORM_UNSUPPORTED",
            "secure demo initialization is unavailable on this platform",
        )


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _same_inode(metadata: os.stat_result, *, device: int, inode: int) -> bool:
    return metadata.st_dev == device and metadata.st_ino == inode


def _entry_matches(
    parent_fd: int,
    name: str,
    *,
    device: int,
    inode: int,
    expected_mode: int,
) -> bool:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return (
        _same_inode(metadata, device=device, inode=inode)
        and stat.S_IFMT(metadata.st_mode) == expected_mode
    )


def _open_pinned_directory(parent_fd: int, name: str) -> _PinnedDirectory:
    descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or not _entry_matches(
            parent_fd,
            name,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            expected_mode=stat.S_IFDIR,
        ):
            raise DemoInitializationError(
                "DEMO_OUTPUT_RACE_DETECTED",
                "the demo output directory changed during initialization",
            )
    except BaseException:
        os.close(descriptor)
        raise
    return _PinnedDirectory(
        name=name,
        parent_fd=parent_fd,
        fd=descriptor,
        device=metadata.st_dev,
        inode=metadata.st_ino,
    )


def _write_payload(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short write")
        remaining = remaining[written:]
    os.fsync(descriptor)


def _write_all_assets(
    root: _PinnedDirectory,
    payloads: dict[str, bytes],
    child_directories: dict[str, _PinnedDirectory],
    written_files: list[_PinnedFile],
) -> None:
    directory_names = sorted(
        {
            parts[0]
            for relative_path in payloads
            if len(parts := PurePosixPath(relative_path).parts) == 2
        }
    )
    for directory_name in directory_names:
        os.mkdir(directory_name, mode=0o700, dir_fd=root.fd)
        child_directories[directory_name] = _open_pinned_directory(root.fd, directory_name)

    for relative_path, payload in sorted(payloads.items()):
        parts = PurePosixPath(relative_path).parts
        if len(parts) == 1:
            parent = root
            filename = parts[0]
        elif len(parts) == 2 and parts[0] in child_directories:
            parent = child_directories[parts[0]]
            filename = parts[1]
        else:
            raise DemoInitializationError(
                "DEMO_ASSET_INVALID",
                "the installed demo asset bundle failed its integrity contract",
            )
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(filename, flags, 0o600, dir_fd=parent.fd)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise DemoInitializationError(
                    "DEMO_OUTPUT_RACE_DETECTED",
                    "the demo output directory changed during initialization",
                )
            _write_payload(descriptor, payload)
        except BaseException:
            os.close(descriptor)
            raise
        written_files.append(
            _PinnedFile(
                name=filename,
                parent=parent,
                fd=descriptor,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                expected_payload=payload,
            )
        )


def _read_pinned_file(record: _PinnedFile) -> bytes:
    os.lseek(record.fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(record.fd, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _verify_completed_output(
    *,
    logical_parent: Path,
    logical_output: Path,
    parent_fd: int,
    parent_metadata: os.stat_result,
    root: _PinnedDirectory,
    child_directories: dict[str, _PinnedDirectory],
    written_files: list[_PinnedFile],
) -> None:
    try:
        logical_parent_metadata = os.stat(logical_parent)
        logical_output_metadata = os.stat(logical_output, follow_symlinks=False)
    except OSError as exc:
        raise DemoInitializationError(
            "DEMO_OUTPUT_RACE_DETECTED",
            "the demo output directory changed during initialization",
        ) from exc
    if (
        not _same_inode(
            logical_parent_metadata,
            device=parent_metadata.st_dev,
            inode=parent_metadata.st_ino,
        )
        or not _same_inode(
            logical_output_metadata,
            device=root.device,
            inode=root.inode,
        )
        or not stat.S_ISDIR(logical_output_metadata.st_mode)
        or not _entry_matches(
            parent_fd,
            root.name,
            device=root.device,
            inode=root.inode,
            expected_mode=stat.S_IFDIR,
        )
    ):
        raise DemoInitializationError(
            "DEMO_OUTPUT_RACE_DETECTED",
            "the demo output directory changed during initialization",
        )

    expected_root_entries = {"README.md", *child_directories}
    if set(os.listdir(root.fd)) != expected_root_entries:
        raise DemoInitializationError(
            "DEMO_OUTPUT_RACE_DETECTED",
            "the demo output directory changed during initialization",
        )
    for name, directory in child_directories.items():
        if not _entry_matches(
            root.fd,
            name,
            device=directory.device,
            inode=directory.inode,
            expected_mode=stat.S_IFDIR,
        ):
            raise DemoInitializationError(
                "DEMO_OUTPUT_RACE_DETECTED",
                "the demo output directory changed during initialization",
            )

    expected_child_entries: dict[int, set[str]] = {
        directory.fd: set() for directory in child_directories.values()
    }
    for record in written_files:
        if record.parent is not root:
            expected_child_entries[record.parent.fd].add(record.name)
        metadata = os.fstat(record.fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not _same_inode(metadata, device=record.device, inode=record.inode)
            or not _entry_matches(
                record.parent.fd,
                record.name,
                device=record.device,
                inode=record.inode,
                expected_mode=stat.S_IFREG,
            )
            or _read_pinned_file(record) != record.expected_payload
        ):
            raise DemoInitializationError(
                "DEMO_OUTPUT_RACE_DETECTED",
                "the demo output directory changed during initialization",
            )
    for directory in child_directories.values():
        if set(os.listdir(directory.fd)) != expected_child_entries[directory.fd]:
            raise DemoInitializationError(
                "DEMO_OUTPUT_RACE_DETECTED",
                "the demo output directory changed during initialization",
            )


def _cleanup_owned_entries(
    *,
    parent_fd: int,
    root: _PinnedDirectory | None,
    child_directories: dict[str, _PinnedDirectory],
    written_files: list[_PinnedFile],
) -> None:
    for record in reversed(written_files):
        if _entry_matches(
            record.parent.fd,
            record.name,
            device=record.device,
            inode=record.inode,
            expected_mode=stat.S_IFREG,
        ):
            with suppress(OSError):
                os.unlink(record.name, dir_fd=record.parent.fd)
    if root is None:
        return
    for name, directory in reversed(child_directories.items()):
        if _entry_matches(
            root.fd,
            name,
            device=directory.device,
            inode=directory.inode,
            expected_mode=stat.S_IFDIR,
        ):
            with suppress(OSError):
                os.rmdir(name, dir_fd=root.fd)
    if _entry_matches(
        parent_fd,
        root.name,
        device=root.device,
        inode=root.inode,
        expected_mode=stat.S_IFDIR,
    ):
        with suppress(OSError):
            os.rmdir(root.name, dir_fd=parent_fd)


def _close_descriptors(
    *,
    parent_fd: int,
    root: _PinnedDirectory | None,
    child_directories: dict[str, _PinnedDirectory],
    written_files: list[_PinnedFile],
) -> None:
    for record in written_files:
        os.close(record.fd)
    for directory in child_directories.values():
        os.close(directory.fd)
    if root is not None:
        os.close(root.fd)
    os.close(parent_fd)


def initialize_demo(output_dir: Path) -> DemoInitializationResult:
    """Create a new demo directory without overwriting any existing target."""

    payloads = _load_and_validate_assets()
    _require_descriptor_safe_platform()
    logical_output = Path(os.path.abspath(output_dir))
    logical_parent = logical_output.parent
    if not logical_output.name:
        raise DemoInitializationError(
            "DEMO_OUTPUT_EXISTS",
            "the demo output target already exists; choose a new directory",
        )
    try:
        logical_parent.mkdir(parents=True, exist_ok=True)
        resolved_parent = logical_parent.resolve(strict=True)
        parent_fd = os.open(resolved_parent, _directory_open_flags())
    except OSError as exc:
        raise DemoInitializationError(
            "DEMO_OUTPUT_UNAVAILABLE",
            "the demo output directory cannot be created",
        ) from exc

    root: _PinnedDirectory | None = None
    child_directories: dict[str, _PinnedDirectory] = {}
    written_files: list[_PinnedFile] = []
    try:
        parent_metadata = os.fstat(parent_fd)
        try:
            os.stat(logical_output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise DemoInitializationError(
                "DEMO_OUTPUT_EXISTS",
                "the demo output target already exists; choose a new directory",
            )
        os.mkdir(logical_output.name, mode=0o700, dir_fd=parent_fd)
        try:
            root = _open_pinned_directory(parent_fd, logical_output.name)
        except OSError as exc:
            raise DemoInitializationError(
                "DEMO_OUTPUT_RACE_DETECTED",
                "the demo output directory changed during initialization",
            ) from exc
        _write_all_assets(root, payloads, child_directories, written_files)
        _verify_completed_output(
            logical_parent=logical_parent,
            logical_output=logical_output,
            parent_fd=parent_fd,
            parent_metadata=parent_metadata,
            root=root,
            child_directories=child_directories,
            written_files=written_files,
        )
    except FileExistsError as exc:
        _cleanup_owned_entries(
            parent_fd=parent_fd,
            root=root,
            child_directories=child_directories,
            written_files=written_files,
        )
        raise DemoInitializationError(
            "DEMO_OUTPUT_EXISTS",
            "the demo output target already exists; choose a new directory",
        ) from exc
    except DemoInitializationError:
        _cleanup_owned_entries(
            parent_fd=parent_fd,
            root=root,
            child_directories=child_directories,
            written_files=written_files,
        )
        raise
    except OSError as exc:
        _cleanup_owned_entries(
            parent_fd=parent_fd,
            root=root,
            child_directories=child_directories,
            written_files=written_files,
        )
        raise DemoInitializationError(
            "DEMO_OUTPUT_WRITE_FAILED",
            "the demo asset bundle could not be written completely",
        ) from exc
    finally:
        _close_descriptors(
            parent_fd=parent_fd,
            root=root,
            child_directories=child_directories,
            written_files=written_files,
        )

    return DemoInitializationResult(
        classification="PUBLIC_SYNTHETIC",
        files=tuple(sorted(payloads)),
    )
