"""Fetch and verify the pinned Alpine APK closure without trusting filenames.

The lock is the authority.  Downloads are restricted to the official Alpine
HTTPS host, redirects and proxies are disabled, and every byte is checked
before it becomes part of the temporary build input repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
from email.message import Message
from pathlib import Path, PurePosixPath
from typing import IO, Any
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

SCHEMA = "proofflow.reference-video.alpine-apk-closure.v1"
BASE_IMAGE_DIGEST = "sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb"
OFFICIAL_HOST = "dl-cdn.alpinelinux.org"
ALPINE_RELEASE = "v3.24"
ARCHITECTURE = "x86_64"
REPOSITORIES = {"main", "community"}
MAX_PACKAGES = 256
MAX_PACKAGE_BYTES = 96 * 1024 * 1024
MAX_TOTAL_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_TAR_MEMBERS = 262_144
APK_BINARY = "/sbin/apk"
APK_KEYS_DIR = Path("/etc/apk/keys")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*\.apk$")
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.~-]*-r[0-9]+$")
SIGNATURE_RE = re.compile(r"^\.SIGN\.RSA\.([A-Za-z0-9@._+-]+\.rsa\.pub)$")
SIGNATURE_KEY_RE = re.compile(r"^[A-Za-z0-9@._+-]+\.rsa\.pub$")


class ClosureFailure(Exception):
    """A closed-set closure failure safe to expose in CI."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> Request | None:
        raise ClosureFailure("REDIRECT_FORBIDDEN")


def _strict_json(raw: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ClosureFailure("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ClosureFailure("NONFINITE_JSON_NUMBER")
            ),
        )
    except ClosureFailure:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ClosureFailure("INVALID_LOCK_JSON") from error


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ClosureFailure("BUNDLE_FILE_UNREADABLE") from error
    return "sha256:" + digest.hexdigest()


def _require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ClosureFailure(code)
    return value


def _require_signature_key(value: object) -> str:
    if not isinstance(value, str) or SIGNATURE_KEY_RE.fullmatch(value) is None:
        raise ClosureFailure("SIGNATURE_KEY_INVALID")
    return value


def _validate_url(url: object, repository: str, filename: str) -> str:
    if not isinstance(url, str):
        raise ClosureFailure("URL_INVALID")
    parsed = urlsplit(url)
    expected_path = f"/alpine/{ALPINE_RELEASE}/{repository}/{ARCHITECTURE}/{filename}"
    if (
        parsed.scheme != "https"
        or parsed.hostname != OFFICIAL_HOST
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
    ):
        raise ClosureFailure("URL_NOT_OFFICIAL_PINNED_PATH")
    return url


def _exact_keys(value: object, required: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        raise ClosureFailure(code)
    return value


def validate_lock(document: object) -> dict[str, Any]:
    lock = _exact_keys(
        document,
        {
            "schema",
            "base_image",
            "alpine_release",
            "architecture",
            "availability",
            "root_packages",
            "repositories",
            "package_count",
            "total_package_bytes",
            "packages",
        },
        "LOCK_KEYSET_INVALID",
    )
    if lock["schema"] != SCHEMA:
        raise ClosureFailure("LOCK_SCHEMA_INVALID")
    if _require_digest(lock["base_image"], "BASE_IMAGE_DIGEST_INVALID") != BASE_IMAGE_DIGEST:
        raise ClosureFailure("BASE_IMAGE_DIGEST_MISMATCH")
    if lock["alpine_release"] != ALPINE_RELEASE or lock["architecture"] != ARCHITECTURE:
        raise ClosureFailure("LOCK_PLATFORM_INVALID")
    if lock["availability"] != "UNKNOWN":
        raise ClosureFailure("AVAILABILITY_MUST_REMAIN_UNKNOWN")
    roots = lock["root_packages"]
    if not isinstance(roots, list) or not roots or len(set(roots)) != len(roots):
        raise ClosureFailure("ROOT_PACKAGES_INVALID")
    if any(not isinstance(root, str) or "=" not in root or len(root) > 160 for root in roots):
        raise ClosureFailure("ROOT_PACKAGES_INVALID")

    repositories = lock["repositories"]
    if not isinstance(repositories, list) or len(repositories) != len(REPOSITORIES):
        raise ClosureFailure("REPOSITORIES_INVALID")
    seen_repositories: set[str] = set()
    repository_keys: set[str] = set()
    for raw_repository in repositories:
        repository = _exact_keys(
            raw_repository,
            {"name", "signature_key", "signature_key_sha256"},
            "REPOSITORY_KEYSET_INVALID",
        )
        name = repository["name"]
        if not isinstance(name, str) or name not in REPOSITORIES or name in seen_repositories:
            raise ClosureFailure("REPOSITORY_NAME_INVALID")
        seen_repositories.add(name)
        repository_keys.add(_require_signature_key(repository["signature_key"]))
        _require_digest(repository["signature_key_sha256"], "SIGNATURE_KEY_DIGEST_INVALID")

    packages = lock["packages"]
    if not isinstance(packages, list) or not packages or len(packages) > MAX_PACKAGES:
        raise ClosureFailure("PACKAGE_COUNT_LIMIT")
    if lock["package_count"] != len(packages):
        raise ClosureFailure("PACKAGE_COUNT_MISMATCH")
    names: set[str] = set()
    filenames: set[str] = set()
    urls: set[str] = set()
    total = 0
    last_filename = ""
    for raw_package in packages:
        package = _exact_keys(
            raw_package,
            {
                "name",
                "version",
                "origin",
                "build_commit",
                "architecture",
                "repository",
                "filename",
                "url",
                "size",
                "sha256",
                "signature_key",
            },
            "PACKAGE_KEYSET_INVALID",
        )
        name = package["name"]
        version = package["version"]
        filename = package["filename"]
        repository = package["repository"]
        package_architecture = package["architecture"]
        if not isinstance(name, str) or PACKAGE_NAME_RE.fullmatch(name) is None:
            raise ClosureFailure("PACKAGE_NAME_INVALID")
        if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
            raise ClosureFailure("PACKAGE_VERSION_INVALID")
        if name in names:
            raise ClosureFailure("DUPLICATE_PACKAGE_NAME")
        names.add(name)
        if not isinstance(filename, str) or FILENAME_RE.fullmatch(filename) is None:
            raise ClosureFailure("PACKAGE_FILENAME_INVALID")
        if filename != f"{name}-{version}.apk":
            raise ClosureFailure("PACKAGE_FILENAME_METADATA_MISMATCH")
        if filename in filenames or filename <= last_filename:
            raise ClosureFailure("PACKAGE_FILENAME_ORDER_OR_DUPLICATE")
        filenames.add(filename)
        last_filename = filename
        if not isinstance(repository, str) or repository not in REPOSITORIES:
            raise ClosureFailure("PACKAGE_REPOSITORY_INVALID")
        if package_architecture not in {ARCHITECTURE, "noarch"}:
            raise ClosureFailure("PACKAGE_ARCHITECTURE_INVALID")
        url = _validate_url(package["url"], repository, filename)
        if url in urls:
            raise ClosureFailure("DUPLICATE_PACKAGE_URL")
        urls.add(url)
        size = package["size"]
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_PACKAGE_BYTES:
            raise ClosureFailure("PACKAGE_SIZE_INVALID")
        total += size
        if total > MAX_TOTAL_PACKAGE_BYTES:
            raise ClosureFailure("TOTAL_PACKAGE_SIZE_LIMIT")
        _require_digest(package["sha256"], "PACKAGE_DIGEST_INVALID")
        if not isinstance(package["origin"], str) or not package["origin"]:
            raise ClosureFailure("PACKAGE_ORIGIN_INVALID")
        commit = package["build_commit"]
        if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            raise ClosureFailure("PACKAGE_BUILD_COMMIT_INVALID")
        if _require_signature_key(package["signature_key"]) not in repository_keys:
            raise ClosureFailure("PACKAGE_SIGNATURE_KEY_NOT_PINNED")
    if lock["total_package_bytes"] != total:
        raise ClosureFailure("TOTAL_PACKAGE_SIZE_MISMATCH")
    available_roots = {f"{package['name']}={package['version']}" for package in packages}
    if not set(roots).issubset(available_roots):
        raise ClosureFailure("ROOT_PACKAGE_NOT_IN_CLOSURE")
    return lock


def load_lock(path: Path) -> dict[str, Any]:
    try:
        file_stat = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_size > 4 * 1024 * 1024
        ):
            raise ClosureFailure("LOCK_FILE_INVALID")
        return validate_lock(_strict_json(path.read_bytes()))
    except ClosureFailure:
        raise
    except OSError as error:
        raise ClosureFailure("LOCK_FILE_UNREADABLE") from error


def _prepare_output(path: Path) -> None:
    try:
        if path.exists() or path.is_symlink():
            file_stat = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(file_stat.st_mode) or any(path.iterdir()):
                raise ClosureFailure("OUTPUT_DIRECTORY_NOT_EMPTY_OR_UNSAFE")
        else:
            path.mkdir(mode=0o700, parents=True)
    except ClosureFailure:
        raise
    except OSError as error:
        raise ClosureFailure("OUTPUT_DIRECTORY_UNAVAILABLE") from error


def _download(url: str, destination: Path, expected_size: int, expected_digest: str) -> None:
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    temporary = destination.with_name(destination.name + ".part")
    try:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if (
            destination.exists()
            or destination.is_symlink()
            or temporary.exists()
            or temporary.is_symlink()
        ):
            raise ClosureFailure("DOWNLOAD_DESTINATION_EXISTS")
        request = Request(url, headers={"User-Agent": "ProofFlow-APK-Closure/1"})
        with opener.open(request, timeout=30) as response:
            if response.status != 200 or response.geturl() != url:
                raise ClosureFailure("DOWNLOAD_HTTP_OR_FINAL_URL_INVALID")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    if int(content_length) != expected_size:
                        raise ClosureFailure("DOWNLOAD_CONTENT_LENGTH_MISMATCH")
                except ValueError as error:
                    raise ClosureFailure("DOWNLOAD_CONTENT_LENGTH_INVALID") from error
            digest = hashlib.sha256()
            total = 0
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    while True:
                        chunk = response.read(min(1024 * 1024, expected_size + 1 - total))
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > expected_size:
                            raise ClosureFailure("DOWNLOAD_SIZE_LIMIT")
                        digest.update(chunk)
                        handle.write(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                if temporary.exists():
                    temporary.unlink()
                raise
        if total != expected_size:
            raise ClosureFailure("DOWNLOAD_SIZE_MISMATCH")
        if "sha256:" + digest.hexdigest() != expected_digest:
            raise ClosureFailure("DOWNLOAD_DIGEST_MISMATCH")
        os.replace(temporary, destination)
        destination.chmod(0o444)
    except ClosureFailure:
        if temporary.exists():
            temporary.unlink()
        raise
    except Exception as error:
        if temporary.exists():
            temporary.unlink()
        raise ClosureFailure("DOWNLOAD_FAILED") from error


def _read_tar_member(archive: tarfile.TarFile, name: str, limit: int) -> bytes:
    members = [member for member in archive.getmembers() if member.name == name]
    if len(members) != 1 or not members[0].isreg() or members[0].size > limit:
        raise ClosureFailure("ARCHIVE_REQUIRED_MEMBER_INVALID")
    stream = archive.extractfile(members[0])
    if stream is None:
        raise ClosureFailure("ARCHIVE_REQUIRED_MEMBER_INVALID")
    payload = stream.read(limit + 1)
    if len(payload) != members[0].size or len(payload) > limit:
        raise ClosureFailure("ARCHIVE_REQUIRED_MEMBER_INVALID")
    return payload


def _archive_signature_key(archive: tarfile.TarFile) -> str:
    members = archive.getmembers()
    if len(members) > MAX_TAR_MEMBERS:
        raise ClosureFailure("ARCHIVE_MEMBER_LIMIT")
    keys: list[str] = []
    for member in members:
        path = PurePosixPath(member.name)
        if member.name.startswith("/") or "\\" in member.name or ".." in path.parts:
            raise ClosureFailure("ARCHIVE_PATH_TRAVERSAL")
        match = SIGNATURE_RE.fullmatch(member.name)
        if match is not None:
            if not member.isreg() or member.size <= 0 or member.size > 16 * 1024:
                raise ClosureFailure("ARCHIVE_SIGNATURE_MEMBER_INVALID")
            keys.append(match.group(1))
    if len(keys) != 1:
        raise ClosureFailure("ARCHIVE_SIGNATURE_COUNT_INVALID")
    return keys[0]


def _parse_pkginfo(payload: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    scalar = {"pkgname", "pkgver", "origin", "commit", "arch"}
    try:
        text = payload.decode("utf-8")
    except UnicodeError as error:
        raise ClosureFailure("PKGINFO_INVALID") from error
    for line in text.splitlines():
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        if key in scalar:
            if key in values or not value:
                raise ClosureFailure("PKGINFO_INVALID")
            values[key] = value
    if set(values) != scalar:
        raise ClosureFailure("PKGINFO_INVALID")
    return values


def verify_package(path: Path, package: dict[str, Any]) -> None:
    if path.is_symlink() or not path.is_file():
        raise ClosureFailure("BUNDLE_PACKAGE_NOT_REGULAR")
    if path.stat().st_size != package["size"] or _digest_file(path) != package["sha256"]:
        raise ClosureFailure("BUNDLE_PACKAGE_BYTES_MISMATCH")
    try:
        with tarfile.open(path, "r:*") as archive:
            key = _archive_signature_key(archive)
            metadata = _parse_pkginfo(_read_tar_member(archive, ".PKGINFO", 1024 * 1024))
    except ClosureFailure:
        raise
    except (OSError, tarfile.TarError) as error:
        raise ClosureFailure("PACKAGE_ARCHIVE_INVALID") from error
    if key != package["signature_key"]:
        raise ClosureFailure("PACKAGE_SIGNATURE_KEY_MISMATCH")
    expected = {
        "pkgname": package["name"],
        "pkgver": package["version"],
        "origin": package["origin"],
        "commit": package["build_commit"],
        "arch": package["architecture"],
    }
    if metadata != expected:
        raise ClosureFailure("PACKAGE_METADATA_MISMATCH")


def verify_signatures(output: Path, lock: dict[str, Any]) -> None:
    """Use only the fixed base image key directory and apk's verifier."""
    if not APK_KEYS_DIR.is_dir() or APK_KEYS_DIR.is_symlink():
        raise ClosureFailure("FIXED_APK_KEYS_UNAVAILABLE")
    keys = {repository["signature_key"] for repository in lock["repositories"]}
    keys.update(package["signature_key"] for package in lock["packages"])
    for key_name in keys:
        key_path = APK_KEYS_DIR / key_name
        if key_path.is_symlink() or not key_path.is_file():
            raise ClosureFailure("FIXED_APK_SIGNING_KEY_MISSING")
        expected = next(
            repository["signature_key_sha256"]
            for repository in lock["repositories"]
            if repository["signature_key"] == key_name
        )
        if _digest_file(key_path) != expected:
            raise ClosureFailure("FIXED_APK_SIGNING_KEY_DIGEST_MISMATCH")
    paths = [
        str(output / ALPINE_RELEASE / package["repository"] / ARCHITECTURE / package["filename"])
        for package in lock["packages"]
    ]
    command = [APK_BINARY, "--keys-dir", "/etc/apk/keys", "verify", *paths]
    if "--allow-untrusted" in command:
        raise ClosureFailure("APK_SIGNATURE_BYPASS_FORBIDDEN")
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": "/sbin:/usr/sbin:/usr/bin:/bin", "HOME": "/nonexistent"},
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ClosureFailure("APK_SIGNATURE_VERIFICATION_UNAVAILABLE") from error
    if completed.returncode != 0:
        raise ClosureFailure("APK_SIGNATURE_VERIFICATION_FAILED")


def expected_paths(lock: dict[str, Any]) -> set[Path]:
    paths: set[Path] = set()
    for package in lock["packages"]:
        paths.add(Path(ALPINE_RELEASE) / package["repository"] / ARCHITECTURE / package["filename"])
    return paths


def verify_directory(output: Path, lock: dict[str, Any]) -> None:
    wanted = expected_paths(lock)
    actual: set[Path] = set()
    try:
        for path in output.rglob("*"):
            relative = path.relative_to(output)
            if path.is_symlink():
                raise ClosureFailure("BUNDLE_SYMLINK_FORBIDDEN")
            if path.is_file():
                actual.add(relative)
            elif not path.is_dir():
                raise ClosureFailure("BUNDLE_SPECIAL_FILE_FORBIDDEN")
    except ClosureFailure:
        raise
    except OSError as error:
        raise ClosureFailure("BUNDLE_DIRECTORY_UNREADABLE") from error
    if actual != wanted:
        raise ClosureFailure("BUNDLE_MEMBER_SET_MISMATCH")
    for package in lock["packages"]:
        verify_package(
            output / ALPINE_RELEASE / package["repository"] / ARCHITECTURE / package["filename"],
            package,
        )


def fetch(lock: dict[str, Any], output: Path) -> None:
    _prepare_output(output)
    for package in lock["packages"]:
        destination = (
            output / ALPINE_RELEASE / package["repository"] / ARCHITECTURE / package["filename"]
        )
        _download(package["url"], destination, package["size"], package["sha256"])
        verify_package(destination, package)
    verify_directory(output, lock)
    verify_signatures(output, lock)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        lock = load_lock(args.lock)
        fetch(lock, args.output)
        result = {
            "schema": SCHEMA,
            "status": "PASS",
            "package_count": lock["package_count"],
            "total_package_bytes": lock["total_package_bytes"],
            "availability": "UNKNOWN",
        }
        status = 0
    except ClosureFailure as error:
        result = {"schema": SCHEMA, "status": "FAIL", "error_code": error.code}
        status = 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    raise SystemExit(status)


if __name__ == "__main__":
    main()
