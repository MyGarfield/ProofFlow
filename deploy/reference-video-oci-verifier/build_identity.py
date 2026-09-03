"""Create the immutable toolchain identity embedded in the verifier image."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import subprocess
from pathlib import Path

BASE_DIGEST = "sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb"
TOOLS = {
    "git": "/usr/bin/git",
    "python": "/usr/local/bin/python3.12",
    "ffmpeg": "/usr/bin/ffmpeg",
    "ffprobe": "/usr/bin/ffprobe",
    "tesseract": "/usr/bin/tesseract",
}
TESSDATA = ("/usr/share/tessdata/eng.traineddata", "/usr/share/tessdata/chi_sim.traineddata")
FONT_ROOT = "/usr/share/fonts/noto-cjk"
APK_INSTALLED = "/lib/apk/db/installed"


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    return sha256_bytes(Path(path).read_bytes())


def command_first_line(command: list[str]) -> str:
    output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
    return next((line.strip() for line in output.splitlines() if line.strip()), "")


def tree_digest(root: str) -> dict[str, object]:
    base = Path(root)
    entries: list[tuple[str, str]] = []
    if not base.is_dir():
        return {"root": root, "file_count": 0, "sha256": None}
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(base).as_posix()
        entries.append((relative, sha256_file(str(path))))
    payload = json.dumps(
        entries, ensure_ascii=False, separators=(",", ":"), sort_keys=False
    ).encode()
    return {"root": root, "file_count": len(entries), "sha256": sha256_bytes(payload)}


def apk_closure() -> dict[str, object]:
    path = Path(APK_INSTALLED)
    if not path.is_file():
        return {"db_path": APK_INSTALLED, "db_sha256": None, "packages": []}
    packages: list[str] = []
    current: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "":
            if "P" in current and "V" in current:
                packages.append(f"{current['P']}={current['V']}")
            current = {}
        elif ":" in line:
            key, value = line.split(":", 1)
            current[key] = value
    if "P" in current and "V" in current:
        packages.append(f"{current['P']}={current['V']}")
    return {
        "db_path": APK_INSTALLED,
        "db_sha256": sha256_file(APK_INSTALLED),
        "packages": sorted(packages),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact-commit", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--schema-sha256", required=True)
    parser.add_argument("--validator-sha256", required=True)
    parser.add_argument("--alpine-lock", type=Path, required=True)
    parser.add_argument("--python-lock", type=Path, required=True)
    args = parser.parse_args()

    tools: dict[str, dict[str, str]] = {}
    for name, path in TOOLS.items():
        if name == "python":
            version = platform.python_version()
        elif name == "git" or name == "tesseract":
            version = command_first_line([path, "--version"])
        else:
            version = command_first_line([path, "-version"])
        tools[name] = {"path": path, "sha256": sha256_file(path), "version": version}

    locale_output = subprocess.check_output(["/usr/bin/locale", "-a"], text=True)
    identity = {
        "schema": "proofflow.reference-runtime-oci-verifier.image-identity.v1",
        "platform": "linux/amd64",
        "base_image": {
            "ref": "python:3.12-alpine",
            "child_digest": BASE_DIGEST,
        },
        "build_inputs": {
            "artifact_commit": args.artifact_commit,
            "manifest_sha256": args.manifest_sha256,
            "schema_sha256": args.schema_sha256,
            "validator_sha256": args.validator_sha256,
            "alpine_packages_lock_sha256": sha256_file(str(args.alpine_lock)),
            "python_requirements_lock_sha256": sha256_file(str(args.python_lock)),
        },
        "tools": tools,
        "jsonschema_version": importlib.metadata.version("jsonschema"),
        "apk_installed_closure": apk_closure(),
        "locale": {"name": "C.UTF-8", "available": "C.UTF-8" in locale_output.split()},
        "locale_inventory_sha256": sha256_bytes(locale_output.encode()),
        "tessdata": [{"path": path, "sha256": sha256_file(path)} for path in TESSDATA],
        "font_inventory": tree_digest(FONT_ROOT),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(identity, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
