#!/usr/bin/env python3
"""Collect narrow offline evidence for the pinned Aliyun security-scan Skill.

The upstream ``main.sh`` is intentionally not executed: it always invokes
``openclaw security audit --deep`` even with cloud analysis disabled. This
collector verifies the exact upstream snapshot, records that behavior, and
scans temporary copies of exactly eight public ProofFlow Skill contracts.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.2"
CLAIM_LEVEL = "OFFLINE_PINNED_SOURCE_AND_STATIC_CONTRACT_REPLAY_ONLY"
PROOFFLOW_BASE_COMMIT = "b63eeb60d1072c73d2d0d1d6061b3c8f800487a4"
UPSTREAM_REPOSITORY = "https://github.com/aliyun/alibabacloud-aiops-skills"
UPSTREAM_TAG = "alibabacloud-openclaw-skill-security-scan-0.0.1"
UPSTREAM_COMMIT = "3cdce6a5ead21b4aec740d97ae30eb0b71c1c786"
UPSTREAM_REPOSITORY_PATH = (
    "skills/security/riskmanagement/alibabacloud-openclaw-skill-security-scan"
)
VENDORED_PATH = "third_party/aliyun/alibabacloud-openclaw-skill-security-scan/upstream"
SANDBOX_PROFILE = "(version 1) (allow default) (deny network*)"
OFFICIAL_EMPTY_TARGET_REASON = "OFFICIAL_TARGET_POLICY_EXCLUDES_SKILL_MD_ONLY_INPUTS"
NETWORK_POSITIVE_CONTROL = "LOOPBACK_IPV4_TCP_CONNECT_SUCCEEDED"
PYTHON_LAUNCHER_PATH = Path("/usr/bin/python3")
EXPECTED_PYTHON_LAUNCHER_SHA256 = (
    "sha256:179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818"
)
EXPECTED_RESOLVED_PYTHON_PATH = Path(
    "/Library/Developer/CommandLineTools/Library/Frameworks/"
    "Python3.framework/Versions/3.9/bin/python3.9"
)
EXPECTED_RESOLVED_PYTHON_SHA256 = (
    "sha256:bdea59019a38eb6600cc9e71e984a97fedadc406448431281e7657030f54987e"
)
UPSTREAM_ROOT_TREE = "c0d8dde900cce28dd7b07321a873cca1efa40d94"
UPSTREAM_SUBTREE_TREE = "3f097e3281d89bb59ce9a638e846070d47bcbcdc"

SOURCE_DIGESTS = {
    "SKILL.md": "sha256:d5df78b1d78361596b626fb129567e2fb69eb65002de7545e451b1f648311e80",
    "assets/LICENSE.txt": (
        "sha256:c4db38611836ea364d14273ebfe902b106e220f07b8f723b8230125be7f2795b"
    ),
    "references/baseline.md": (
        "sha256:b2bee705755d001079dadf4da9e1462d275c44a44fd08f7ba233835389be21b4"
    ),
    "references/report_template.md": (
        "sha256:9f52e97e0075dc609be666c259155b253280bb96c109f9c6f7a8d09d23b3ddbf"
    ),
    "references/skillaudit.md": (
        "sha256:41de28a8680332ccfca1dcf247dd261fdd3e12de3dd660869dbd2d4f16764be4"
    ),
    "scripts/basic_udf.sh": (
        "sha256:9fdf8763b6bfc5c5b681d781c7ab49caa36aa94125799d295441fbe952997466"
    ),
    "scripts/main.sh": ("sha256:a0a4cf6a04bd8e367cf984cc385fcf9f2e11a00a9f96d3ab3eb88c424d508f94"),
    "scripts/skill_zip_packager.sh": (
        "sha256:f61362ef8c2a3ba6ecf7e4f34740757dfb35b017def5e5bd5378818583824a47"
    ),
}

SOURCE_GIT_BLOB_OIDS = {
    "SKILL.md": "2a30f79d7ec60fd6e54b3a6ecf6d72a1e54ce435",
    "assets/LICENSE.txt": "80e4229339bf299202b1246d82d1d83174617b93",
    "references/baseline.md": "075624512c0cc00ffe89527c5e39d94fc299370f",
    "references/report_template.md": "1d4c3f14ee400b589cc0c961614ad3e492ad417e",
    "references/skillaudit.md": "3f254b6e1ac435d74b3faaf3a4ebfb18531af188",
    "scripts/basic_udf.sh": "9b4c85153c448c9b858aba4e410059fba1db7afa",
    "scripts/main.sh": "ee8070ae54d9039a930f489b8f85f2de3c22ce9c",
    "scripts/skill_zip_packager.sh": "f4cd0fdc47dfd8fe0d0c43e9e524a3a4cf59781d",
}

EXPECTED_SKILLS = (
    "conflict_detect",
    "decision_audit",
    "deterministic_calculate",
    "document_package",
    "evidence_ingest",
    "human_approval",
    "rule_retrieve",
    "timeline_build",
)

SCENARIOS = (
    (1, "REVERSE_SHELL_OR_BACKDOOR", "CRITICAL"),
    (2, "CREDENTIAL_HARVESTING", "CRITICAL"),
    (3, "DATA_EXFILTRATION", "HIGH"),
    (4, "CRYPTOMINER", "CRITICAL"),
    (5, "PERMISSION_ABUSE", "HIGH"),
    (6, "PROMPT_INJECTION", "HIGH"),
    (7, "CODE_OBFUSCATION", "MEDIUM"),
    (8, "RANSOMWARE", "CRITICAL"),
    (9, "PERSISTENCE", "MEDIUM"),
    (10, "SUPPLY_CHAIN_ATTACK", "MEDIUM"),
    (11, "MALICIOUS_DOWNLOADER", "CRITICAL"),
    (12, "PRIVACY_DATA_EXPOSURE", "MEDIUM"),
)

SUPPLEMENTAL_CHECKS = {
    "ABSOLUTE_USER_PATH": re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\)"),
    "CLOUD_OR_SERVICE_TOKEN_LITERAL": re.compile(
        r"(?:AKIA[0-9A-Z]{16}|LTAI[0-9A-Za-z]{20}|gh[op]_[0-9A-Za-z]{36}|"
        r"glpat-[0-9A-Za-z-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,})"
    ),
    "CREDENTIAL_FILE_PATH": re.compile(
        r"(?:\.ssh/(?:id_rsa|id_ed25519)|\.aws/credentials|\.config/gh/hosts|"
        r"\.git-credentials|\.docker/config\.json|\.kube/config|\.env(?:\.|$))",
        re.IGNORECASE | re.MULTILINE,
    ),
    "DYNAMIC_EVAL": re.compile(r"\beval\s*\("),
    "EXPLICIT_PROMPT_OVERRIDE": re.compile(
        r"(?:ignore (?:all|previous).*instructions|system prompt.*override|"
        r"do anything now|\bjailbreak\b)",
        re.IGNORECASE,
    ),
    "EXTERNAL_URL_LITERAL": re.compile(r"https?://[^\s)>\]}`]+", re.IGNORECASE),
    "HARDCODED_SECRET_ASSIGNMENT": re.compile(
        r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)"
        r"\s*[:=]\s*['\"][^'\"]{16,}['\"]",
        re.IGNORECASE,
    ),
    "PRIVATE_KEY_BLOCK": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "SHELL_OR_DOWNLOADER_COMMAND": re.compile(
        r"(?:\b(?:curl|wget|sudo)\b|\bnc\s+-[elp]|\b(?:bash|sh)\s+-c\b)",
        re.IGNORECASE,
    ),
}

FIXED_ENVIRONMENT = {
    "ALIYUN_SKILL_SEC_CLOUD": "false",
    "HOME": "/var/empty",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "PROOFFLOW_NETWORK_POSITIVE_CONTROL": NETWORK_POSITIVE_CONTROL,
    "PROOFFLOW_NETWORK_SANDBOX": "macos-sandbox-exec-deny-network-v1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "REPORT_LANG": "zh",
}
OPTIONAL_OS_ENVIRONMENT = {
    "CPATH",
    "LIBRARY_PATH",
    "MANPATH",
    "SDKROOT",
    "TMPDIR",
    "__CF_USER_TEXT_ENCODING",
}
SENSITIVE_ENVIRONMENT_NAMES = {
    "ALL_PROXY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "OPENAI_API_KEY",
    "ALIBABA_CLOUD_ACCESS_KEY_ID",
    "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
}


class CollectionError(RuntimeError):
    """The offline collection contract was not satisfied."""


def sha256_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _canonical_sandbox_command(collected_at: str) -> list[str]:
    """Return the public, path-redacted contract for the executed runner command."""
    return [
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME=/var/empty",
        "TMPDIR=<bounded-ephemeral>",
        "LANG=C",
        "LC_ALL=C",
        "ALIYUN_SKILL_SEC_CLOUD=false",
        "REPORT_LANG=zh",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONHASHSEED=0",
        f"PROOFFLOW_NETWORK_POSITIVE_CONTROL={NETWORK_POSITIVE_CONTROL}",
        "PROOFFLOW_NETWORK_SANDBOX=macos-sandbox-exec-deny-network-v1",
        "/usr/bin/sandbox-exec",
        "-p",
        SANDBOX_PROFILE,
        "/usr/bin/python3",
        "-I",
        "-S",
        "<bounded-ephemeral>/collector.py",
        "--source-root",
        "<bounded-ephemeral>/source",
        "--skills-root",
        "<bounded-ephemeral>/skills",
        "--collected-at",
        collected_at,
    ]


def _canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(payload)


def _git_object_oid(object_type: str, payload: bytes) -> str:
    header = f"{object_type} {len(payload)}\0".encode()
    # Git's object format mandates SHA-1; this is identity reconstruction, not a safety digest.
    return hashlib.sha1(header + payload).hexdigest()


def _git_tree_oid(source_records: list[dict[str, Any]]) -> str:
    tree: dict[str, Any] = {}
    for record in source_records:
        parts = record["path"].split("/")
        node = tree
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = record

    def encode_tree(node: dict[str, Any]) -> str:
        entries: list[tuple[bytes, bytes]] = []
        for name, value in node.items():
            encoded_name = name.encode("utf-8")
            if isinstance(value, dict) and "git_blob_oid" not in value:
                oid = encode_tree(value)
                sort_key = encoded_name + b"/"
                entry = b"40000 " + encoded_name + b"\0" + bytes.fromhex(oid)
            else:
                oid = value["git_blob_oid"]
                sort_key = encoded_name
                entry = value["git_mode"].encode("ascii") + b" " + encoded_name + b"\0"
                entry += bytes.fromhex(oid)
            entries.append((sort_key, entry))
        body = b"".join(entry for _key, entry in sorted(entries))
        return _git_object_oid("tree", body)

    return encode_tree(tree)


def _secure_file_record(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    mode = metadata.st_mode & 0o777
    if metadata.st_uid != 0 or mode & 0o022:
        raise CollectionError("interpreter path is not root-owned and non-writable")
    return {
        "path": resolved.as_posix(),
        "sha256": sha256_bytes(resolved.read_bytes()),
        "owner_uid": metadata.st_uid,
        "owner_gid": metadata.st_gid,
        "mode": f"{mode:04o}",
        "bytes": metadata.st_size,
    }


def _interpreter_record() -> dict[str, Any]:
    if platform.system() != "Darwin":
        raise CollectionError("the recorded interpreter boundary is Darwin-only")
    if not sys.flags.isolated or not sys.flags.no_site or "site" in sys.modules:
        raise CollectionError("collector requires Python -I -S isolation")
    launcher = _secure_file_record(PYTHON_LAUNCHER_PATH)
    resolved = _secure_file_record(Path(sys.executable))
    if launcher["path"] != PYTHON_LAUNCHER_PATH.as_posix():
        raise CollectionError("Python launcher path changed")
    if launcher["sha256"] != EXPECTED_PYTHON_LAUNCHER_SHA256:
        raise CollectionError("Python launcher digest changed")
    if resolved["path"] != EXPECTED_RESOLVED_PYTHON_PATH.as_posix():
        raise CollectionError("resolved Python path changed")
    if resolved["sha256"] != EXPECTED_RESOLVED_PYTHON_SHA256:
        raise CollectionError("resolved Python digest changed")
    if sys.version_info < (3, 9):  # noqa: UP036 - runner intentionally audits system Python.
        raise CollectionError("root-owned system Python is too old")
    return {
        "invoked": launcher,
        "resolved": resolved,
        "python_version": platform.python_version(),
        "isolated_flag": True,
        "no_site_flag": True,
        "site_module_loaded": False,
    }


def _regular_files(root: Path) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        raise CollectionError("input root is missing or is a symlink")
    files: list[Path] = []
    for candidate in root.rglob("*"):
        if candidate.is_symlink():
            raise CollectionError("symlinks are forbidden in collection inputs")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise CollectionError("non-regular input object")
        files.append(candidate)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def _require_ephemeral_path(path: Path, temp_root: Path) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(temp_root)
    except ValueError as exc:
        raise CollectionError("collector inputs must be isolated beneath TMPDIR") from exc
    return resolved


def _validate_environment() -> tuple[list[str], list[str], Path]:
    for name, expected in FIXED_ENVIRONMENT.items():
        if os.environ.get(name) != expected:
            raise CollectionError("sanitized command environment is not active")
    temp_value = os.environ.get("TMPDIR")
    if not temp_value:
        raise CollectionError("TMPDIR is required")
    temp_root = Path(temp_value).resolve(strict=True)
    if temp_root == Path("/") or not str(temp_root).startswith(("/tmp/", "/private/tmp/")):
        raise CollectionError("TMPDIR is not a bounded ephemeral directory")
    observed = set(os.environ)
    allowed = set(FIXED_ENVIRONMENT) | OPTIONAL_OS_ENVIRONMENT
    if observed - allowed:
        raise CollectionError("unexpected environment names are present")
    sensitive = sorted(observed & SENSITIVE_ENVIRONMENT_NAMES)
    if sensitive:
        raise CollectionError("sensitive environment names are present")
    injected = sorted(observed & OPTIONAL_OS_ENVIRONMENT - {"TMPDIR"})
    return sorted(observed), injected, temp_root


def _run_network_positive_control() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    accepted: socket.socket | None = None
    listener.settimeout(1)
    client.settimeout(1)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client.connect(listener.getsockname())
        accepted, _address = listener.accept()
    except OSError as exc:
        raise CollectionError("IPv4 TCP loopback positive control failed") from exc
    finally:
        if accepted is not None:
            accepted.close()
        client.close()
        listener.close()


def _require_network_denied() -> dict[str, Any]:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.25)
    try:
        probe.connect(("127.0.0.1", 9))
    except PermissionError as exc:
        if exc.errno != errno.EPERM:
            raise CollectionError("network probe failed for an unexpected reason") from exc
        return {
            "mechanism": "MACOS_SANDBOX_EXEC_DENY_NETWORK_ALL",
            "scope": "LOCAL_DARWIN_SEATBELT_COLLECTION_INVOCATION_ONLY",
            "enforced": True,
            "enforcement_test_scope": "IPV4_TCP_LOOPBACK_ONLY",
            "sandbox_profile": SANDBOX_PROFILE,
            "sandbox_profile_sha256": sha256_bytes(SANDBOX_PROFILE.encode("utf-8")),
            "positive_control": {
                "phase": "PRE_SANDBOX_SAME_HOST",
                "transport": "IPV4_TCP_LOOPBACK",
                "status": NETWORK_POSITIVE_CONTROL,
            },
            "negative_control": {
                "phase": "IN_SANDBOX_COLLECTOR",
                "target_class": "LOOPBACK_TCP_DISCARD_PORT",
                "status": "BLOCKED_EPERM",
                "errno": errno.EPERM,
            },
            "external_network_observed": False,
            "observation_semantics": (
                "A same-host IPv4/TCP positive control succeeded before Seatbelt, then the "
                "sandboxed IPv4/TCP probe was denied with EPERM. This does not verify other hosts, "
                "transports, invocations, or filesystem read confinement."
            ),
        }
    except OSError as exc:
        raise CollectionError("network deny was not proven by EPERM") from exc
    finally:
        probe.close()
    raise CollectionError("network probe unexpectedly connected")


def _source_inventory(
    source_root: Path,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], str]:
    files = _regular_files(source_root)
    paths = [item.relative_to(source_root).as_posix() for item in files]
    if paths != sorted(SOURCE_DIGESTS):
        raise CollectionError("upstream source file set differs from pinned snapshot")
    records: list[dict[str, Any]] = []
    for source in files:
        relative_path = source.relative_to(source_root).as_posix()
        payload = source.read_bytes()
        digest = sha256_bytes(payload)
        if digest != SOURCE_DIGESTS[relative_path]:
            raise CollectionError("upstream source digest mismatch")
        git_blob_oid = _git_object_oid("blob", payload)
        if git_blob_oid != SOURCE_GIT_BLOB_OIDS[relative_path]:
            raise CollectionError("upstream source Git blob OID mismatch")
        records.append(
            {
                "path": relative_path,
                "sha256": digest,
                "bytes": len(payload),
                "git_mode": "100644",
                "git_object_type": "blob",
                "git_blob_oid": git_blob_oid,
            }
        )
    if _git_tree_oid(records) != UPSTREAM_SUBTREE_TREE:
        raise CollectionError("upstream subtree Git OID mismatch")
    source_map = {record["path"]: record for record in records}
    return records, source_map, (source_root / "scripts/main.sh").read_text(encoding="utf-8")


def _audit_implementation(source_root: Path, main_text: str) -> dict[str, Any]:
    basic_text = (source_root / "scripts/basic_udf.sh").read_text(encoding="utf-8")
    packager_text = (source_root / "scripts/skill_zip_packager.sh").read_text(encoding="utf-8")
    fragments = (
        "ALIYUN_SKILL_SEC_CLOUD=${ALIYUN_SKILL_SEC_CLOUD:-true}",
        'if [ "$ALIYUN_SKILL_SEC_CLOUD" = "true" ]; then',
        'if [ "$ALIYUN_SKILL_SEC_CLOUD" != "true" ]; then',
        "openclaw security audit --deep",
        "for cmd in openclaw curl grep date mkdir; do",
        "Skip SKILL.md and references/ to avoid false positives",
    )
    if any(fragment not in main_text for fragment in fragments):
        raise CollectionError("pinned main.sh behavior markers changed")
    if 'local host="riskpunish.aliyuncs.com"' not in basic_text:
        raise CollectionError("pinned cloud endpoint marker changed")
    if '--host) host="$2"' not in basic_text:
        raise CollectionError("pinned host override marker changed")
    if '-T "${zip_file}"' not in basic_text or '"$presigned_url"' not in basic_text:
        raise CollectionError("pinned upload behavior marker changed")
    if "local temp_dir=$(mktemp -d)" not in packager_text:
        raise CollectionError("pinned packaging behavior marker changed")
    if 'cp -r "$skill_path"' not in packager_text:
        raise CollectionError("pinned recursive-copy marker changed")
    pattern_count = len(re.findall(r"^\s*scan_pattern\s+", main_text, flags=re.MULTILINE))
    if pattern_count != 118:
        raise CollectionError("pinned static pattern count changed")
    bash_probe = subprocess.run(
        ["/bin/bash", "-c", 'printf "%s" "${BASH_VERSINFO[0]}"'],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if bash_probe.returncode != 0 or bash_probe.stdout != "3" or bash_probe.stderr:
        raise CollectionError("local Bash major version is not the audited value")
    return {
        "inventory_status": "ALL_8_UPSTREAM_FILES_HASHED_AND_CLASSIFIED",
        "files_reviewed": 8,
        "scripts_reviewed": 3,
        "main_required_commands": ["openclaw", "curl", "grep", "date", "mkdir"],
        "main_optional_commands": ["jq", "realpath", "zip", "tar"],
        "packager_commands": ["zip", "du", "cp", "find", "touch", "stat", "xargs"],
        "cloud_environment_default": "true",
        "collection_cloud_environment": "false",
        "cloud_disable_guards_verified": True,
        "cloud_upload_functions_present": True,
        "cloud_endpoint_declared": "riskpunish.aliyuncs.com",
        "cloud_enabled_data_classes": ["ZIP_MD5", "SKILL_NAME", "SKILL_ZIP_BYTES"],
        "host_override_supported": True,
        "presigned_upload_url_host_allowlist_enforced": False,
        "residual_openclaw_config_audit_when_cloud_disabled": True,
        "main_script_minimum_bash_major": 4,
        "local_bash_major_observed": 3,
        "official_main_execution_status": "NOT_EXECUTED_SAFETY_BOUNDARY",
        "official_main_non_execution_reasons": [
            "UNCONDITIONAL_OPENCLAW_DEEP_AUDIT_WOULD_READ_OUT_OF_SCOPE_CONFIGURATION",
            "LOCAL_BASH_BELOW_UPSTREAM_MINIMUM",
        ],
        "official_static_target_policy": [
            "package.json",
            "src/**",
            "scripts/** excluding scripts/main.sh and scripts/basic_udf.sh",
        ],
        "official_static_pattern_invocations": pattern_count,
    }


def _frontmatter_name(payload: str) -> str:
    if not payload.startswith("---\n"):
        raise CollectionError("skill frontmatter is missing")
    parts = payload.split("---", maxsplit=2)
    if len(parts) != 3:
        raise CollectionError("skill frontmatter is malformed")
    match = re.search(r"^name:\s*([^\s]+)\s*$", parts[1], flags=re.MULTILINE)
    if match is None:
        raise CollectionError("skill name is missing")
    return match.group(1)


def _skill_inventory(skills_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if sorted(item.name for item in skills_root.iterdir()) != list(EXPECTED_SKILLS):
        raise CollectionError("skill directory set is not the expected closed set")
    inputs: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for expected_name in EXPECTED_SKILLS:
        directory = skills_root / expected_name
        files = _regular_files(directory)
        if [item.relative_to(directory).as_posix() for item in files] != ["SKILL.md"]:
            raise CollectionError("each public Skill input must contain only SKILL.md")
        payload = files[0].read_bytes()
        text = payload.decode("utf-8")
        if _frontmatter_name(text) != expected_name:
            raise CollectionError("Skill frontmatter name differs from directory")
        matches = sorted(
            check_id for check_id, pattern in SUPPLEMENTAL_CHECKS.items() if pattern.search(text)
        )
        if matches:
            raise CollectionError("supplemental indicator scan found a blocked pattern")
        inputs.append(
            {
                "skill_name": expected_name,
                "relative_path": f"deploy/agentteams/skills/{expected_name}/SKILL.md",
                "sha256": sha256_bytes(payload),
                "bytes": len(payload),
                "regular_file": True,
                "directory_file_count": 1,
                "symlink_count": 0,
            }
        )
        results.append(
            {
                "skill_name": expected_name,
                "official_compatible_target_file_count": 0,
                "official_rule_replay_status": "INCONCLUSIVE_EMPTY_TARGET_SET",
                "official_rule_replay_reason_code": OFFICIAL_EMPTY_TARGET_REASON,
                "scenario_results": [
                    {
                        "scenario_id": scenario_id,
                        "name": name,
                        "severity": severity,
                        "status": "INCONCLUSIVE_EMPTY_TARGET_SET",
                        "match_count": None,
                    }
                    for scenario_id, name, severity in SCENARIOS
                ],
                "supplemental_contract_scan": {
                    "scope": "SKILL_MD_TEXT_ONLY",
                    "check_count": len(SUPPLEMENTAL_CHECKS),
                    "matched_check_ids": matches,
                    "status": "NO_INDICATOR_MATCHES",
                },
            }
        )
    return inputs, results


def collect(source_root: Path, skills_root: Path, collected_at: str) -> dict[str, Any]:
    try:
        timestamp = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CollectionError("collected-at must be RFC 3339 date-time") from exc
    if timestamp.tzinfo is None:
        raise CollectionError("collected-at must include a timezone")
    environment_names, injected_names, temp_root = _validate_environment()
    interpreter = _interpreter_record()
    network = _require_network_denied()
    isolated_source = _require_ephemeral_path(source_root, temp_root)
    isolated_skills = _require_ephemeral_path(skills_root, temp_root)
    source_files, source_map, main_text = _source_inventory(isolated_source)
    implementation = _audit_implementation(isolated_source, main_text)
    skill_inputs, results = _skill_inventory(isolated_skills)
    canonical_command = _canonical_sandbox_command(collected_at)
    git_object_manifest = {
        "object_format": "sha1",
        "tag_ref": f"refs/tags/{UPSTREAM_TAG}",
        "tag_object_type": "commit",
        "tag_ref_target": UPSTREAM_COMMIT,
        "commit": UPSTREAM_COMMIT,
        "root_tree": UPSTREAM_ROOT_TREE,
        "subtree_path": UPSTREAM_REPOSITORY_PATH,
        "subtree_tree": UPSTREAM_SUBTREE_TREE,
        "entry_source": "official_source.source_files",
        "entry_count": 8,
        "vendored_blob_oids_recomputed": True,
        "subtree_tree_recomputed": True,
        "tag_to_commit_offline_verified": False,
        "commit_to_root_tree_offline_verified": False,
        "provenance_semantics": (
            "Vendored blob and subtree OIDs are recomputed offline. The lightweight tag target, "
            "commit, and root tree remain an unsigned point-in-time public Git observation."
        ),
    }
    command_binding = {
        "canonical_argv_sha256": _canonical_json_sha256(canonical_command),
        "sandbox_profile_sha256": network["sandbox_profile_sha256"],
        "interpreter_invoked_sha256": interpreter["invoked"]["sha256"],
        "interpreter_resolved_sha256": interpreter["resolved"]["sha256"],
        "source_subtree_tree": git_object_manifest["subtree_tree"],
    }
    return {
        "$schema": "./aliyun-official-skill-offline-preflight.schema.json",
        "schema_version": SCHEMA_VERSION,
        "evidence_id": "aliyun-official-skill-offline-preflight-2026-08-21",
        "collected_at": collected_at,
        "claim_level": CLAIM_LEVEL,
        "subject": {
            "proof_flow_base_commit": PROOFFLOW_BASE_COMMIT,
            "public_skill_root": "deploy/agentteams/skills",
            "expected_skill_count": 8,
            "expected_skill_names": list(EXPECTED_SKILLS),
            "input_data_class": "PUBLIC_SKILL_CONTRACTS_ONLY",
        },
        "official_source": {
            "repository_url": UPSTREAM_REPOSITORY,
            "tag": UPSTREAM_TAG,
            "tag_object_type": "commit",
            "commit": UPSTREAM_COMMIT,
            "repository_path": UPSTREAM_REPOSITORY_PATH,
            "vendored_path": VENDORED_PATH,
            "tag_resolution_claim": "UNSIGNED_POINT_IN_TIME_GIT_OBSERVATION",
            "modification_status": "UNMODIFIED_HASH_MATCHED_VENDOR_SNAPSHOT",
            "acquisition": {
                "mode": "PUBLIC_GIT_HTTPS_WITH_CLEAN_ENVIRONMENT",
                "network_used": True,
                "credentials_used": False,
                "occurred_before_offline_collection": True,
                "content_reverified_by_hash_inside_sandbox": True,
            },
            "source_files": source_files,
            "git_object_manifest": git_object_manifest,
            "license": {
                "spdx_expression": "MIT",
                "path": "assets/LICENSE.txt",
                "sha256": source_map["assets/LICENSE.txt"]["sha256"],
                "copyright": "Copyright (c) 2026 AliyunSecAI",
                "license_text_vendored": True,
            },
        },
        "implementation_audit": implementation,
        "execution_boundary": {
            "runner": "PROOFFLOW_INDEPENDENT_OFFLINE_REPLAY_V1",
            "working_copy": "EPHEMERAL_COPY_OF_PINNED_SOURCE_AND_8_PUBLIC_SKILLS",
            "python_version": interpreter["python_version"],
            "interpreter": interpreter,
            "environment_cleared_before_process_start": True,
            "environment_names": environment_names,
            "os_injected_environment_names": injected_names,
            "sensitive_environment_names_present": [],
            "cloud_environment_value": "false",
            "home_directory_class": "EMPTY_SENTINEL_DIRECTORY",
            "temporary_directory_class": "BOUNDED_EPHEMERAL_DIRECTORY",
            "network": network,
            "command_contract": {
                "canonicalization": "COMPACT_JSON_UTF8_ARGV_WITH_ONLY_TMP_ROOT_REDACTED",
                "canonical_argv": canonical_command,
                "canonical_argv_sha256": _canonical_json_sha256(canonical_command),
                "binding_components": command_binding,
                "binding_sha256": _canonical_json_sha256(command_binding),
                "sandbox_exec_exit_status": "NOT_VERIFIED_IN_COLLECTOR_ARTIFACT",
                "exit_status_reason_code": (
                    "COLLECTOR_CANNOT_OBSERVE_PARENT_SANDBOX_EXEC_PROCESS_EXIT"
                ),
            },
            "credential_read_status": "NOT_OBSERVED_NOT_OS_ENFORCED",
            "openclaw_config_read_status": "NOT_OBSERVED_NOT_OS_ENFORCED",
            "real_openclaw_invoked": False,
            "live_agentteams_manager_accessed": False,
            "live_agentteams_worker_accessed": False,
            "llm_started": False,
        },
        "skill_inputs": skill_inputs,
        "scan": {
            "official_rule_source": {
                "path": "scripts/main.sh",
                "sha256": source_map["scripts/main.sh"]["sha256"],
                "scenario_count": 12,
                "pattern_invocation_count": 118,
            },
            "official_compatible_scan_status": "INCONCLUSIVE_NO_ANALYZABLE_TARGETS",
            "official_compatible_target_file_count": 0,
            "official_inconclusive_reason_code": OFFICIAL_EMPTY_TARGET_REASON,
            "supplemental_check_ids": sorted(SUPPLEMENTAL_CHECKS),
            "supplemental_scope": "EIGHT_PUBLIC_SKILL_MD_FILES_ONLY",
            "supplemental_status": "NO_INDICATOR_MATCHES_NOT_A_SAFETY_CERTIFICATION",
            "results": results,
            "summary": {
                "skills_received": 8,
                "skills_hashed": 8,
                "skills_with_official_analyzable_targets": 0,
                "skills_with_supplemental_indicator_matches": 0,
                "official_scenarios_accounted_for_per_skill": 12,
            },
        },
        "integration": {
            "recommended_agent_identity": "audit-agent",
            "recommended_stage": "DEPLOYMENT_PREFLIGHT",
            "official_skill_assigned_to_worker": False,
            "runtime_consumption": False,
            "live_worker_execution": False,
            "llm_inference": False,
            "agentteams_resources_mutated": False,
            "cloud_service_used": False,
        },
        "limitations": [
            "OFFICIAL_MAIN_SCRIPT_NOT_EXECUTED",
            "OPENCLAW_DEEP_AUDIT_NOT_EXECUTED",
            "OFFICIAL_STATIC_POLICY_EXCLUDES_SKILL_MD",
            "OFFICIAL_COMPATIBLE_TARGET_SET_WAS_EMPTY",
            "SUPPLEMENTAL_PATTERN_SCAN_CANNOT_PROVE_SKILL_SAFETY",
            "NO_CLOUD_INTELLIGENCE_OR_DEEP_ANALYSIS",
            "NO_WORKER_SKILL_CONSUMPTION_RECEIPT",
            "UNSIGNED_POINT_IN_TIME_EVIDENCE",
            "FILESYSTEM_READ_ALLOWLIST_NOT_ENFORCED",
            "CREDENTIAL_AND_CONFIG_READS_NOT_VERIFIED",
            "SANDBOX_EXEC_EXIT_NOT_BOUND_TO_ARTIFACT",
            "NETWORK_ENFORCEMENT_TEST_LIMITED_TO_LOCAL_IPV4_TCP",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--positive-control-only", action="store_true")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--skills-root", type=Path)
    parser.add_argument("--collected-at")
    arguments = parser.parse_args()
    try:
        if arguments.positive_control_only:
            if any((arguments.source_root, arguments.skills_root, arguments.collected_at)):
                raise CollectionError("positive-control mode rejects collection arguments")
            _interpreter_record()
            _run_network_positive_control()
            print(NETWORK_POSITIVE_CONTROL)
            return 0
        if not arguments.source_root or not arguments.skills_root or not arguments.collected_at:
            raise CollectionError("collection arguments are required")
        document = collect(arguments.source_root, arguments.skills_root, arguments.collected_at)
    except (CollectionError, OSError, UnicodeError) as exc:
        print(f"collection failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    json.dump(document, sys.stdout, ensure_ascii=False, indent=2, allow_nan=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
