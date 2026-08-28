"""Fail-closed contract for the current-commit ProofFlow public landing."""

from __future__ import annotations

import argparse
import html as html_module
import json
import re
import sys
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Iterator, Sequence
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Final
from urllib.parse import unquote, urlsplit

import yaml  # type: ignore[import-untyped]

ROOT: Final = Path(__file__).resolve().parents[1]
SCRIPT_ROOT: Final = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from generate_public_demo_snapshot import (  # noqa: E402
    SOURCE_COMMIT as GENERATOR_SOURCE_COMMIT,
)
from generate_public_demo_snapshot import (  # noqa: E402
    SOURCE_TREE as GENERATOR_SOURCE_TREE,
)
from generate_public_demo_snapshot import (  # noqa: E402
    SnapshotGenerationError,
    build_snapshot,
    serialize_snapshot,
)

SITE_ROOT: Final = ROOT / "public-demo"

# These verifier pins are deliberately duplicated outside the generated JSON.
EXPECTED_SOURCE_COMMIT: Final = "610f5d87006567055c658ca8adb66b61284f7603"
EXPECTED_SOURCE_TREE: Final = "883d36075bb9149bddb1122c0b4b401a34d38d05"

EXPECTED_SITE_FILES: Final = frozenset(
    {
        "README.md",
        "app.js",
        "evidence-snapshot.json",
        "favicon.svg",
        "index.html",
        "styles.css",
    }
)

EXPECTED_RESOURCES: Final = frozenset(
    {
        ("link", "href", "./favicon.svg"),
        ("link", "href", "./styles.css"),
        ("script", "src", "./app.js"),
    }
)

EXPECTED_EXTERNAL_ANCHORS: Final = frozenset(
    {
        f"https://github.com/MyGarfield/ProofFlow/commit/{EXPECTED_SOURCE_COMMIT}",
        f"https://github.com/MyGarfield/ProofFlow/blob/{EXPECTED_SOURCE_COMMIT}/README.md",
        (
            "https://github.com/MyGarfield/ProofFlow/blob/"
            f"{EXPECTED_SOURCE_COMMIT}/docs/12_GLOBAL_PRODUCT_ROADMAP.md"
        ),
        (
            "https://github.com/MyGarfield/ProofFlow/blob/"
            f"{EXPECTED_SOURCE_COMMIT}/docs/13_ACTION_CERTIFICATE_V0P1.md"
        ),
        f"https://github.com/MyGarfield/ProofFlow/tree/{EXPECTED_SOURCE_COMMIT}/schemas",
        (
            "https://github.com/MyGarfield/ProofFlow/blob/"
            f"{EXPECTED_SOURCE_COMMIT}/.github/workflows/ci.yml"
        ),
        (
            "https://github.com/MyGarfield/ProofFlow/blob/"
            f"{EXPECTED_SOURCE_COMMIT}/deploy/tool-service/SUPPLY_CHAIN_EVIDENCE.md"
        ),
        *(
            f"https://github.com/MyGarfield/ProofFlow/blob/{EXPECTED_SOURCE_COMMIT}/schemas/{name}"
            for name in (
                "action-certificate-dsse-envelope.schema.json",
                "action-certificate-expected-binding.schema.json",
                "action-certificate-predicate-v0p1.schema.json",
                "action-certificate-revocation-snapshot.schema.json",
                "action-certificate-statement-v0p1.schema.json",
                "action-certificate-trust-policy-v0p1.schema.json",
                "action-certificate-verification-result-v0p1.schema.json",
            )
        ),
        (
            "https://github.com/MyGarfield/ProofFlow/blob/"
            f"{EXPECTED_SOURCE_COMMIT}/submission/public/README.md"
        ),
    }
)

REQUIRED_LOCAL_ANCHORS: Final = frozenset(
    {
        "#current-core",
        "#evidence",
        "#materials",
        "#proof-plane",
        "#top",
        "./README.md",
        "./evidence-snapshot.json",
    }
)

EXPECTED_CSP: Final = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-src 'none'"
)

REQUIRED_VISIBLE_BOUNDARIES: Final = (
    "CURRENT CORE ALPHA SNAPSHOT",
    "PUBLIC_SYNTHETIC",
    "Workers Stopped",
    "readyWorkers=0",
    "LLM OFF",
    "NO EXTERNAL SIDE EFFECTS",
    "非法律意见",
    "ActionCertificate v0.1",
    "53 certificate tests",
    "569 full repo tests",
    "LANDING POST-DATES SOURCE",
    "NOT RELEASE ELIGIBLE",
    "ExecutionReceipt 未实现",
    "OutcomeClosure 未实现",
    "EVALUATION NOT_EXECUTED / UNKNOWN",
    "SUPPLY EVIDENCE STALE",
    "未晋级 GOAI 复赛",
    "GENERATOR EXECUTED TESTS: FALSE",
    "COMMIT SIGNATURE VERIFIED: FALSE",
    "self_authenticating=false",
    EXPECTED_SOURCE_COMMIT,
    EXPECTED_SOURCE_TREE,
    "72febbf664d2889a9f433b88ebc78bb6c42d3007f41aa62f99f643ab5a34f6f2",
    "a050229692db496056f26fd9af52bbb41f0e53f96c8446c93ae3bd87a0d887f5",
)

FORBIDDEN_CLAIMS: Final = (
    re.compile(r"Workers\s+Running", re.IGNORECASE),
    re.compile(r"readyWorkers\s*=\s*[1-9][0-9]*", re.IGNORECASE),
    re.compile(r"\bLLM\s+ON\b", re.IGNORECASE),
    re.compile(r"OFFICIAL\s+SCORE\s*(?:=|:)\s*[0-9]", re.IGNORECASE),
    re.compile(r"\bPRODUCTION[_ -]?READY\b", re.IGNORECASE),
    re.compile(r"\bREAL[_ -]?CASE\b", re.IGNORECASE),
    re.compile(r"LEGAL\s+ACCURACY\s*(?:=|:)?\s*100%", re.IGNORECASE),
    re.compile(r"SUPPLY\s+EVIDENCE\s+(?:FRESH|CURRENT)", re.IGNORECASE),
    re.compile(r"ExecutionReceipt\s+(?:IMPLEMENTED|READY|AVAILABLE)", re.IGNORECASE),
    re.compile(r"OutcomeClosure\s+(?:IMPLEMENTED|READY|AVAILABLE)", re.IGNORECASE),
)

SENSITIVE_TEXT_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "local machine path",
        re.compile(
            r"(?:file://|(?:smb|afp)://|~/|~\\|/Users/|/home/|/root/|/Volumes/|"
            r"/var/folders/|/private/tmp/|/private/var/folders/|/tmp/|/workspace/|"
            r"(?<![0-9A-Za-z])[A-Za-z]:[\\/]|\\\\[0-9A-Za-z.$_-]+\\[0-9A-Za-z.$_-]+)"
        ),
    ),
    (
        "private network address",
        re.compile(
            r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
            r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
        ),
    ),
    (
        "email address",
        re.compile(
            r"(?<![0-9A-Za-z._%+-])[0-9A-Za-z._%+-]+@[0-9A-Za-z.-]+\.[A-Za-z]{2,}"
            r"(?![0-9A-Za-z.-])"
        ),
    ),
    (
        "mainland China mobile number",
        re.compile(r"(?<![0-9A-Za-z])1[3-9]\d{9}(?![0-9A-Za-z])"),
    ),
    (
        "mainland China identity number",
        re.compile(r"(?<![0-9A-Za-z])\d{17}[0-9Xx](?![0-9A-Za-z])"),
    ),
    (
        "private key material",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "service credential token",
        re.compile(
            r"\b(?:gh[pousr]_[0-9A-Za-z]{20,}|sk-[0-9A-Za-z]{20,}|"
            r"(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[0-9A-Za-z-]{10,})\b"
        ),
    ),
    (
        "authorization bearer token",
        re.compile(r"\bBearer\s+[0-9A-Za-z._~+/=-]{16,}", re.IGNORECASE),
    ),
    (
        "assigned credential",
        re.compile(
            r"(?<![0-9A-Za-z])(?:[0-9A-Za-z]+[._-])*"
            r"(?:api[\s._-]*(?:key|secret)|access[\s._-]*token|auth[\s._-]*token|"
            r"client[\s._-]*secret|consumer[\s._-]*secret|id[\s._-]*token|password|"
            r"private[\s._-]*key|refresh[\s._-]*token|"
            r"secret(?:[\s._-]*(?:access[\s._-]*key|key))?|token|"
            r"webhook[\s._-]*secret)\s*[:=]\s*[\"']?[0-9A-Za-z_./+=-]{8,}",
            re.IGNORECASE,
        ),
    ),
)

NETWORK_JS_TOKENS: Final = (
    "document.write",
    "eval(",
    "fetch(",
    "innerHTML",
    "insertAdjacentHTML",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "sendBeacon",
    "serviceWorker",
    "localStorage",
    "sessionStorage",
)

CHECKOUT_ACTION: Final = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
SETUP_UV_ACTION: Final = "astral-sh/setup-uv@d0cc045d04ccac9d8b7881df0226f9e82c39688e"
UPLOAD_PAGES_ACTION: Final = (
    "actions/upload-pages-artifact@7b1f4a764d45c48632c6b24a0339c27f5614fb0b"
)
DEPLOY_PAGES_ACTION: Final = "actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e"
EXPECTED_ACTION_PINS: Final = frozenset(
    {
        CHECKOUT_ACTION,
        SETUP_UV_ACTION,
        UPLOAD_PAGES_ACTION,
        DEPLOY_PAGES_ACTION,
    }
)
SNAPSHOT_CHECK_COMMAND: Final = (
    "uv run --frozen python scripts/generate_public_demo_snapshot.py --check "
    f"--source-commit {EXPECTED_SOURCE_COMMIT}"
)
LANDING_CHECK_COMMAND: Final = (
    "uv run --frozen python scripts/validate_public_demo_landing.py "
    f"--expected-source-commit {EXPECTED_SOURCE_COMMIT}"
)


def _expected_pages_workflow() -> dict[str | bool, Any]:
    """Return the exact YAML-safe-loaded Pages workflow contract."""
    return {
        "name": "Pages",
        # PyYAML intentionally follows YAML 1.1 and loads the plain key `on` as True.
        True: {
            "push": {
                "branches": ["main"],
                "paths": [
                    "public-demo/**",
                    "scripts/generate_public_demo_snapshot.py",
                    "scripts/validate_public_demo_landing.py",
                    ".github/workflows/pages.yml",
                ],
            },
            "workflow_dispatch": None,
        },
        "concurrency": {"group": "pages", "cancel-in-progress": False},
        "permissions": {"contents": "read"},
        "jobs": {
            "build": {
                "if": "github.ref == 'refs/heads/main'",
                "runs-on": "ubuntu-latest",
                "permissions": {"contents": "read"},
                "steps": [
                    {
                        "name": "Check out complete source history without persisted credentials",
                        "uses": CHECKOUT_ACTION,
                        "with": {"fetch-depth": 0, "persist-credentials": False},
                    },
                    {
                        "name": "Install the locked Python toolchain",
                        "uses": SETUP_UV_ACTION,
                        "with": {
                            "version": "0.11.28",
                            "python-version": "3.12",
                            "enable-cache": False,
                        },
                    },
                    {
                        "name": "Verify source-bound public snapshot",
                        "run": SNAPSHOT_CHECK_COMMAND,
                    },
                    {
                        "name": "Validate static claim and privacy boundary",
                        "run": LANDING_CHECK_COMMAND,
                    },
                    {
                        "name": "Upload only the static public-demo artifact",
                        "uses": UPLOAD_PAGES_ACTION,
                        "with": {"path": "./public-demo"},
                    },
                ],
            },
            "deploy": {
                "if": "github.ref == 'refs/heads/main'",
                "needs": "build",
                "runs-on": "ubuntu-latest",
                "permissions": {"pages": "write", "id-token": "write"},
                "environment": {
                    "name": "github-pages",
                    "url": "${{ steps.deployment.outputs.page_url }}",
                },
                "steps": [
                    {
                        "name": "Deploy the reviewed static artifact",
                        "id": "deployment",
                        "uses": DEPLOY_PAGES_ACTION,
                    }
                ],
            },
        },
    }


class _DuplicateYamlKeyError(yaml.YAMLError):  # type: ignore[misc]
    """Internal marker for duplicate mapping keys without echoing their values."""


class _UniqueKeySafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """SafeLoader variant that rejects duplicate keys at every mapping depth."""


def _construct_unique_yaml_mapping(
    loader: Any,
    node: Any,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise _DuplicateYamlKeyError from exc
        if duplicate:
            raise _DuplicateYamlKeyError
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_yaml_mapping,
)


class LandingHTMLParser(HTMLParser):
    """Collect the bounded DOM facts required by the static verifier."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[dict[str, str]] = []
        self.csp_values: list[str] = []
        self.forbidden_elements: list[str] = []
        self.headings: list[str] = []
        self.ids: list[str] = []
        self.inline_event_attributes: list[str] = []
        self.inline_scripts = 0
        self.inline_styles = 0
        self.qa_boxes = 0
        self.resource_urls: list[tuple[str, str, str]] = []
        self.source_commit = ""
        self.text_parts: list[str] = []
        self._current_heading: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if tag == "html":
            self.source_commit = values.get("data-source-commit", "")
        if identifier := values.get("id"):
            self.ids.append(identifier)
        if "data-qa-box" in values:
            self.qa_boxes += 1
        for name in values:
            if name.casefold().startswith("on"):
                self.inline_event_attributes.append(f"{tag}[{name}]")
        if tag in {"base", "embed", "form", "iframe", "object"}:
            self.forbidden_elements.append(tag)
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._current_heading = []
        if tag == "a":
            self.anchors.append(values)
        if tag == "meta" and values.get("http-equiv", "").casefold() == ("content-security-policy"):
            self.csp_values.append(values.get("content", ""))
        if tag == "script":
            if values.get("src"):
                self.resource_urls.append((tag, "src", values["src"]))
            else:
                self.inline_scripts += 1
        elif tag == "link" and {"icon", "stylesheet"}.intersection(
            values.get("rel", "").casefold().split()
        ):
            self.resource_urls.append((tag, "href", values.get("href", "")))
        else:
            for attribute in ("src", "poster"):
                if tag in {"audio", "img", "source", "track", "video"} and values.get(attribute):
                    self.resource_urls.append((tag, attribute, values[attribute]))
            if tag in {"img", "source"} and values.get("srcset"):
                for candidate in values["srcset"].split(","):
                    self.resource_urls.append(
                        (tag, "srcset", candidate.strip().split(maxsplit=1)[0])
                    )
        if tag == "style":
            self.inline_styles += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"} and self._current_heading is not None:
            self.headings.append(_normalized_text(" ".join(self._current_heading)))
            self._current_heading = None

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.text_parts.append(data)
            if self._current_heading is not None:
                self._current_heading.append(data)


def _normalized_text(value: str) -> str:
    return " ".join(value.split())


def _load_strict_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON value: {value}")
        ),
    )


def _iter_json_string_values(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _iter_json_string_values(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_json_string_values(item, f"{path}[{index}]")


def _text_scan_variants(value: str) -> tuple[str, ...]:
    decoded = unicodedata.normalize("NFKC", html_module.unescape(value))
    decoded = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "", decoded)
    variants = {decoded}
    for tag_replacement in ("", " "):
        without_tags = re.sub(r"<!--.*?-->|<[^>]*>", tag_replacement, decoded, flags=re.DOTALL)
        without_links = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", without_tags)
        variants.add(without_links)
        variants.add(re.sub(r"[\\*_`~\[\]{}]", "", without_links))
        variants.add(re.sub(r"[^0-9A-Za-z_@%+=:./\\-]+", " ", without_links))
    return tuple(_normalized_text(item) for item in variants)


def _scan_text(*, label: str, value: str) -> list[str]:
    errors: list[str] = []
    variants = _text_scan_variants(value)
    for pattern in FORBIDDEN_CLAIMS:
        if any(pattern.search(variant) for variant in variants):
            errors.append(f"forbidden claim token in {label}: {pattern.pattern}")
    for category, pattern in SENSITIVE_TEXT_PATTERNS:
        if any(pattern.search(variant) for variant in variants):
            errors.append(f"sensitive {category} in {label}")
    return errors


def _scan_json(*, label: str, value: Any) -> list[str]:
    errors: list[str] = []
    for path, string_value in _iter_json_string_values(value):
        errors.extend(_scan_text(label=f"{label}{path}", value=string_value))
    return errors


def _compare_closed_shape(expected: Any, actual: Any, path: str, errors: list[str]) -> None:
    if type(actual) is not type(expected):
        errors.append(f"{path} type mismatch")
        return
    if isinstance(expected, dict):
        expected_keys = set(expected)
        actual_keys = set(actual)
        missing = sorted(expected_keys - actual_keys)
        unexpected = sorted(actual_keys - expected_keys)
        if missing or unexpected:
            details: list[str] = []
            if missing:
                details.append("missing=" + ",".join(missing))
            if unexpected:
                details.append("unexpected=" + ",".join(unexpected))
            errors.append(f"{path} exact-key shape mismatch ({'; '.join(details)})")
        for key in sorted(expected_keys & actual_keys):
            _compare_closed_shape(expected[key], actual[key], f"{path}.{key}", errors)
        return
    if isinstance(expected, list):
        if len(actual) != len(expected):
            errors.append(f"{path} array length mismatch")
        for index, (expected_item, actual_item) in enumerate(zip(expected, actual, strict=False)):
            _compare_closed_shape(expected_item, actual_item, f"{path}[{index}]", errors)
        return
    if actual != expected:
        errors.append(f"{path} value does not match the reviewed source-derived snapshot")


def _validate_local_url(
    *,
    url: str,
    site_root: Path,
    ids: set[str],
    label: str,
) -> list[str]:
    parsed = urlsplit(url)
    if parsed.scheme or parsed.netloc:
        return [f"{label} must be path-relative: {url}"]
    if parsed.path.startswith("/"):
        return [f"{label} must not assume a domain root: {url}"]
    errors: list[str] = []
    decoded = unquote(parsed.path)
    if ".." in Path(decoded).parts:
        return [f"{label} must not escape public-demo: {url}"]
    if parsed.path:
        target = (site_root / decoded).resolve()
        try:
            target.relative_to(site_root.resolve())
        except ValueError:
            errors.append(f"{label} escapes public-demo: {url}")
        else:
            if not target.is_file():
                errors.append(f"{label} target is missing: {url}")
    if parsed.fragment and not parsed.path and parsed.fragment not in ids:
        errors.append(f"{label} fragment is missing from DOM: #{parsed.fragment}")
    return errors


def _validate_favicon(path: Path) -> list[str]:
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except (OSError, ET.ParseError) as exc:
        return [f"invalid local favicon SVG: {exc}"]
    errors: list[str] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", maxsplit=1)[-1]
        if tag not in {"path", "rect", "svg"}:
            errors.append(f"favicon contains forbidden SVG element: {tag}")
        for attribute in element.attrib:
            name = attribute.rsplit("}", maxsplit=1)[-1]
            if name in {"href", "src"} or name.casefold().startswith("on"):
                errors.append(f"favicon contains active/external attribute: {name}")
    return errors


def _validate_snapshot(
    repository_root: Path,
    site_root: Path,
    *,
    expected_source_commit: str,
) -> list[str]:
    errors: list[str] = []
    snapshot_path = site_root / "evidence-snapshot.json"
    try:
        actual = _load_strict_json(snapshot_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [f"invalid evidence-snapshot.json: {exc}"]
    errors.extend(_scan_json(label="evidence-snapshot.json", value=actual))

    if expected_source_commit != EXPECTED_SOURCE_COMMIT:
        errors.append("caller expected source commit is outside the reviewed landing contract")
        return errors
    if GENERATOR_SOURCE_COMMIT != EXPECTED_SOURCE_COMMIT:
        errors.append("generator and verifier source commit pins disagree")
        return errors
    if GENERATOR_SOURCE_TREE != EXPECTED_SOURCE_TREE:
        errors.append("generator and verifier source tree pins disagree")
        return errors
    try:
        expected = build_snapshot(repository_root, source_commit=expected_source_commit)
    except SnapshotGenerationError as exc:
        errors.append(f"cannot derive expected snapshot from pinned Git objects: {exc}")
        return errors

    _compare_closed_shape(expected, actual, "evidence-snapshot.json$", errors)
    try:
        current_bytes = snapshot_path.read_bytes()
    except OSError as exc:
        errors.append(f"cannot read evidence snapshot bytes: {exc}")
    else:
        if current_bytes != serialize_snapshot(expected):
            errors.append("evidence snapshot is not the deterministic generated serialization")
    return errors


def _validate_pages_workflow(repository_root: Path) -> list[str]:
    path = repository_root / ".github" / "workflows" / "pages.yml"
    try:
        value = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"Pages workflow is missing or unreadable: {exc}"]
    errors = _scan_text(label="pages.yml", value=value)
    if "secrets." in value:
        errors.append("Pages workflow contains forbidden deployment capability: secrets.")
    try:
        workflow = yaml.safe_load(value)
        yaml.load(value, Loader=_UniqueKeySafeLoader)
    except _DuplicateYamlKeyError:
        errors.append("Pages workflow contains duplicate YAML mapping keys")
        return sorted(set(errors))
    except yaml.YAMLError as exc:
        errors.append(f"Pages workflow is not valid safe YAML: {exc.__class__.__name__}")
        return sorted(set(errors))
    if not isinstance(workflow, dict):
        errors.append("Pages workflow must be a YAML object")
        return sorted(set(errors))

    expected = _expected_pages_workflow()
    permissions = workflow.get("permissions")
    if permissions != {"contents": "read"}:
        errors.append("Pages workflow top-level permissions must be exactly contents: read")
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != {"build", "deploy"}:
        errors.append("Pages workflow jobs must be the exact build/deploy closed set")
        jobs = {}
    build = jobs.get("build")
    if not isinstance(build, dict) or build.get("permissions") != {"contents": "read"}:
        errors.append("Pages build permissions must be exactly contents: read")
    deploy = jobs.get("deploy")
    if not isinstance(deploy, dict) or deploy.get("permissions") != {
        "pages": "write",
        "id-token": "write",
    }:
        errors.append("Pages deploy permissions must be exactly pages: write and id-token: write")

    build_steps = build.get("steps", []) if isinstance(build, dict) else []
    deploy_steps = deploy.get("steps", []) if isinstance(deploy, dict) else []
    if not isinstance(build_steps, list) or not isinstance(deploy_steps, list):
        errors.append("Pages workflow steps must be ordered arrays")
        all_steps: list[Any] = []
    else:
        all_steps = [*build_steps, *deploy_steps]
    actions = [step.get("uses") for step in all_steps if isinstance(step, dict) and "uses" in step]
    commands = [step.get("run") for step in all_steps if isinstance(step, dict) and "run" in step]
    if actions != [
        CHECKOUT_ACTION,
        SETUP_UV_ACTION,
        UPLOAD_PAGES_ACTION,
        DEPLOY_PAGES_ACTION,
    ]:
        errors.append("Pages workflow actions must be the exact ordered full-SHA closed set")
    for action in actions:
        if not isinstance(action, str):
            errors.append("Pages workflow action reference must be a string")
            continue
        if not re.fullmatch(r"[a-z0-9-]+/[a-z0-9-]+@[0-9a-f]{40}", action):
            errors.append("Pages workflow action is not pinned to a reviewed full commit")
    if commands != [SNAPSHOT_CHECK_COMMAND, LANDING_CHECK_COMMAND]:
        errors.append("Pages workflow run commands must be the exact ordered validator closed set")
    if workflow != expected:
        errors.append(
            "Pages workflow structure must exactly match the reviewed permissions, jobs, "
            "concurrency, environment, needs, and step contract"
        )
    return sorted(set(errors))


def validate_public_demo(
    repository_root: Path = ROOT,
    site_root: Path | None = None,
    *,
    expected_source_commit: str = EXPECTED_SOURCE_COMMIT,
) -> list[str]:
    """Return all static contract errors; an empty list is the only passing result."""
    selected_site_root = site_root or repository_root / "public-demo"
    errors: list[str] = []

    actual_files: set[str] = set()
    if selected_site_root.is_dir():
        for path in selected_site_root.rglob("*"):
            if path.is_symlink():
                errors.append(
                    "public-demo artifact must not contain symlinks: "
                    + path.relative_to(selected_site_root).as_posix()
                )
            elif path.is_file():
                actual_files.add(path.relative_to(selected_site_root).as_posix())
    missing = sorted(EXPECTED_SITE_FILES - actual_files)
    unexpected = sorted(actual_files - EXPECTED_SITE_FILES)
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if unexpected:
            details.append("unexpected=" + ",".join(unexpected))
        errors.append(
            "public-demo static artifact closed set mismatch (" + "; ".join(details) + ")"
        )
    if errors:
        return sorted(set(errors))

    html = (selected_site_root / "index.html").read_text(encoding="utf-8")
    css = (selected_site_root / "styles.css").read_text(encoding="utf-8")
    javascript = (selected_site_root / "app.js").read_text(encoding="utf-8")
    parser = LandingHTMLParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:
        return [f"cannot parse index.html: {exc}"]

    if parser.source_commit != expected_source_commit:
        errors.append("HTML source commit pin does not match the external expected source")
    if parser.forbidden_elements:
        errors.append("forbidden active/embed elements: " + ", ".join(parser.forbidden_elements))
    if parser.inline_event_attributes:
        errors.append(
            "inline event handlers are forbidden: " + ", ".join(parser.inline_event_attributes)
        )
    if parser.inline_scripts:
        errors.append("inline executable scripts are forbidden")
    if parser.inline_styles:
        errors.append("inline style blocks are forbidden")
    duplicates = sorted({item for item in parser.ids if parser.ids.count(item) > 1})
    if duplicates:
        errors.append("duplicate DOM ids: " + ", ".join(duplicates))
    if parser.headings.count("PROOF BEFORE ACTION") != 1:
        errors.append("page must expose exactly one PROOF BEFORE ACTION h1")
    if parser.qa_boxes < 17:
        errors.append("page must expose at least 17 bounded QA boxes for collision inspection")

    visible_text = _normalized_text(" ".join(parser.text_parts))
    for phrase in REQUIRED_VISIBLE_BOUNDARIES:
        if phrase not in visible_text:
            errors.append(f"required visible claim boundary is missing: {phrase}")
    errors.extend(_scan_text(label="visible HTML", value=visible_text))

    loaded_text_assets = {
        "README.md": (selected_site_root / "README.md").read_text(encoding="utf-8"),
        "app.js": javascript,
        "favicon.svg": (selected_site_root / "favicon.svg").read_text(encoding="utf-8"),
        "index.html": html,
        "styles.css": css,
    }
    for label, content in loaded_text_assets.items():
        errors.extend(_scan_text(label=f"public artifact {label}", value=content))

    if parser.csp_values != [EXPECTED_CSP]:
        errors.append("CSP must be the exact reviewed deny-by-default static policy")
    resources = frozenset(parser.resource_urls)
    if resources != EXPECTED_RESOURCES:
        errors.append("loaded resources must be the exact three path-relative static files")
    ids = set(parser.ids)
    for tag, attribute, url in parser.resource_urls:
        errors.extend(
            _validate_local_url(
                url=url,
                site_root=selected_site_root,
                ids=ids,
                label=f"loaded resource {tag}[{attribute}]",
            )
        )

    external_anchors: set[str] = set()
    local_anchors: set[str] = set()
    for anchor in parser.anchors:
        url = anchor.get("href", "")
        parsed = urlsplit(url)
        if parsed.scheme in {"http", "https"}:
            external_anchors.add(url)
            if parsed.scheme != "https" or parsed.hostname != "github.com":
                errors.append(f"external navigation host is not allowed: {url}")
            if expected_source_commit not in url:
                errors.append(f"external source link is not fixed to the expected commit: {url}")
            rel = set(anchor.get("rel", "").casefold().split())
            if anchor.get("target") != "_blank" or not {"noopener", "noreferrer"} <= rel:
                errors.append(f"external navigation must isolate referrer/opener: {url}")
        elif parsed.scheme or parsed.netloc:
            errors.append(f"unsupported anchor scheme: {url}")
        else:
            local_anchors.add(url)
            errors.extend(
                _validate_local_url(
                    url=url,
                    site_root=selected_site_root,
                    ids=ids,
                    label="local anchor",
                )
            )
    if external_anchors != EXPECTED_EXTERNAL_ANCHORS:
        errors.append("external materials must be the exact current-source GitHub closed set")
    if not local_anchors >= REQUIRED_LOCAL_ANCHORS:
        errors.append(
            "required relative/fragment links are missing: "
            + ", ".join(sorted(REQUIRED_LOCAL_ANCHORS - local_anchors))
        )

    tokens = {
        "--accent": "#FF0000",
        "--bg": "#FFFFFF",
        "--blue": "#0000FF",
        "--fg": "#000000",
        "--gold": "#FFD700",
        "--hair": "#000000",
        "--mono": 'ui-monospace,"SF Mono",Menlo,Consolas,monospace',
        "--sans": (
            '-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,'
            '"PingFang SC","Microsoft YaHei",sans-serif'
        ),
    }
    for token, expected in tokens.items():
        if not re.search(rf"{re.escape(token)}\s*:\s*{re.escape(expected)}\s*;", css):
            errors.append(f"Swiss Style token drifted: {token}")
    for forbidden in ("border-radius", "@font-face", "@import", "url("):
        if forbidden.casefold() in css.casefold():
            errors.append(f"CSS contains forbidden remote/rounded-style token: {forbidden}")
    if "grid-template-columns: repeat(12, minmax(0, 1fr));" not in css:
        errors.append("Swiss 12-column grid must use minmax(0, 1fr)")
    if "--target: 44px;" not in css:
        errors.append("interactive target token must remain 44px")
    if "@media (prefers-reduced-motion: reduce)" not in css:
        errors.append("global reduced-motion contract is missing")
    for token in NETWORK_JS_TOKENS:
        if token in javascript:
            errors.append(f"static landing script must not use network/storage API: {token}")

    errors.extend(
        _validate_snapshot(
            repository_root,
            selected_site_root,
            expected_source_commit=expected_source_commit,
        )
    )
    errors.extend(_validate_favicon(selected_site_root / "favicon.svg"))
    errors.extend(_validate_pages_workflow(repository_root))
    return sorted(set(errors))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the source-bound ProofFlow public landing page."
    )
    parser.add_argument("--site-root", type=Path, default=SITE_ROOT)
    parser.add_argument(
        "--expected-source-commit",
        default=EXPECTED_SOURCE_COMMIT,
        help="independent product commit expectation",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    errors = validate_public_demo(
        ROOT,
        args.site_root.resolve(),
        expected_source_commit=args.expected_source_commit,
    )
    if errors:
        print("PUBLIC_DEMO_INVALID")
        for error in errors:
            print(f"- {error}")
        return 1
    print("PUBLIC_DEMO_VALID")
    print("scope=CURRENT_CORE_ALPHA_SOURCE_OBJECT")
    print(f"source_commit={EXPECTED_SOURCE_COMMIT}")
    print(f"source_tree={EXPECTED_SOURCE_TREE}")
    print("landing_in_source_commit=false")
    print("self_authenticating=false")
    print("runtime=Workers_Stopped/readyWorkers_0/LLM_OFF")
    print("evaluation=NOT_EXECUTED/UNKNOWN")
    print("supply=STALE/NOT_RELEASE_ELIGIBLE")
    print("external_loaded_resources=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
