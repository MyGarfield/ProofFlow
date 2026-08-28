"""Fail-closed static contract for the ProofFlow public evidence landing page."""

from __future__ import annotations

import argparse
import hashlib
import html as html_module
import json
import re
import subprocess
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Iterator, Sequence
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Final
from urllib.parse import unquote, urlsplit

ROOT: Final = Path(__file__).resolve().parents[1]
SITE_ROOT: Final = ROOT / "public-demo"
SOURCE_COMMIT: Final = "b63eeb60d1072c73d2d0d1d6061b3c8f800487a4"
SOURCE_TREE: Final = "2e58bc7cf5a2677ec156490108ad91f35d5c41c1"
FLOW: Final = ("prepare", "409", "approve", "package", "verify", "11/11")
ALLOWED_EXTERNAL_ANCHOR_HOSTS: Final = frozenset({"github.com"})
EXPECTED_EXTERNAL_ANCHORS: Final = frozenset(
    {
        "https://github.com/MyGarfield/ProofFlow",
        f"https://github.com/MyGarfield/ProofFlow/commit/{SOURCE_COMMIT}",
        (
            f"https://github.com/MyGarfield/ProofFlow/blob/{SOURCE_COMMIT}/submission/"
            "public/ProofFlow_GOAI_%E5%A4%8D%E8%B5%9B%E7%AD%94%E8%BE%A9_v2.0.pdf"
        ),
        (
            f"https://github.com/MyGarfield/ProofFlow/blob/{SOURCE_COMMIT}/submission/"
            "public/ProofFlow_GOAI_%E5%A4%8D%E8%B5%9B%E7%AD%94%E8%BE%A9_v2.0.pptx"
        ),
        (
            f"https://github.com/MyGarfield/ProofFlow/blob/{SOURCE_COMMIT}/"
            "docs/09_SEMIFINAL_DEMO_RUNBOOK.md"
        ),
        (
            f"https://github.com/MyGarfield/ProofFlow/blob/{SOURCE_COMMIT}/submission/"
            "public/submission-manifest.json"
        ),
    }
)
REQUIRED_LOCAL_ANCHORS: Final = frozenset(
    {
        "#evidence",
        "#materials",
        "#proof-path",
        "#reference-media",
        "#top",
        "./README.md",
        "./evidence-snapshot.json",
        "./media/proofflow-reference-demo.zh-CN.vtt",
        "./media/video-contract.json",
    }
)
EXPECTED_ARTIFACTS: Final = {
    "submission/public/ProofFlow_GOAI_复赛答辩_v2.0.pptx": (
        "fabe3102c1ef6550b131d0d230fed3a4eef46c579886ec268fc6c11c298f55a5",
        901601,
    ),
    "submission/public/ProofFlow_GOAI_复赛答辩_v2.0.pdf": (
        "6c45562bd6b7fa1a813bac0d713dfa3a3a2d7f54f6e07a3763bbb1306d12e773",
        1523247,
    ),
    "submission/public/submission-manifest.json": (
        "6b36d4b98fd6bb5261460f8a3d394f06419ce31821ebc085efed4b79175365d6",
        1621,
    ),
}
REQUIRED_CSP_DIRECTIVES: Final = (
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "connect-src 'none'",
    "font-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-src 'none'",
)
FORBIDDEN_VISIBLE_CLAIMS: Final = (
    re.compile(r"Workers\s+Running", re.IGNORECASE),
    re.compile(r"readyWorkers\s*=\s*[1-9][0-9]*", re.IGNORECASE),
    re.compile(r"\bLLM\s+ON\b", re.IGNORECASE),
    re.compile(r"\bPRODUCTION[_ ]READY\b", re.IGNORECASE),
    re.compile(r"\bREAL[_ ]CASE\b", re.IGNORECASE),
    re.compile(r"LEGAL\s+ACCURACY\s*(?:=|:)?\s*100%", re.IGNORECASE),
    re.compile(r"OFFICIAL\s+SCORE\s*(?:=|:)\s*[0-9]", re.IGNORECASE),
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
            r"(?:api[\s._-]*(?:key|secret)|access[\s._-]*token|"
            r"auth[\s._-]*token|client[\s._-]*secret|consumer[\s._-]*secret|"
            r"id[\s._-]*token|password|private[\s._-]*key|"
            r"refresh[\s._-]*token|secret(?:[\s._-]*(?:access[\s._-]*key|key))?|"
            r"token|webhook[\s._-]*secret)\s*[:=]\s*"
            r"[\"']?[0-9A-Za-z_./+=-]{8,}",
            re.IGNORECASE,
        ),
    ),
)
EVIDENCE_OBJECT_KEYS: Final = {
    "$": frozenset(
        {
            "schema_version",
            "snapshot_scope",
            "observed_on",
            "classification",
            "repository",
            "source",
            "landing",
            "runtime_boundary",
            "reference_flow",
            "input_pins",
            "contract_suite",
            "public_artifacts",
            "evaluation_boundary",
            "media",
            "digest_disclaimer",
        }
    ),
    "source": frozenset(
        {
            "branch",
            "commit",
            "tree",
            "signature_verified",
            "landing_page_in_source_commit",
        }
    ),
    "landing": frozenset(
        {
            "mode",
            "runtime_connected",
            "tracking_enabled",
            "remote_runtime_exposed",
            "base_path_contract",
        }
    ),
    "runtime_boundary": frozenset(
        {
            "workers",
            "readyWorkers",
            "worker_containers",
            "llm_enabled",
            "external_side_effects_enabled",
            "real_case_data_used",
            "legal_advice",
        }
    ),
    "reference_flow[]": frozenset({"step", "observed_outcome"}),
    "input_pins": frozenset({"fixture_bundle", "rule_catalog", "hash_kind"}),
    "contract_suite": frozenset(
        {
            "result",
            "report_hash",
            "scope",
            "legal_accuracy_measured",
            "performance_measured",
            "official_score",
        }
    ),
    "public_artifacts[]": frozenset({"path", "sha256", "bytes"}),
    "evaluation_boundary": frozenset(
        {
            "status",
            "deterministic_reference_score",
            "single_agent_score",
            "six_agent_score",
            "official_score",
        }
    ),
    "media": frozenset({"publication_status", "contract"}),
}
VIDEO_OBJECT_KEYS: Final = {
    "$": frozenset(
        {
            "schema_version",
            "publication_status",
            "playback_mode",
            "source_evidence_commit",
            "video",
            "subtitles",
            "publication_gate",
            "claim_boundaries",
        }
    ),
    "video": frozenset(
        {"path", "present", "sha256", "duration_seconds", "width", "height", "codec"}
    ),
    "subtitles": frozenset({"path", "present", "language", "cue_count", "sha256"}),
    "claim_boundaries": frozenset(
        {
            "classification",
            "workers",
            "readyWorkers",
            "llm_enabled",
            "external_side_effects_enabled",
            "legal_accuracy_measured",
            "live_runtime_demonstrated",
        }
    ),
}
EXPECTED_REFERENCE_FLOW: Final = (
    {"step": "prepare", "observed_outcome": "AWAITING_APPROVAL"},
    {"step": "409", "observed_outcome": "HUMAN_GATE_REQUIRED"},
    {"step": "approve", "observed_outcome": "LOCAL_DEMO"},
    {"step": "package", "observed_outcome": "2_FILES"},
    {
        "step": "verify",
        "observed_outcome": "VALID_TRUE_25_ARTIFACTS_2_PACKAGE_FILES",
    },
    {"step": "11/11", "observed_outcome": "STRUCTURAL_CONTRACTS_ONLY"},
)
EXPECTED_PUBLICATION_GATE: Final = (
    "Replace STORYBOARD_FALLBACK only after the MP4 exists at the declared relative path.",
    "Record the exact MP4 SHA-256 and trusted ffprobe observations.",
    (
        "Verify rendered claims against the source evidence commit and reject prohibited "
        "live-runtime claims."
    ),
    "Extract representative frames from the MP4 and compare them with approved snapshots.",
    (
        "Run a current privacy and secret scan over the MP4, subtitles, script, snapshots, "
        "and manifest."
    ),
    "Keep subtitles enabled and preserve PUBLIC_SYNTHETIC claim boundaries in every scene.",
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


class LandingHTMLParser(HTMLParser):
    """Collect the bounded DOM facts needed by the static verifier."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[dict[str, str]] = []
        self.csp_values: list[str] = []
        self.flow: list[str] = []
        self.forbidden_elements: list[str] = []
        self.headings: list[str] = []
        self.ids: list[str] = []
        self.inline_event_attributes: list[str] = []
        self.inline_scripts = 0
        self.inline_styles = 0
        self.range_inputs: list[dict[str, str]] = []
        self.resource_urls: list[tuple[str, str, str]] = []
        self.segments: list[dict[str, Any]] = []
        self.text_parts: list[str] = []
        self._current_heading: list[str] | None = None
        self._current_segment: dict[str, Any] | None = None
        self._inside_segment_span = 0
        self._inside_inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if identifier := values.get("id"):
            self.ids.append(identifier)
        for name in values:
            if name.lower().startswith("on"):
                self.inline_event_attributes.append(f"{tag}[{name}]")

        if tag in {"base", "embed", "form", "iframe", "object"}:
            self.forbidden_elements.append(tag)
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._current_heading = []
        if flow_step := values.get("data-flow-step"):
            self.flow.append(flow_step)
        if tag == "a":
            self.anchors.append(values)
        if tag == "meta" and values.get("http-equiv", "").casefold() == ("content-security-policy"):
            self.csp_values.append(values.get("content", ""))
        if tag == "input" and values.get("type", "").casefold() == "range":
            self.range_inputs.append(values)

        if tag == "script":
            if values.get("src"):
                self.resource_urls.append((tag, "src", values["src"]))
            else:
                self._inside_inline_script = True
                self.inline_scripts += 1
        elif tag == "link" and {
            "icon",
            "stylesheet",
        }.intersection(values.get("rel", "").casefold().split()):
            self.resource_urls.append((tag, "href", values.get("href", "")))
        else:
            for attribute in ("src", "poster"):
                if tag in {"audio", "img", "source", "track", "video"} and values.get(attribute):
                    self.resource_urls.append((tag, attribute, values[attribute]))
            for attribute in ("srcset",):
                if tag in {"img", "source"} and values.get(attribute):
                    for candidate in values[attribute].split(","):
                        self.resource_urls.append(
                            (tag, attribute, candidate.strip().split(maxsplit=1)[0])
                        )

        if tag == "style":
            self.inline_styles += 1
        if tag == "li" and "data-start" in values and "data-end" in values:
            self._current_segment = {
                "caption_parts": [],
                "end": values["data-end"],
                "heading": values.get("data-heading", ""),
                "start": values["data-start"],
                "step": values.get("data-step", ""),
            }
        elif tag == "span" and self._current_segment is not None:
            self._inside_segment_span += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"} and self._current_heading is not None:
            self.headings.append(_normalized_text(" ".join(self._current_heading)))
            self._current_heading = None
        if tag == "script" and self._inside_inline_script:
            self._inside_inline_script = False
        if tag == "span" and self._inside_segment_span:
            self._inside_segment_span -= 1
        if tag == "li" and self._current_segment is not None:
            self._current_segment["caption"] = _normalized_text(
                " ".join(self._current_segment.pop("caption_parts"))
            )
            self.segments.append(self._current_segment)
            self._current_segment = None
            self._inside_segment_span = 0

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.text_parts.append(data)
            if self._current_heading is not None:
                self._current_heading.append(data)
            if self._current_segment is not None and self._inside_segment_span:
                self._current_segment["caption_parts"].append(data)


def _normalized_text(value: str) -> str:
    return " ".join(value.split())


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + _sha256(payload)


def _load_strict_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON value: {value}")
        ),
    )


def _require_exact_object(
    value: Any,
    *,
    path: str,
    expected_keys: frozenset[str],
    errors: list[str],
) -> dict[str, Any] | None:
    """Require an object with no missing or unreviewed keys at this exact path."""
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object with an exact-key closed shape")
        return None
    actual_keys = set(value)
    missing = sorted(expected_keys - actual_keys)
    unexpected = sorted(actual_keys - expected_keys)
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if unexpected:
            details.append("unexpected=" + ",".join(unexpected))
        errors.append(f"{path} exact-key shape mismatch ({'; '.join(details)})")
    return value


def _require_exact_object_array(
    value: Any,
    *,
    path: str,
    expected_item_keys: frozenset[str],
    errors: list[str],
) -> list[dict[str, Any]]:
    """Require an array whose every item is an exact-key object."""
    if not isinstance(value, list):
        errors.append(f"{path} must be an array of exact-key objects")
        return []
    items: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        validated = _require_exact_object(
            item,
            path=f"{path}[{index}]",
            expected_keys=expected_item_keys,
            errors=errors,
        )
        if validated is not None:
            items.append(validated)
    return items


def _iter_json_string_values(
    value: Any,
    path: str = "$",
) -> Iterator[tuple[str, str]]:
    """Yield JSON string values recursively without treating object keys as content."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, nested in value.items():
            yield from _iter_json_string_values(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _iter_json_string_values(nested, f"{path}[{index}]")


def _text_scan_variants(value: str) -> tuple[str, ...]:
    """Approximate public rendering so markup cannot split a prohibited claim."""
    decoded = unicodedata.normalize("NFKC", html_module.unescape(value))
    decoded = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "", decoded)
    variants = {decoded}
    for tag_replacement in ("", " "):
        without_tags = re.sub(
            r"<!--.*?-->|<[^>]*>",
            tag_replacement,
            decoded,
            flags=re.DOTALL,
        )
        without_links = re.sub(
            r"!?\[([^\]]*)\]\([^)]*\)",
            r"\1",
            without_tags,
        )
        variants.add(without_links)
        variants.add(re.sub(r"[\\*_`~\[\]{}]", "", without_links))
        variants.add(re.sub(r"[^0-9A-Za-z_@%+=:./\\-]+", " ", without_links))
    return tuple(_normalized_text(variant) for variant in variants)


def _scan_text(*, label: str, value: str) -> list[str]:
    """Reject overclaims and anonymous-publication leaks without echoing matched values."""
    errors: list[str] = []
    variants = _text_scan_variants(value)
    for pattern in FORBIDDEN_VISIBLE_CLAIMS:
        if any(pattern.search(variant) for variant in variants):
            errors.append(f"forbidden claim token in {label}: {pattern.pattern}")
    for category, pattern in SENSITIVE_TEXT_PATTERNS:
        if any(pattern.search(variant) for variant in variants):
            errors.append(f"sensitive {category} in {label}")
    return errors


def _scan_json_string_values(*, label: str, value: Any) -> list[str]:
    errors: list[str] = []
    for path, string_value in _iter_json_string_values(value):
        errors.extend(_scan_text(label=f"{label}{path}", value=string_value))
    return errors


def _git_bytes(repository_root: Path, *arguments: str) -> bytes | None:
    try:
        result = subprocess.run(
            ["git", "-c", "core.quotepath=false", *arguments],
            cwd=repository_root,
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def _git_text(repository_root: Path, *arguments: str) -> str | None:
    value = _git_bytes(repository_root, *arguments)
    if value is None:
        return None
    try:
        return value.decode("ascii").strip()
    except UnicodeDecodeError:
        return None


def _validate_local_url(
    *,
    url: str,
    site_root: Path,
    ids: set[str],
    label: str,
) -> list[str]:
    errors: list[str] = []
    parsed = urlsplit(url)
    if parsed.scheme or parsed.netloc:
        return [f"{label} must be path-relative: {url}"]
    if parsed.path.startswith("/"):
        return [f"{label} must not assume a domain root: {url}"]
    decoded = unquote(parsed.path)
    parts = Path(decoded).parts
    if ".." in parts:
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


def _parse_vtt(path: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    try:
        value = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [f"cannot read subtitles: {exc}"]
    if not value.startswith("WEBVTT\n"):
        errors.append("subtitle file must start with WEBVTT")
    cue_pattern = re.compile(
        r"(?m)^\d{2}:\d{2}:\d{2}\.\d{3} --> \d{2}:\d{2}:\d{2}\.\d{3}\n([^\n]+)$"
    )
    captions = [_normalized_text(match) for match in cue_pattern.findall(value)]
    if len(captions) != 6:
        errors.append(f"subtitle file must contain 6 bounded cues, found {len(captions)}")
    return captions, errors


def _validate_favicon(path: Path) -> list[str]:
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except (OSError, ET.ParseError) as exc:
        return [f"invalid local favicon SVG: {exc}"]
    allowed_tags = {"path", "rect", "svg"}
    forbidden_attributes = {"href", "src", "xlink:href"}
    errors: list[str] = []
    for element in root.iter():
        local_tag = element.tag.rsplit("}", maxsplit=1)[-1]
        if local_tag not in allowed_tags:
            errors.append(f"favicon contains forbidden SVG element: {local_tag}")
        for attribute in element.attrib:
            local_attribute = attribute.rsplit("}", maxsplit=1)[-1]
            if local_attribute in forbidden_attributes or local_attribute.startswith("on"):
                errors.append(f"favicon contains active/external attribute: {local_attribute}")
    return errors


def _validate_evidence(repository_root: Path, site_root: Path) -> list[str]:
    errors: list[str] = []
    evidence_path = site_root / "evidence-snapshot.json"
    try:
        evidence = _load_strict_json(evidence_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [f"invalid evidence-snapshot.json: {exc}"]

    errors.extend(_scan_json_string_values(label="evidence-snapshot.json", value=evidence))
    evidence_object = _require_exact_object(
        evidence,
        path="evidence-snapshot.json$",
        expected_keys=EVIDENCE_OBJECT_KEYS["$"],
        errors=errors,
    )
    if evidence_object is None:
        return errors
    evidence = evidence_object

    top_level_facts = {
        key: evidence.get(key)
        for key in (
            "schema_version",
            "snapshot_scope",
            "observed_on",
            "classification",
            "repository",
            "digest_disclaimer",
        )
    }
    if top_level_facts != {
        "schema_version": "1.0",
        "snapshot_scope": "HISTORICAL_REFERENCE_CORE_AND_PUBLIC_MATERIALS",
        "observed_on": "2026-08-22",
        "classification": "PUBLIC_SYNTHETIC",
        "repository": "https://github.com/MyGarfield/ProofFlow",
        "digest_disclaimer": (
            "SHA-256 values are unsigned content digests, not digital signatures, source "
            "authenticity, legal correctness, official acceptance, or competition scores."
        ),
    }:
        errors.append("evidence top-level point-in-time facts drifted from the reviewed snapshot")

    source = (
        _require_exact_object(
            evidence.get("source"),
            path="evidence-snapshot.json$.source",
            expected_keys=EVIDENCE_OBJECT_KEYS["source"],
            errors=errors,
        )
        or {}
    )
    if source.get("branch") != "main":
        errors.append("evidence source branch must remain main")
    if source.get("commit") != SOURCE_COMMIT:
        errors.append("evidence source commit is not the reviewed baseline")
    if source.get("tree") != SOURCE_TREE:
        errors.append("evidence source tree is not the reviewed baseline")
    if source.get("signature_verified") is not False:
        errors.append("unsigned baseline must not be described as signature verified")
    if source.get("landing_page_in_source_commit") is not False:
        errors.append("evidence must disclose that the landing page post-dates the baseline")
    actual_tree = _git_text(repository_root, "rev-parse", f"{SOURCE_COMMIT}^{{tree}}")
    if actual_tree != SOURCE_TREE:
        errors.append("local Git object does not resolve to the declared baseline tree")

    landing = (
        _require_exact_object(
            evidence.get("landing"),
            path="evidence-snapshot.json$.landing",
            expected_keys=EVIDENCE_OBJECT_KEYS["landing"],
            errors=errors,
        )
        or {}
    )
    expected_landing = {
        "base_path_contract": "/ProofFlow/",
        "mode": "STATIC_READ_ONLY_OUTER_LAYER",
        "remote_runtime_exposed": False,
        "runtime_connected": False,
        "tracking_enabled": False,
    }
    if landing != expected_landing:
        errors.append("landing boundary is not the exact static /ProofFlow/ contract")

    runtime = (
        _require_exact_object(
            evidence.get("runtime_boundary"),
            path="evidence-snapshot.json$.runtime_boundary",
            expected_keys=EVIDENCE_OBJECT_KEYS["runtime_boundary"],
            errors=errors,
        )
        or {}
    )
    expected_runtime = {
        "external_side_effects_enabled": False,
        "legal_advice": False,
        "llm_enabled": False,
        "readyWorkers": 0,
        "real_case_data_used": False,
        "worker_containers": 0,
        "workers": "Stopped",
    }
    if runtime != expected_runtime:
        errors.append("runtime boundary drifted from Stopped/0/no-LLM/no-side-effect truth")

    reference_flow = _require_exact_object_array(
        evidence.get("reference_flow"),
        path="evidence-snapshot.json$.reference_flow",
        expected_item_keys=EVIDENCE_OBJECT_KEYS["reference_flow[]"],
        errors=errors,
    )
    if reference_flow != list(EXPECTED_REFERENCE_FLOW):
        errors.append(f"evidence flow must be exactly the reviewed {' -> '.join(FLOW)} sequence")

    pins = (
        _require_exact_object(
            evidence.get("input_pins"),
            path="evidence-snapshot.json$.input_pins",
            expected_keys=EVIDENCE_OBJECT_KEYS["input_pins"],
            errors=errors,
        )
        or {}
    )
    if pins.get("hash_kind") != "UNSIGNED_CONTENT_DIGEST":
        errors.append("input pins must remain explicitly unsigned")
    rule_bytes = _git_bytes(
        repository_root,
        "show",
        f"{SOURCE_COMMIT}:data/rules/cn_labor_contract_law.catalog.json",
    )
    if rule_bytes is None:
        errors.append("cannot load pinned rule catalog from baseline commit")
    elif pins.get("rule_catalog") != "sha256:" + _sha256(rule_bytes):
        errors.append("rule catalog digest does not match baseline commit bytes")

    fixture_names = (
        "contract.json",
        "manifest.json",
        "payroll.json",
        "termination_notice.json",
    )
    fixture_entries: list[dict[str, str]] = []
    for name in fixture_names:
        relative_path = f"examples/cases/happy_path/{name}"
        content = _git_bytes(repository_root, "show", f"{SOURCE_COMMIT}:{relative_path}")
        if content is None:
            errors.append(f"cannot load fixture from baseline commit: {relative_path}")
            continue
        fixture_entries.append({"path": relative_path, "sha256": "sha256:" + _sha256(content)})
    if len(fixture_entries) == len(fixture_names) and pins.get(
        "fixture_bundle"
    ) != _canonical_digest(fixture_entries):
        errors.append("fixture bundle digest does not match baseline commit bytes")

    suite = (
        _require_exact_object(
            evidence.get("contract_suite"),
            path="evidence-snapshot.json$.contract_suite",
            expected_keys=EVIDENCE_OBJECT_KEYS["contract_suite"],
            errors=errors,
        )
        or {}
    )
    if suite != {
        "result": "11/11",
        "report_hash": ("sha256:f81883cca94268e35375e8fcb7eb6afb60b769e15040130cbe7359c6bb23bc17"),
        "scope": "LOCAL_DETERMINISTIC_SYNTHETIC_STRUCTURAL_CONTRACTS",
        "legal_accuracy_measured": False,
        "performance_measured": False,
        "official_score": None,
    }:
        errors.append("contract suite drifted from the reviewed structural-only 11/11 snapshot")

    artifacts = _require_exact_object_array(
        evidence.get("public_artifacts"),
        path="evidence-snapshot.json$.public_artifacts",
        expected_item_keys=EVIDENCE_OBJECT_KEYS["public_artifacts[]"],
        errors=errors,
    )
    artifacts_by_path = {
        item["path"]: item for item in artifacts if isinstance(item.get("path"), str)
    }
    if len(artifacts) != len(EXPECTED_ARTIFACTS):
        errors.append("public artifact inventory must contain exactly three reviewed items")
    if set(artifacts_by_path) != set(EXPECTED_ARTIFACTS):
        errors.append("public artifact inventory must be the exact reviewed closed set")
    for path, (expected_digest, expected_bytes) in EXPECTED_ARTIFACTS.items():
        item = artifacts_by_path.get(path, {})
        content = _git_bytes(repository_root, "show", f"{SOURCE_COMMIT}:{path}")
        if content is None:
            errors.append(f"cannot load public artifact from baseline commit: {path}")
            continue
        actual_digest = _sha256(content)
        if actual_digest != expected_digest or item.get("sha256") != actual_digest:
            errors.append(f"public artifact hash mismatch: {path}")
        if len(content) != expected_bytes or item.get("bytes") != expected_bytes:
            errors.append(f"public artifact byte length mismatch: {path}")

    evaluation = (
        _require_exact_object(
            evidence.get("evaluation_boundary"),
            path="evidence-snapshot.json$.evaluation_boundary",
            expected_keys=EVIDENCE_OBJECT_KEYS["evaluation_boundary"],
            errors=errors,
        )
        or {}
    )
    if evaluation != {
        "deterministic_reference_score": None,
        "official_score": None,
        "single_agent_score": None,
        "six_agent_score": None,
        "status": "PROTOCOL_VALIDATED_NOT_EXECUTED",
    }:
        errors.append("evaluation scores must remain UNKNOWN/null and protocol-not-executed")
    media = (
        _require_exact_object(
            evidence.get("media"),
            path="evidence-snapshot.json$.media",
            expected_keys=EVIDENCE_OBJECT_KEYS["media"],
            errors=errors,
        )
        or {}
    )
    if media != {
        "contract": "media/video-contract.json",
        "publication_status": "NOT_PUBLISHED",
    }:
        errors.append("evidence snapshot must disclose the unpublished media fallback")
    return errors


def _validate_media(site_root: Path, parser: LandingHTMLParser) -> list[str]:
    errors: list[str] = []
    contract_path = site_root / "media/video-contract.json"
    try:
        contract = _load_strict_json(contract_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [f"invalid video-contract.json: {exc}"]

    errors.extend(_scan_json_string_values(label="video-contract.json", value=contract))
    contract_object = _require_exact_object(
        contract,
        path="video-contract.json$",
        expected_keys=VIDEO_OBJECT_KEYS["$"],
        errors=errors,
    )
    if contract_object is None:
        return errors
    contract = contract_object
    video = (
        _require_exact_object(
            contract.get("video"),
            path="video-contract.json$.video",
            expected_keys=VIDEO_OBJECT_KEYS["video"],
            errors=errors,
        )
        or {}
    )
    subtitles = (
        _require_exact_object(
            contract.get("subtitles"),
            path="video-contract.json$.subtitles",
            expected_keys=VIDEO_OBJECT_KEYS["subtitles"],
            errors=errors,
        )
        or {}
    )
    if contract.get("schema_version") != "1.0":
        errors.append("video contract schema version must remain 1.0")
    if contract.get("publication_status") != "NOT_PUBLISHED":
        errors.append("video must remain NOT_PUBLISHED until an independently verified MP4 exists")
    if contract.get("playback_mode") != "STORYBOARD_FALLBACK":
        errors.append("unpublished media must use STORYBOARD_FALLBACK")
    if contract.get("source_evidence_commit") != SOURCE_COMMIT:
        errors.append("video contract must bind the reviewed source evidence commit")
    if video != {
        "codec": None,
        "duration_seconds": None,
        "height": None,
        "path": "media/proofflow-reference-demo.mp4",
        "present": False,
        "sha256": None,
        "width": None,
    }:
        errors.append(
            "unpublished video fields must remain false/null with the fixed relative path"
        )
    if (site_root / "media/proofflow-reference-demo.mp4").exists():
        errors.append("an MP4 exists while the media contract still says NOT_PUBLISHED")

    subtitle_path = site_root / "media/proofflow-reference-demo.zh-CN.vtt"
    try:
        subtitle_bytes = subtitle_path.read_bytes()
    except OSError:
        subtitle_bytes = b""
        errors.append("declared subtitle file is missing")
    if subtitles != {
        "path": "media/proofflow-reference-demo.zh-CN.vtt",
        "present": True,
        "language": "zh-CN",
        "cue_count": 6,
        "sha256": "f539afa38f93e1604b66db7a4e46b276e69650f432d82de8471acdcd98ef295b",
    }:
        errors.append("subtitle contract drifted from the fixed present zh-CN track")
    if subtitles.get("sha256") != _sha256(subtitle_bytes):
        errors.append("subtitle digest does not match the declared VTT bytes")
    captions, vtt_errors = _parse_vtt(subtitle_path)
    errors.extend(vtt_errors)
    html_captions = [segment["caption"] for segment in parser.segments]
    if captions != html_captions:
        errors.append("VTT captions must exactly match the draggable HTML transcript")

    boundaries = (
        _require_exact_object(
            contract.get("claim_boundaries"),
            path="video-contract.json$.claim_boundaries",
            expected_keys=VIDEO_OBJECT_KEYS["claim_boundaries"],
            errors=errors,
        )
        or {}
    )
    if boundaries != {
        "classification": "PUBLIC_SYNTHETIC",
        "external_side_effects_enabled": False,
        "legal_accuracy_measured": False,
        "live_runtime_demonstrated": False,
        "llm_enabled": False,
        "readyWorkers": 0,
        "workers": "Stopped",
    }:
        errors.append("video claim boundaries drifted from the public synthetic truth")
    publication_gate = contract.get("publication_gate")
    if publication_gate != list(EXPECTED_PUBLICATION_GATE):
        errors.append("video publication gate must keep the exact 6 reviewed checks")
    return errors


def validate_public_demo(
    repository_root: Path = ROOT,
    site_root: Path | None = None,
) -> list[str]:
    """Return every contract error; an empty list is the only passing verdict."""
    selected_site_root = site_root or repository_root / "public-demo"
    errors: list[str] = []
    required_files = (
        "README.md",
        "app.js",
        "evidence-snapshot.json",
        "favicon.svg",
        "index.html",
        "media/proofflow-reference-demo.zh-CN.vtt",
        "media/video-contract.json",
        "styles.css",
    )
    for relative_path in required_files:
        selected_path = selected_site_root / relative_path
        if not selected_path.is_file():
            errors.append(f"required static file is missing: {relative_path}")
        elif selected_path.is_symlink():
            errors.append(f"required static file must not be a symlink: {relative_path}")
    if errors:
        return sorted(errors)

    html = (selected_site_root / "index.html").read_text(encoding="utf-8")
    css = (selected_site_root / "styles.css").read_text(encoding="utf-8")
    javascript = (selected_site_root / "app.js").read_text(encoding="utf-8")
    parser = LandingHTMLParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:  # HTMLParser can surface malformed entity/state failures.
        return [f"cannot parse index.html: {exc}"]

    visible_text = _normalized_text(" ".join(parser.text_parts))
    if parser.forbidden_elements:
        errors.append(
            "forbidden active/embed elements: " + ", ".join(sorted(parser.forbidden_elements))
        )
    if parser.inline_event_attributes:
        errors.append(
            "inline event handlers are forbidden: "
            + ", ".join(sorted(parser.inline_event_attributes))
        )
    if parser.inline_scripts:
        errors.append("inline executable scripts are forbidden")
    if parser.inline_styles:
        errors.append("inline style blocks are forbidden")
    duplicate_ids = sorted(
        {identifier for identifier in parser.ids if parser.ids.count(identifier) > 1}
    )
    if duplicate_ids:
        errors.append("duplicate DOM ids: " + ", ".join(duplicate_ids))
    if len([heading for heading in parser.headings if heading == "PROOF BEFORE ACTION"]) != 1:
        errors.append("page must expose exactly one PROOF BEFORE ACTION h1")
    if parser.flow != list(FLOW):
        errors.append(f"DOM flow must be exactly {' -> '.join(FLOW)}")
    if len(parser.segments) != 6:
        errors.append(f"draggable transcript must contain 6 segments, found {len(parser.segments)}")
    else:
        starts = [int(segment["start"]) for segment in parser.segments]
        ends = [int(segment["end"]) for segment in parser.segments]
        if starts != [0, 12, 28, 40, 58, 75] or ends != [12, 28, 40, 58, 75, 91]:
            errors.append("storyboard segments must cover the fixed 0-90 second sequence")
    if len(parser.range_inputs) != 1:
        errors.append("page must expose exactly one draggable storyboard range input")
    elif {
        "min": parser.range_inputs[0].get("min"),
        "max": parser.range_inputs[0].get("max"),
        "step": parser.range_inputs[0].get("step"),
    } != {"min": "0", "max": "90", "step": "1"}:
        errors.append("storyboard range must be the fixed 0-90 second timeline")

    required_text = (
        "PUBLIC_SYNTHETIC",
        "Workers Stopped",
        "readyWorkers=0",
        "LLM OFF",
        "NO EXTERNAL SIDE EFFECTS",
        "非法律意见",
        "READ-ONLY FLOW / NOT LIVE RUNTIME",
        "VIDEO NOT PUBLISHED",
        "STORYBOARD_FALLBACK",
        "LEGAL ACCURACY: NOT MEASURED",
        "OFFICIAL SCORE UNKNOWN / null",
    )
    for phrase in required_text:
        if phrase not in visible_text:
            errors.append(f"required visible claim boundary is missing: {phrase}")
    for pattern in FORBIDDEN_VISIBLE_CLAIMS:
        if pattern.search(visible_text):
            errors.append(f"forbidden visible claim matched: {pattern.pattern}")

    loaded_text_assets = {
        "README.md": (selected_site_root / "README.md").read_text(encoding="utf-8"),
        "app.js": javascript,
        "favicon.svg": (selected_site_root / "favicon.svg").read_text(encoding="utf-8"),
        "index.html": html,
        "styles.css": css,
        "media/proofflow-reference-demo.zh-CN.vtt": (
            selected_site_root / "media/proofflow-reference-demo.zh-CN.vtt"
        ).read_text(encoding="utf-8"),
    }
    for label, content in loaded_text_assets.items():
        errors.extend(_scan_text(label=f"loaded asset {label}", value=content))

    if len(parser.csp_values) != 1:
        errors.append("page must declare exactly one CSP meta policy")
    else:
        for directive in REQUIRED_CSP_DIRECTIVES:
            if directive not in parser.csp_values[0]:
                errors.append(f"CSP is missing required directive: {directive}")

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
    external_anchor_urls: set[str] = set()
    local_anchor_urls: set[str] = set()
    for anchor in parser.anchors:
        url = anchor.get("href", "")
        parsed = urlsplit(url)
        if parsed.scheme in {"http", "https"}:
            external_anchor_urls.add(url)
            if parsed.scheme != "https" or parsed.hostname not in ALLOWED_EXTERNAL_ANCHOR_HOSTS:
                errors.append(f"external navigation host is not allowed: {url}")
            if SOURCE_COMMIT not in url and url != "https://github.com/MyGarfield/ProofFlow":
                errors.append(f"external evidence link is not fixed to the baseline commit: {url}")
            rel = set(anchor.get("rel", "").casefold().split())
            if anchor.get("target") != "_blank" or not {"noopener", "noreferrer"} <= rel:
                errors.append(f"external navigation must isolate referrer/opener: {url}")
        elif parsed.scheme or parsed.netloc:
            errors.append(f"unsupported anchor scheme: {url}")
        else:
            local_anchor_urls.add(url)
            errors.extend(
                _validate_local_url(
                    url=url,
                    site_root=selected_site_root,
                    ids=ids,
                    label="local anchor",
                )
            )
    if external_anchor_urls != EXPECTED_EXTERNAL_ANCHORS:
        errors.append("external material links must be the exact reviewed GitHub closed set")
    if not local_anchor_urls >= REQUIRED_LOCAL_ANCHORS:
        missing = sorted(REQUIRED_LOCAL_ANCHORS - local_anchor_urls)
        errors.append("required relative/fragment links are missing: " + ", ".join(missing))

    token_expectations = {
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
    for token, value in token_expectations.items():
        if not re.search(rf"{re.escape(token)}\s*:\s*{re.escape(value)}\s*;", css):
            errors.append(f"Swiss Style token drifted: {token}")
    for forbidden_css in ("border-radius", "@font-face", "@import", "url("):
        if forbidden_css.casefold() in css.casefold():
            errors.append(f"CSS contains forbidden external/rounded-style token: {forbidden_css}")
    allowed_generated_content = {'""', "''", '"→"', "'→'"}
    generated_content = {
        value.strip() for value in re.findall(r"(?<![-\w])content\s*:\s*([^;]+);", css)
    }
    if not generated_content <= allowed_generated_content:
        errors.append("CSS generated text is outside the reviewed empty/arrow closed set")
    if "grid-template-columns: repeat(12, minmax(0, 1fr));" not in css:
        errors.append("Swiss 12-column grid must use minmax(0, 1fr)")
    if "--target: 44px;" not in css:
        errors.append("interactive target token must remain 44px")
    if "@media (prefers-reduced-motion: reduce)" not in css:
        errors.append("global reduced-motion contract is missing")

    for token in NETWORK_JS_TOKENS:
        if token in javascript:
            errors.append(f"static storyboard must not use network/storage API: {token}")

    errors.extend(_validate_evidence(repository_root, selected_site_root))
    errors.extend(_validate_favicon(selected_site_root / "favicon.svg"))
    errors.extend(_validate_media(selected_site_root, parser))
    return sorted(set(errors))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the offline ProofFlow public demo landing page."
    )
    parser.add_argument(
        "--site-root",
        type=Path,
        default=SITE_ROOT,
        help="public-demo directory to validate",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    errors = validate_public_demo(ROOT, args.site_root.resolve())
    if errors:
        print("PUBLIC_DEMO_INVALID")
        for error in errors:
            print(f"- {error}")
        return 1
    print("PUBLIC_DEMO_VALID")
    print("scope=HISTORICAL_REFERENCE_BASELINE_NOT_CURRENT_CORE")
    print(f"source_commit={SOURCE_COMMIT}")
    print("flow=prepare->409->approve->package->verify->11/11")
    print("media=STORYBOARD_FALLBACK/NOT_PUBLISHED")
    print("external_loaded_resources=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
