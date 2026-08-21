"""stdlib-only HTTP measurement engine for the local ProofFlow tool service."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import math
import os
import platform
import re
import resource
import socket
import ssl
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Timer
from time import monotonic, monotonic_ns, process_time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from benchmarks.performance.samples import (
    RequestSample,
    build_evidence_setup_samples,
    build_fixed_samples,
)
from proofflow.models import EvidenceObject

ROOT = Path(__file__).resolve().parents[2]
REPORT_SCHEMA_VERSION = "proofflow.performance-report/v1"
REPORT_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
RUNTIME_IMAGE_DIGEST_ENV = "PROOFFLOW_RUNTIME_IMAGE_DIGEST"
MAX_TARGETS = 2
MAX_WARMUP_REQUESTS_PER_ENDPOINT = 100
MAX_MEASURED_REQUESTS_PER_ENDPOINT = 10_000
MAX_CONCURRENCY = 64
MAX_TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_BYTES = 1024 * 1024
RESPONSE_READ_CHUNK_BYTES = 64 * 1024


class BenchmarkConfigurationError(ValueError):
    """Raised before network activity when benchmark configuration is unsafe."""


@dataclass(frozen=True, slots=True)
class BenchmarkTarget:
    """A local endpoint exposing the same three ProofFlow REST paths."""

    label: str
    kind: str
    base_url: str


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    """Fixed load parameters; counts apply independently to every endpoint."""

    targets: tuple[BenchmarkTarget, ...]
    warmup_requests_per_endpoint: int = 5
    measured_requests_per_endpoint: int = 100
    concurrency: int = 4
    timeout_seconds: float = 5.0
    max_response_bytes: int = MAX_RESPONSE_BYTES
    allow_non_loopback: bool = False
    resource_scope: str = "RUNNER_ONLY"

    def validate(self) -> None:
        if not self.targets:
            raise BenchmarkConfigurationError("at least one target is required")
        if len(self.targets) > MAX_TARGETS:
            raise BenchmarkConfigurationError(f"target count cannot exceed {MAX_TARGETS}")
        if not 0 <= self.warmup_requests_per_endpoint <= MAX_WARMUP_REQUESTS_PER_ENDPOINT:
            raise BenchmarkConfigurationError(
                f"warmup count must be between 0 and {MAX_WARMUP_REQUESTS_PER_ENDPOINT}"
            )
        if not 1 <= self.measured_requests_per_endpoint <= MAX_MEASURED_REQUESTS_PER_ENDPOINT:
            raise BenchmarkConfigurationError(
                f"measured request count must be between 1 and {MAX_MEASURED_REQUESTS_PER_ENDPOINT}"
            )
        if not 1 <= self.concurrency <= MAX_CONCURRENCY:
            raise BenchmarkConfigurationError(
                f"concurrency must be between 1 and {MAX_CONCURRENCY}"
            )
        if (
            not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= MAX_TIMEOUT_SECONDS
        ):
            raise BenchmarkConfigurationError(
                f"timeout must be finite, positive, and at most {MAX_TIMEOUT_SECONDS} seconds"
            )
        if not 1 <= self.max_response_bytes <= MAX_RESPONSE_BYTES:
            raise BenchmarkConfigurationError(
                f"response limit must be between 1 and {MAX_RESPONSE_BYTES} bytes"
            )
        if self.resource_scope not in {"RUNNER_ONLY", "CLIENT_AND_SERVICE"}:
            raise BenchmarkConfigurationError("resource scope is not recognized")
        labels: set[str] = set()
        for target in self.targets:
            if not target.label or target.label in labels:
                raise BenchmarkConfigurationError("target labels must be non-empty and unique")
            if target.kind not in {"DIRECT_HTTP", "HIGRESS_HTTP_FORWARD"}:
                raise BenchmarkConfigurationError("target kind is not recognized")
            labels.add(target.label)
            validate_base_url(target.base_url, allow_non_loopback=self.allow_non_loopback)


@dataclass(frozen=True, slots=True)
class RequestObservation:
    """One client-observed outcome without response bodies or exception text."""

    latency_ns: int
    http_status: int | None
    transport_error: str | None
    response_read_error: str | None
    json_valid: bool
    skill_status: str | None
    service_status: str | None


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def unsigned_sha256(value: object) -> str:
    """Return an unsigned canonical content digest, not an authenticity proof."""
    return f"sha256:{hashlib.sha256(_canonical_json_bytes(value)).hexdigest()}"


def compute_report_hash(report: Mapping[str, Any]) -> str:
    """Hash the complete report except a pre-existing top-level report hash."""
    return unsigned_sha256({key: value for key, value in report.items() if key != "report_hash"})


def nearest_rank_percentile(values: Iterable[int], percentile: int) -> int | None:
    """Return the nearest-rank percentile for integer observations."""
    if not 1 <= percentile <= 100:
        raise ValueError("percentile must be between 1 and 100")
    ordered = sorted(values)
    if not ordered:
        return None
    rank = max(1, math.ceil(percentile / 100 * len(ordered)))
    return ordered[rank - 1]


def validate_base_url(base_url: str, *, allow_non_loopback: bool = False) -> str:
    """Validate and normalize a target, refusing non-loopback hosts by default."""
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise BenchmarkConfigurationError("target URL scheme must be http or https")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise BenchmarkConfigurationError("target URL must have a host and no userinfo")
    if parsed.query or parsed.fragment:
        raise BenchmarkConfigurationError("target URL cannot contain a query or fragment")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise BenchmarkConfigurationError("target URL has an invalid port") from exc
    del parsed_port
    if not allow_non_loopback and not _is_loopback_host(parsed.hostname):
        raise BenchmarkConfigurationError(
            "non-loopback target refused; use an explicit opt-in only for an authorized gateway"
        )
    normalized_path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, normalized_path, "", ""))


def _is_loopback_host(hostname: str) -> bool:
    if hostname.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _safe_target_url(base_url: str) -> str:
    """Return a reportable URL with no credentials, query, or fragment."""
    parsed = urlsplit(base_url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


class _ResponseTooLarge(Exception):
    """Raised without retaining attacker-controlled response bytes."""


class _ResponseReadDeadline(Exception):
    """Raised once the aggregate response-body read deadline expires."""


def _transport_error_category(error: BaseException) -> str:
    if isinstance(error, TimeoutError):
        return "TIMEOUT"
    if isinstance(error, socket.gaierror):
        return "NAME_RESOLUTION"
    if isinstance(error, ssl.SSLError):
        return "TLS"
    if isinstance(error, ConnectionRefusedError):
        return "CONNECTION_REFUSED"
    if isinstance(error, ConnectionResetError):
        return "CONNECTION_RESET"
    return "OTHER_IO_ERROR"


def _connection_for_url(
    base_url: str, *, timeout_seconds: float
) -> tuple[http.client.HTTPConnection, str]:
    """Create a direct connection that cannot use proxies or follow redirects."""
    parsed = urlsplit(base_url)
    assert parsed.hostname is not None
    request_prefix = parsed.path.rstrip("/")
    if parsed.scheme == "https":
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            parsed.hostname,
            port=parsed.port,
            timeout=timeout_seconds,
            context=ssl.create_default_context(),
        )
    else:
        connection = http.client.HTTPConnection(
            parsed.hostname,
            port=parsed.port,
            timeout=timeout_seconds,
        )
    return connection, request_prefix


def _content_length(response: http.client.HTTPResponse) -> int | None:
    values = response.headers.get_all("Content-Length", failobj=[])
    if len(values) != 1:
        return None
    raw_value = values[0].strip()
    if not raw_value.isascii() or not raw_value.isdigit():
        return None
    return int(raw_value)


def _read_response_body(
    response: http.client.HTTPResponse,
    connection: http.client.HTTPConnection,
    *,
    max_response_bytes: int,
    deadline: float,
) -> bytes:
    """Read at most one bounded body under a single aggregate deadline."""
    declared_length = _content_length(response)
    if declared_length is not None and declared_length > max_response_bytes:
        raise _ResponseTooLarge
    body = bytearray()
    while True:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise _ResponseReadDeadline
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        try:
            chunk = response.read1(
                min(RESPONSE_READ_CHUNK_BYTES, max_response_bytes + 1 - len(body))
            )
        except TimeoutError as exc:
            raise _ResponseReadDeadline from exc
        if not chunk:
            if monotonic() > deadline:
                raise _ResponseReadDeadline
            return bytes(body)
        body.extend(chunk)
        if len(body) > max_response_bytes:
            raise _ResponseTooLarge


@dataclass(frozen=True, slots=True)
class _RequestExchange:
    observation: RequestObservation
    json_object: dict[str, Any] | None


def _request_json_once(
    target: BenchmarkTarget,
    sample: RequestSample,
    *,
    bearer_token: str | None,
    timeout_seconds: float,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> _RequestExchange:
    base_url = validate_base_url(target.base_url, allow_non_loopback=True)
    headers = {"Accept": "application/json"}
    if sample.body is not None:
        headers["Content-Type"] = "application/json"
        if bearer_token is not None:
            headers["Authorization"] = f"Bearer {bearer_token}"

    started = monotonic_ns()
    status: int | None = None
    response_read_error: str | None = None
    body = b""
    connection, request_prefix = _connection_for_url(base_url, timeout_seconds=timeout_seconds)
    deadline = monotonic() + timeout_seconds
    deadline_fired = Event()

    def abort_at_deadline() -> None:
        deadline_fired.set()
        active_socket = connection.sock
        if active_socket is not None:
            with suppress(OSError):
                active_socket.shutdown(socket.SHUT_RDWR)
        connection.close()

    watchdog = Timer(timeout_seconds, abort_at_deadline)
    watchdog.daemon = True
    watchdog.start()
    try:
        connection.request(
            sample.method,
            f"{request_prefix}{sample.path}",
            body=sample.body,
            headers=headers,
        )
        response = connection.getresponse()
        status = response.status
        try:
            body = _read_response_body(
                response,
                connection,
                max_response_bytes=max_response_bytes,
                deadline=deadline,
            )
        except _ResponseTooLarge:
            response_read_error = "RESPONSE_TOO_LARGE"
        except _ResponseReadDeadline:
            response_read_error = (
                "RESPONSE_TOTAL_DEADLINE" if deadline_fired.is_set() else "RESPONSE_BODY_DEADLINE"
            )
        except http.client.IncompleteRead:
            response_read_error = "INCOMPLETE_RESPONSE"
        except (OSError, http.client.HTTPException):
            response_read_error = (
                "RESPONSE_TOTAL_DEADLINE" if deadline_fired.is_set() else "RESPONSE_IO_ERROR"
            )
    except (OSError, http.client.HTTPException) as error:
        return _RequestExchange(
            observation=RequestObservation(
                latency_ns=monotonic_ns() - started,
                http_status=None,
                transport_error=(
                    "REQUEST_RESPONSE_DEADLINE"
                    if deadline_fired.is_set()
                    else _transport_error_category(error)
                ),
                response_read_error=None,
                json_valid=False,
                skill_status=None,
                service_status=None,
            ),
            json_object=None,
        )
    finally:
        watchdog.cancel()
        connection.close()

    skill_status: str | None = None
    service_status: str | None = None
    json_valid = False
    decoded_object: dict[str, Any] | None = None
    if response_read_error is None:
        try:
            decoded = json.loads(body)
            json_valid = isinstance(decoded, dict)
            if json_valid:
                decoded_object = decoded
                status_value = decoded.get("status")
                if isinstance(status_value, str):
                    if sample.expected_skill_status is not None:
                        skill_status = status_value
                    elif sample.expected_service_status is not None:
                        service_status = status_value
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return _RequestExchange(
        observation=RequestObservation(
            latency_ns=monotonic_ns() - started,
            http_status=status,
            transport_error=None,
            response_read_error=response_read_error,
            json_valid=json_valid,
            skill_status=skill_status,
            service_status=service_status,
        ),
        json_object=decoded_object,
    )


def _request_once(
    target: BenchmarkTarget,
    sample: RequestSample,
    *,
    bearer_token: str | None,
    timeout_seconds: float,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> RequestObservation:
    return _request_json_once(
        target,
        sample,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
        max_response_bytes=max_response_bytes,
    ).observation


def _functionally_successful(
    observation: RequestObservation,
    *,
    expected_skill_status: str | None,
    expected_service_status: str | None,
) -> bool:
    if observation.http_status is None or not 200 <= observation.http_status < 300:
        return False
    if observation.response_read_error is not None or not observation.json_valid:
        return False
    if expected_skill_status is not None:
        return observation.skill_status == expected_skill_status
    if expected_service_status is not None:
        return observation.service_status == expected_service_status
    return True


def summarize_observations(
    observations: Iterable[RequestObservation],
    *,
    wall_seconds: float,
    expected_skill_status: str | None,
    expected_service_status: str | None,
) -> dict[str, Any]:
    """Summarize transport/HTTP errors separately from Skill outcomes."""
    values = tuple(observations)
    if not values:
        raise ValueError("at least one observation is required")
    if not math.isfinite(wall_seconds) or wall_seconds <= 0:
        raise ValueError("wall_seconds must be finite and positive")
    latency_ns = [observation.latency_ns for observation in values]
    http_statuses = Counter(
        str(observation.http_status)
        for observation in values
        if observation.http_status is not None
    )
    transport_errors = Counter(
        observation.transport_error
        for observation in values
        if observation.transport_error is not None
    )
    response_read_errors = Counter(
        observation.response_read_error
        for observation in values
        if observation.response_read_error is not None
    )
    skill_statuses = Counter(
        observation.skill_status for observation in values if observation.skill_status is not None
    )
    http_success_count = sum(
        observation.http_status is not None and 200 <= observation.http_status < 300
        for observation in values
    )
    http_error_count = sum(
        observation.http_status is not None and not 200 <= observation.http_status < 300
        for observation in values
    )
    invalid_json_count = sum(
        observation.http_status is not None
        and observation.response_read_error is None
        and not observation.json_valid
        for observation in values
    )
    skill_status_unavailable_count = (
        sum(observation.skill_status is None for observation in values)
        if expected_skill_status is not None
        else 0
    )

    functional_success_count = sum(
        _functionally_successful(
            item,
            expected_skill_status=expected_skill_status,
            expected_service_status=expected_service_status,
        )
        for item in values
    )

    def to_milliseconds(value: int | None) -> float | None:
        return None if value is None else round(value / 1_000_000, 6)

    return {
        "attempted_request_count": len(values),
        "functional_success_count": functional_success_count,
        "functional_failure_count": len(values) - functional_success_count,
        "http_status_received_count": len(values) - sum(transport_errors.values()),
        "complete_http_response_count": (
            len(values) - sum(transport_errors.values()) - sum(response_read_errors.values())
        ),
        "http_2xx_status_count": http_success_count,
        "http_non_2xx_status_count": http_error_count,
        "transport_error_count": sum(transport_errors.values()),
        "transport_errors": dict(sorted(transport_errors.items())),
        "response_read_error_count": sum(response_read_errors.values()),
        "response_read_errors": dict(sorted(response_read_errors.items())),
        "http_status_counts": dict(sorted(http_statuses.items())),
        "invalid_json_response_count": invalid_json_count,
        "skill_status_counts": dict(sorted(skill_statuses.items())),
        "skill_status_unavailable_count": skill_status_unavailable_count,
        "latency_ms": {
            "population": "ALL_REQUEST_ATTEMPTS",
            "minimum": to_milliseconds(min(latency_ns)),
            "p50_nearest_rank": to_milliseconds(nearest_rank_percentile(latency_ns, 50)),
            "p95_nearest_rank": to_milliseconds(nearest_rank_percentile(latency_ns, 95)),
            "p99_nearest_rank": to_milliseconds(nearest_rank_percentile(latency_ns, 99)),
            "maximum": to_milliseconds(max(latency_ns)),
        },
        "measured_wall_seconds": round(wall_seconds, 6),
        "attempted_throughput_requests_per_second": round(len(values) / wall_seconds, 6),
        "functional_throughput_requests_per_second": round(
            functional_success_count / wall_seconds, 6
        ),
    }


def _prepare_target(
    target: BenchmarkTarget,
    config: BenchmarkConfig,
    bearer_token: str | None,
) -> tuple[tuple[EvidenceObject, ...], dict[str, Any], tuple[RequestSample, ...]]:
    """Seed server-issued synthetic Evidence without including setup in measurements."""
    setup_samples = build_evidence_setup_samples()
    evidence: list[EvidenceObject] = []
    request_reports: list[dict[str, Any]] = []
    for sample in setup_samples:
        exchange = _request_json_once(
            target,
            sample,
            bearer_token=bearer_token,
            timeout_seconds=config.timeout_seconds,
            max_response_bytes=config.max_response_bytes,
        )
        observation = exchange.observation
        request_success = _functionally_successful(
            observation,
            expected_skill_status=sample.expected_skill_status,
            expected_service_status=sample.expected_service_status,
        )
        artifact_count = 0
        artifacts_valid = False
        if request_success and exchange.json_object is not None:
            value = exchange.json_object.get("value")
            raw_evidence = value.get("evidence_objects") if isinstance(value, dict) else None
            if isinstance(raw_evidence, list):
                try:
                    parsed_evidence = tuple(
                        EvidenceObject.model_validate(item) for item in raw_evidence
                    )
                except (TypeError, ValueError):
                    parsed_evidence = ()
                else:
                    if parsed_evidence:
                        artifacts_valid = True
                        evidence.extend(parsed_evidence)
                        artifact_count = len(parsed_evidence)
        request_reports.append(
            {
                "name": sample.name,
                "path": sample.path,
                "http_status": observation.http_status,
                "transport_error": observation.transport_error,
                "response_read_error": observation.response_read_error,
                "json_valid": observation.json_valid,
                "skill_status": observation.skill_status,
                "artifacts_valid": artifacts_valid,
                "registered_evidence_count": artifact_count,
                "functional_success": request_success and artifacts_valid,
                "sample_body_sha256": (
                    f"sha256:{hashlib.sha256(sample.body).hexdigest()}"
                    if sample.body is not None
                    else None
                ),
            }
        )
    all_successful = all(item["functional_success"] for item in request_reports)
    return (
        tuple(evidence),
        {
            "purpose": "SEED_BOUNDED_IN_MEMORY_SYNTHETIC_TRUST_REGISTRY",
            "included_in_latency_or_throughput": False,
            "request_count": len(request_reports),
            "all_requests_successful": all_successful,
            "registered_evidence_count": len(evidence),
            "requests": request_reports,
        },
        setup_samples,
    )


def _measure_endpoint(
    target: BenchmarkTarget,
    sample: RequestSample,
    config: BenchmarkConfig,
    bearer_token: str | None,
) -> dict[str, Any]:
    warmup = [
        _request_once(
            target,
            sample,
            bearer_token=bearer_token,
            timeout_seconds=config.timeout_seconds,
            max_response_bytes=config.max_response_bytes,
        )
        for _ in range(config.warmup_requests_per_endpoint)
    ]
    started = monotonic()
    worker_count = min(config.concurrency, config.measured_requests_per_endpoint)
    quotient, remainder = divmod(config.measured_requests_per_endpoint, worker_count)
    worker_request_counts = tuple(
        quotient + (1 if worker_index < remainder else 0) for worker_index in range(worker_count)
    )

    def worker(request_count: int) -> tuple[RequestObservation, ...]:
        return tuple(
            _request_once(
                target,
                sample,
                bearer_token=bearer_token,
                timeout_seconds=config.timeout_seconds,
                max_response_bytes=config.max_response_bytes,
            )
            for _ in range(request_count)
        )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        observations = tuple(
            observation
            for worker_observations in executor.map(worker, worker_request_counts)
            for observation in worker_observations
        )
    wall_seconds = monotonic() - started
    measured = summarize_observations(
        observations,
        wall_seconds=wall_seconds,
        expected_skill_status=sample.expected_skill_status,
        expected_service_status=sample.expected_service_status,
    )
    warmup_failures = sum(
        not _functionally_successful(
            observation,
            expected_skill_status=sample.expected_skill_status,
            expected_service_status=sample.expected_service_status,
        )
        for observation in warmup
    )
    return {
        "endpoint": sample.name,
        "method": sample.method,
        "path": sample.path,
        "sample_body_bytes": len(sample.body) if sample.body is not None else 0,
        "sample_body_sha256": (
            f"sha256:{hashlib.sha256(sample.body).hexdigest()}" if sample.body is not None else None
        ),
        "expected_skill_status": sample.expected_skill_status,
        "expected_service_status": sample.expected_service_status,
        "warmup": {
            "attempted_request_count": len(warmup),
            "functional_failure_count": warmup_failures,
            "excluded_from_latency_and_throughput": True,
        },
        "measurement": measured,
    }


@dataclass(frozen=True, slots=True)
class _ResourceSnapshot:
    process_cpu_seconds: float
    process_max_rss_bytes: int
    system_available_memory_bytes: int | None


def _max_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def _system_available_memory_bytes() -> int | None:
    if sys.platform.startswith("linux"):
        try:
            fields = {}
            for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
                name, separator, remainder = line.partition(":")
                if separator:
                    fields[name] = int(remainder.strip().split()[0]) * 1024
            return fields.get("MemAvailable")
        except (OSError, ValueError, IndexError):
            return None
    if sys.platform == "darwin":
        try:
            page_size = int(subprocess.check_output(["sysctl", "-n", "hw.pagesize"], timeout=2))
            output = subprocess.check_output(["vm_stat"], text=True, timeout=2)
            page_fields: dict[str, int] = {}
            for line in output.splitlines():
                name, separator, raw_value = line.partition(":")
                if separator:
                    try:
                        page_fields[name] = int(raw_value.strip().rstrip("."))
                    except ValueError:
                        continue
            available_pages = sum(
                page_fields.get(name, 0)
                for name in ("Pages free", "Pages inactive", "Pages speculative")
            )
            return available_pages * page_size
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
    return None


def _total_memory_bytes() -> int | None:
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        physical_pages = os.sysconf("SC_PHYS_PAGES")
        if (
            isinstance(page_size, int)
            and isinstance(physical_pages, int)
            and page_size > 0
            and physical_pages > 0
        ):
            return page_size * physical_pages
    except (OSError, ValueError):
        pass
    if sys.platform == "darwin":
        try:
            return int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], timeout=2))
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
    return None


def _cpu_model() -> str | None:
    if sys.platform == "darwin":
        try:
            value = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"], text=True, timeout=2
            ).strip()
            if value:
                return value
        except (OSError, subprocess.SubprocessError):
            pass
    value = platform.processor().strip()
    if value:
        return value
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
                name, separator, raw_value = line.partition(":")
                if separator and name.strip() in {"model name", "Hardware"}:
                    return raw_value.strip() or None
        except OSError:
            return None
    return None


def _resource_snapshot() -> _ResourceSnapshot:
    return _ResourceSnapshot(
        process_cpu_seconds=process_time(),
        process_max_rss_bytes=_max_rss_bytes(),
        system_available_memory_bytes=_system_available_memory_bytes(),
    )


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _bundle_digest(relative_root: str, *, exclude_reports: bool = False) -> dict[str, Any]:
    base = ROOT / relative_root
    entries = []
    for path in sorted(item for item in base.rglob("*") if item.is_file()):
        relative = path.relative_to(ROOT).as_posix()
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if exclude_reports and "reports" in path.relative_to(base).parts:
            continue
        entries.append({"path": relative, "sha256": _file_digest(path)})
    return {
        "root": relative_root,
        "file_count": len(entries),
        "bundle_sha256": unsigned_sha256(entries),
        "hash_kind": "UNSIGNED_CONTENT_DIGEST",
        "signature_verified": False,
    }


def _git_output(*arguments: str) -> bytes | None:
    try:
        result = subprocess.run(
            ["git", "-c", "core.quotepath=false", *arguments],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def _git_ascii(*arguments: str) -> str | None:
    raw = _git_output(*arguments)
    if raw is None:
        return None
    try:
        return raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None


def _provenance(samples: tuple[RequestSample, ...]) -> dict[str, Any]:
    status = _git_output("status", "--porcelain=v1", "-z", "--untracked-files=all")
    image_digest = os.environ.get(RUNTIME_IMAGE_DIGEST_ENV)
    image_digest_valid = bool(image_digest and REPORT_HASH_PATTERN.fullmatch(image_digest))
    return {
        "git": {
            "available": status is not None,
            "head_commit": _git_ascii("rev-parse", "--verify", "HEAD"),
            "head_tree": _git_ascii("rev-parse", "--verify", "HEAD^{tree}"),
            "dirty": bool(status) if status is not None else None,
            "dirty_status_digest": (
                f"sha256:{hashlib.sha256(status).hexdigest()}" if status is not None else None
            ),
            "dirty_paths_disclosed": False,
            "signature_verified": False,
        },
        "input_bundles": {
            "benchmark_harness": _bundle_digest("benchmarks/performance", exclude_reports=True),
            "reference_core": _bundle_digest("src/proofflow"),
            "synthetic_fixture": _bundle_digest("examples/cases/happy_path"),
            "rule_catalog": _bundle_digest("data/rules"),
        },
        "uv_lock": {
            "path": "uv.lock",
            "sha256": _file_digest(ROOT / "uv.lock"),
            "hash_kind": "UNSIGNED_CONTENT_DIGEST",
            "signature_verified": False,
        },
        "request_samples": [
            {
                "name": sample.name,
                "method": sample.method,
                "path": sample.path,
                "body_bytes": len(sample.body) if sample.body is not None else 0,
                "body_sha256": (
                    f"sha256:{hashlib.sha256(sample.body).hexdigest()}"
                    if sample.body is not None
                    else None
                ),
                "fixture_status": "SYNTHETIC",
            }
            for sample in samples
        ],
        "runtime_image": {
            "digest": image_digest if image_digest_valid else None,
            "source": "UNVERIFIED_ENVIRONMENT_ASSERTION" if image_digest_valid else None,
            "verified": False,
        },
        "hashes_are_digital_signatures": False,
    }


def _machine_environment() -> dict[str, Any]:
    return {
        "python": {
            "implementation": sys.implementation.name,
            "version": platform.python_version(),
            "cache_tag": sys.implementation.cache_tag,
        },
        "operating_system": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "cpu": {
            "logical_cpu_count": os.cpu_count(),
            "model": _cpu_model(),
        },
        "memory": {"physical_total_bytes": _total_memory_bytes()},
        "hostname_recorded": False,
        "absolute_paths_recorded": False,
    }


def run_benchmark(
    config: BenchmarkConfig,
    *,
    bearer_token: str | None,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Run one local benchmark and return a self-hashed machine-readable report."""
    config.validate()
    report_time = generated_at or datetime.now(UTC)
    if report_time.tzinfo is None or report_time.utcoffset() is None:
        raise BenchmarkConfigurationError("generated_at must be timezone-aware")
    before = _resource_snapshot()
    run_started = monotonic()
    target_reports = []
    provenance_samples: list[RequestSample] = []
    for target in config.targets:
        trusted_evidence, preparation_report, setup_samples = _prepare_target(
            target, config, bearer_token
        )
        samples = build_fixed_samples(trusted_evidence=trusted_evidence)
        provenance_samples.extend((*setup_samples, *samples))
        endpoint_reports = [
            _measure_endpoint(target, sample, config, bearer_token) for sample in samples
        ]
        target_reports.append(
            {
                "label": target.label,
                "kind": target.kind,
                "base_url": _safe_target_url(target.base_url),
                "preparation": preparation_report,
                "endpoints": endpoint_reports,
            }
        )
    total_wall_seconds = monotonic() - run_started
    after = _resource_snapshot()

    endpoint_measurements = [
        endpoint["measurement"] for target in target_reports for endpoint in target["endpoints"]
    ]
    attempted = sum(item["attempted_request_count"] for item in endpoint_measurements)
    functional_success = sum(item["functional_success_count"] for item in endpoint_measurements)
    all_preparations_successful = all(
        target["preparation"]["all_requests_successful"] for target in target_reports
    )
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "benchmark_version": "0.1.0",
        "generated_at": report_time.isoformat(),
        "run_classification": "LOCAL_SINGLE_RUN",
        "measurement_scope": "TOOL_SERVICE_HTTP_ONLY",
        "data_classification": "PUBLIC_SYNTHETIC",
        "configuration": {
            "warmup_requests_per_endpoint": config.warmup_requests_per_endpoint,
            "measured_requests_per_endpoint": config.measured_requests_per_endpoint,
            "concurrency": config.concurrency,
            "timeout_seconds": config.timeout_seconds,
            "total_request_response_deadline_seconds": config.timeout_seconds,
            "response_body_uses_remaining_total_deadline": True,
            "max_response_body_bytes": config.max_response_bytes,
            "target_count": len(config.targets),
            "endpoint_count_per_target": 3,
            "total_measured_request_count": attempted,
            "total_preparation_request_count": sum(
                target["preparation"]["request_count"] for target in target_reports
            ),
            "http_client": "PYTHON_STDLIB_HTTP_CLIENT",
            "connection_policy": "NO_POOL_ONE_DIRECT_CONNECTION_PER_ATTEMPT",
            "environment_proxy_policy": "IGNORED_BY_IMPLEMENTATION",
            "redirect_policy": "NEVER_FOLLOW",
            "request_sample_policy": "ONE_FROZEN_BODY_REUSED_BYTE_FOR_BYTE",
            "warmup_excluded_from_measurement": True,
            "preparation_excluded_from_latency_and_throughput": True,
            "non_loopback_opt_in": config.allow_non_loopback,
        },
        "limitations": {
            "local_single_run_only": True,
            "production_sla_measured": False,
            "cost_measured": False,
            "agentteams_orchestration_measured": False,
            "mcp_protocol_measured": False,
            "llm_measured": False,
            "legal_accuracy_measured": False,
            "external_network_called_by_default": False,
            "preparation_side_effects": "BOUNDED_IN_MEMORY_SYNTHETIC_REGISTRY_ONLY",
            "higress_http_forwarding_measured": any(
                target.kind == "HIGRESS_HTTP_FORWARD" for target in config.targets
            ),
            "latency_includes_client_and_connection_setup": True,
            "results_are_not_a_production_capacity_claim": True,
        },
        "environment": _machine_environment(),
        "resource_usage": {
            "scope": config.resource_scope,
            "process_cpu_seconds_delta": round(
                after.process_cpu_seconds - before.process_cpu_seconds, 6
            ),
            "process_cpu_percent_of_wall_one_core_equals_100": round(
                (after.process_cpu_seconds - before.process_cpu_seconds) / total_wall_seconds * 100,
                6,
            ),
            "process_max_rss_bytes_before": before.process_max_rss_bytes,
            "process_max_rss_bytes_after": after.process_max_rss_bytes,
            "system_available_memory_bytes_before": before.system_available_memory_bytes,
            "system_available_memory_bytes_after": after.system_available_memory_bytes,
            "total_benchmark_wall_seconds": round(total_wall_seconds, 6),
            "interpretation": (
                "IN_PROCESS_CLIENT_AND_SERVICE"
                if config.resource_scope == "CLIENT_AND_SERVICE"
                else "CLIENT_PROCESS_ONLY_EXTERNAL_SERVICE_EXCLUDED"
            ),
            "population": "PREPARATION_PLUS_WARMUP_PLUS_MEASURED_PHASES",
        },
        "targets": target_reports,
        "summary": {
            "attempted_request_count": attempted,
            "functional_success_count": functional_success,
            "functional_failure_count": attempted - functional_success,
            "all_measured_requests_functionally_successful": attempted == functional_success,
            "all_target_preparations_successful": all_preparations_successful,
            "benchmark_run_valid": (
                attempted == functional_success and all_preparations_successful
            ),
        },
        "provenance": _provenance(tuple(provenance_samples)),
        "report_hash_semantics": {
            "algorithm": "SHA-256",
            "kind": "UNSIGNED_CONTENT_DIGEST",
            "digital_signature_present": False,
            "authenticity_verified": False,
        },
    }
    report["report_hash"] = compute_report_hash(report)
    return report


def render_report(report: Mapping[str, Any]) -> str:
    """Render stable UTF-8 JSON; timings still make separate runs non-identical."""
    return json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
