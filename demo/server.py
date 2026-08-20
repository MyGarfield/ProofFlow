"""Local-only HTTP console for the frozen ProofFlow semifinal demonstration.

The server deliberately exposes a closed action set over a pinned public synthetic
fixture.  It never accepts file paths, uploads, roles, decisions, or network
destinations from a request.  Runtime and benchmark artifacts live only in
``TemporaryDirectory`` instances owned by this process.
"""

from __future__ import annotations

import argparse
import hmac
import json
import secrets
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Final, cast
from urllib.parse import urlsplit

from benchmarks.suite import run_suite
from proofflow.canonical import sha256_digest, sha256_file
from proofflow.models import ApprovalDecision
from proofflow.reference_runtime import (
    ReferenceRunBlocked,
    ReferenceRunError,
    approve_reference_run,
    package_reference_run,
    prepare_reference_run,
    verify_reference_run,
)

ROOT: Final = Path(__file__).resolve().parents[1]
ASSET_ROOT: Final = Path(__file__).resolve().parent
FIXTURE_ROOT: Final = ROOT / "examples/cases/happy_path"
MANIFEST_PATH: Final = FIXTURE_ROOT / "manifest.json"
RULE_CATALOG_PATH: Final = ROOT / "data/rules/cn_labor_contract_law.catalog.json"
FIXED_NOW: Final = datetime(2026, 8, 20, 4, 0, tzinfo=UTC)

FIXTURE_FILE_NAMES: Final = (
    "contract.json",
    "manifest.json",
    "payroll.json",
    "termination_notice.json",
)
PINNED_FIXTURE_BUNDLE_DIGEST: Final = (
    "sha256:60ce3111c813c8869e4be65ae5f4fcd9712e388769b35645393dc270184c7f9d"
)
PINNED_RULE_CATALOG_DIGEST: Final = (
    "sha256:27686c904451870dd5953ec6e47c155a395b2f279995e50f68aea984e6bf91de"
)

BIND_HOST: Final = "127.0.0.1"
DEFAULT_PORT: Final = 8765
MAX_BODY_BYTES: Final = 4096
MAX_REASON_CHARS: Final = 300
MIN_REASON_CHARS: Final = 12
APPROVER_ID: Final = "semifinal-demo-reviewer"
APPROVER_ROLE: Final = "legal-reviewer"

STATIC_ROUTES: Final = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
ACTION_ROUTES: Final = {
    "/api/approve": "approve",
    "/api/benchmark": "benchmark",
    "/api/package": "package",
    "/api/prepare": "prepare",
    "/api/reset": "reset",
    "/api/verify": "verify",
}
NO_PAYLOAD_ACTIONS: Final = frozenset({"benchmark", "package", "prepare", "reset", "verify"})


class DemoConfigurationError(RuntimeError):
    """Raised when the frozen input bundle no longer matches its declared pins."""


class ApiProblem(RuntimeError):
    """A safe error that can be serialized without leaking local implementation details."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        state: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.state = state


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_bundle_digest() -> str:
    entries = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(path),
        }
        for path in (FIXTURE_ROOT / name for name in FIXTURE_FILE_NAMES)
    ]
    return sha256_digest(entries)


def verify_pinned_inputs() -> None:
    """Fail closed before a run if either public input bundle changed."""
    try:
        fixture_digest = _fixture_bundle_digest()
        rule_digest = sha256_file(RULE_CATALOG_PATH)
        manifest = _load_json(MANIFEST_PATH)
    except (OSError, json.JSONDecodeError) as exc:
        raise DemoConfigurationError("the pinned public synthetic inputs are unavailable") from exc
    if fixture_digest != PINNED_FIXTURE_BUNDLE_DIGEST:
        raise DemoConfigurationError("the happy_path fixture bundle does not match its pin")
    if rule_digest != PINNED_RULE_CATALOG_DIGEST:
        raise DemoConfigurationError("the rule catalog does not match its pin")
    if manifest.get("fixture_status") != "SYNTHETIC":
        raise DemoConfigurationError("the pinned fixture is not classified SYNTHETIC")


def _read_optional_json(path: Path, default: Any) -> Any:
    try:
        return _load_json(path)
    except (OSError, json.JSONDecodeError):
        return default


class DemoApplication:
    """Stateful, process-local coordinator behind the HTTP adapter."""

    def __init__(self) -> None:
        verify_pinned_inputs()
        self.request_token = secrets.token_urlsafe(32)
        # GET snapshots and state-changing actions share this re-entrant lock.
        # Re-entrancy lets dispatch include a snapshot while still keeping reset
        # and readers in one atomic state boundary.
        self.execution_lock = threading.RLock()
        self._workspace: tempfile.TemporaryDirectory[str] | None = None
        self._run_dir: Path | None = None
        self._gate_probe = "NOT_ATTEMPTED"
        self._verification: dict[str, Any] | None = None
        self._benchmark: dict[str, Any] | None = None
        self._last_benchmark_workspace: Path | None = None
        self._open_workspace()

    def __enter__(self) -> DemoApplication:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @property
    def workspace_path(self) -> Path:
        if self._workspace is None:
            raise RuntimeError("demo application is closed")
        return Path(self._workspace.name)

    @property
    def run_dir(self) -> Path:
        if self._run_dir is None:
            raise RuntimeError("demo application is closed")
        return self._run_dir

    @property
    def last_benchmark_workspace(self) -> Path | None:
        """The already-cleaned path is retained only for cleanup contract tests."""
        return self._last_benchmark_workspace

    def _open_workspace(self) -> None:
        self._workspace = tempfile.TemporaryDirectory(prefix="proofflow-demo-")
        self._run_dir = Path(self._workspace.name) / "reference-run"

    def close(self) -> None:
        with self.execution_lock:
            if self._workspace is not None:
                self._workspace.cleanup()
                self._workspace = None
                self._run_dir = None

    def _reset(self) -> dict[str, Any]:
        previous_workspace = self.workspace_path
        if self._workspace is not None:
            self._workspace.cleanup()
        self._workspace = None
        self._run_dir = None
        self._gate_probe = "NOT_ATTEMPTED"
        self._verification = None
        self._benchmark = None
        self._last_benchmark_workspace = None
        self._open_workspace()
        return {
            "previous_workspace_removed": not previous_workspace.exists(),
            "stage": "NOT_PREPARED",
        }

    def _require_payload(self, action: str, payload: dict[str, Any]) -> None:
        if action in NO_PAYLOAD_ACTIONS and payload:
            raise ApiProblem(
                HTTPStatus.BAD_REQUEST,
                "UNEXPECTED_FIELDS",
                f"{action} accepts an empty JSON object only.",
            )
        if action == "approve" and set(payload) != {"reason"}:
            raise ApiProblem(
                HTTPStatus.BAD_REQUEST,
                "INVALID_APPROVAL_FIELDS",
                "Approval accepts only one field: reason.",
            )

    def _prepare(self) -> dict[str, Any]:
        verify_pinned_inputs()
        if self.run_dir.exists():
            raise ApiProblem(
                HTTPStatus.CONFLICT,
                "RUN_ALREADY_PREPARED",
                "Reset the local demo before preparing another run.",
            )
        state = prepare_reference_run(
            manifest_path=MANIFEST_PATH,
            rule_catalog_path=RULE_CATALOG_PATH,
            run_dir=self.run_dir,
            now=FIXED_NOW,
        )
        return {
            "approval_request_id": state.approval_request_id,
            "approval_subject_hash": state.approval_subject_hash,
            "stage": state.stage.value,
            "stopped_at_human_gate": state.stage.value == "AWAITING_APPROVAL",
        }

    def _approve(self, payload: dict[str, Any]) -> dict[str, Any]:
        reason = payload.get("reason")
        if not isinstance(reason, str):
            raise ApiProblem(
                HTTPStatus.BAD_REQUEST,
                "INVALID_REASON",
                "Approval reason must be a string.",
            )
        reason = reason.strip()
        if not MIN_REASON_CHARS <= len(reason) <= MAX_REASON_CHARS:
            raise ApiProblem(
                HTTPStatus.BAD_REQUEST,
                "INVALID_REASON_LENGTH",
                f"Approval reason must contain {MIN_REASON_CHARS}-{MAX_REASON_CHARS} characters.",
            )
        if any(ord(character) < 32 for character in reason):
            raise ApiProblem(
                HTTPStatus.BAD_REQUEST,
                "INVALID_REASON_CONTROL_CHARACTER",
                "Approval reason must be a single printable line.",
            )
        if not self.run_dir.exists():
            raise ApiProblem(
                HTTPStatus.CONFLICT,
                "RUN_NOT_PREPARED",
                "Prepare the frozen synthetic run before approval.",
            )
        record = approve_reference_run(
            run_dir=self.run_dir,
            approver_id=APPROVER_ID,
            approver_role=APPROVER_ROLE,
            decision=ApprovalDecision.APPROVE,
            reason=reason,
            now=FIXED_NOW + timedelta(minutes=1),
        )
        return {
            "approval_method": record.approval_method,
            "approved_artifact_hash": record.approved_artifact_hash,
            "decision": record.decision.value,
            "reason_recorded": record.reason == reason,
            "role": record.approver_role,
        }

    def _package(self) -> dict[str, Any]:
        if not self.run_dir.exists():
            raise ApiProblem(
                HTTPStatus.CONFLICT,
                "RUN_NOT_PREPARED",
                "Prepare the frozen synthetic run before packaging.",
            )
        state = _read_optional_json(self.run_dir / "run-state.json", {})
        if state.get("stage") != "APPROVED":
            if state.get("stage") == "AWAITING_APPROVAL":
                self._gate_probe = "BLOCKED_AS_EXPECTED"
                raise ApiProblem(
                    HTTPStatus.CONFLICT,
                    "HUMAN_GATE_REQUIRED",
                    "Packaging is blocked until the fixed legal-reviewer approval is recorded.",
                )
            raise ApiProblem(
                HTTPStatus.CONFLICT,
                "INVALID_STAGE_FOR_PACKAGE",
                "Packaging is allowed exactly once from the APPROVED stage.",
            )
        manifest = package_reference_run(
            run_dir=self.run_dir,
            now=FIXED_NOW + timedelta(minutes=2),
        )
        return {
            "content_hash": manifest.meta.content_hash,
            "file_count": len(manifest.files),
            "package_id": manifest.meta.artifact_id,
            "stage": "PACKAGED",
        }

    def _verify(self) -> dict[str, Any]:
        if not self.run_dir.exists():
            raise ApiProblem(
                HTTPStatus.CONFLICT,
                "RUN_NOT_PREPARED",
                "Prepare and package the frozen synthetic run before verification.",
            )
        state = _read_optional_json(self.run_dir / "run-state.json", {})
        if state.get("stage") != "PACKAGED":
            raise ApiProblem(
                HTTPStatus.CONFLICT,
                "PACKAGE_NOT_READY",
                "Independent verification is exposed after packaging.",
            )
        report = verify_reference_run(self.run_dir)
        self._verification = {
            "checked_artifacts": report.checked_artifacts,
            "checked_package_files": report.checked_package_files,
            "errors": list(report.errors),
            "valid": report.valid,
        }
        if not report.valid:
            raise ApiProblem(
                HTTPStatus.CONFLICT,
                "VERIFICATION_FAILED",
                f"Independent verification found {len(report.errors)} integrity error(s).",
            )
        return dict(self._verification)

    def _run_benchmark(self) -> dict[str, Any]:
        verify_pinned_inputs()
        with tempfile.TemporaryDirectory(prefix="proofflow-benchmark-") as directory:
            workspace = Path(directory) / "contract-suite"
            self._last_benchmark_workspace = workspace
            if workspace == self.run_dir or self.run_dir in workspace.parents:
                raise RuntimeError("benchmark workspace must be independent")
            report = run_suite(workspace)
        if self._last_benchmark_workspace.exists():
            raise RuntimeError("benchmark temporary workspace was not cleaned")

        results = [
            {
                "fault": item.get("fault"),
                "id": item["id"],
                "passed": item["passed"],
                "title": item.get("title"),
            }
            for item in report["results"]
        ]
        self._benchmark = {
            "all_contracts_satisfied": report["summary"]["all_contracts_satisfied"],
            "contract_pass_fraction": report["summary"]["contract_pass_fraction"],
            "excluded_coverage": report["excluded_coverage"],
            "legal_accuracy_measured": report["legal_accuracy_measured"],
            "performance_measured": report["performance_measured"],
            "report_hash": report["report_hash"],
            "results": results,
            "suite_id": report["suite_id"],
            "suite_version": report["suite_version"],
        }
        return dict(self._benchmark)

    def dispatch(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute one allowlisted action under a process-wide serial lock."""
        with self.execution_lock:
            try:
                self._require_payload(action, payload)
                if action == "prepare":
                    result = self._prepare()
                elif action == "approve":
                    result = self._approve(payload)
                elif action == "package":
                    result = self._package()
                elif action == "verify":
                    result = self._verify()
                elif action == "benchmark":
                    result = self._run_benchmark()
                elif action == "reset":
                    result = self._reset()
                else:
                    raise ApiProblem(
                        HTTPStatus.NOT_FOUND,
                        "ACTION_NOT_ALLOWED",
                        "The requested action is not in the demo allowlist.",
                    )
            except ApiProblem as exc:
                exc.state = self._snapshot_unlocked()
                raise
            except ReferenceRunBlocked as exc:
                issue_codes = sorted({issue.code for issue in exc.result.issues})
                code = issue_codes[0] if issue_codes else "REFERENCE_RUN_BLOCKED"
                raise ApiProblem(
                    HTTPStatus.CONFLICT,
                    code,
                    f"The evidence gate blocked {exc.stage}.",
                    state=self._snapshot_unlocked(),
                ) from exc
            except ReferenceRunError as exc:
                raise ApiProblem(
                    HTTPStatus.CONFLICT,
                    "REFERENCE_RUN_CONFLICT",
                    "The requested transition is not valid for the current run state.",
                    state=self._snapshot_unlocked(),
                ) from exc
            except DemoConfigurationError as exc:
                raise ApiProblem(
                    HTTPStatus.PRECONDITION_FAILED,
                    "PINNED_INPUT_MISMATCH",
                    str(exc),
                    state=self._snapshot_unlocked(),
                ) from exc
            return {
                "action": action,
                "ok": True,
                "result": result,
                "state": self._snapshot_unlocked(),
            }

    def snapshot(self) -> dict[str, Any]:
        """Return only public, path-free facts needed by the one-screen console."""
        with self.execution_lock:
            return self._snapshot_unlocked()

    def _snapshot_unlocked(self) -> dict[str, Any]:
        """Build a snapshot while the caller owns ``execution_lock``."""
        stage = "NOT_PREPARED"
        run_id: str | None = None
        trace_id: str | None = None
        subject_hash: str | None = None
        agentteams_integrated = False
        external_side_effects_enabled = False
        evidence_count = 0
        rule_count = 0
        proposal_count = 0
        trace_events: list[dict[str, Any]] = []
        calculation_total: str | None = None
        audit_verdict: str | None = None
        approval_method: str | None = None
        approval_reason: str | None = None
        package_file_count = 0

        state_path = self.run_dir / "run-state.json"
        if state_path.is_file():
            state = _read_optional_json(state_path, {})
            stage = state.get("stage", "UNKNOWN")
            run_id = state.get("run_id")
            trace_id = state.get("trace_id")
            subject_hash = state.get("approval_subject_hash")
            agentteams_integrated = bool(state.get("agentteams_integrated"))
            external_side_effects_enabled = bool(state.get("external_side_effects_enabled"))
            evidence = _read_optional_json(self.run_dir / "artifacts/evidence.json", [])
            rules = _read_optional_json(self.run_dir / "artifacts/rules.json", [])
            proposals = _read_optional_json(self.run_dir / "artifacts/proposals.json", [])
            calculation = _read_optional_json(self.run_dir / "artifacts/calculation.json", {})
            audit = _read_optional_json(self.run_dir / "artifacts/audit-report.json", {})
            approval = _read_optional_json(self.run_dir / "artifacts/approval-record.json", {})
            package = _read_optional_json(self.run_dir / "package/package-manifest.json", {})
            evidence_count = len(evidence) if isinstance(evidence, list) else 0
            rule_count = len(rules) if isinstance(rules, list) else 0
            proposal_count = len(proposals) if isinstance(proposals, list) else 0
            calculation_total = calculation.get("total") if isinstance(calculation, dict) else None
            audit_verdict = audit.get("verdict") if isinstance(audit, dict) else None
            approval_method = (
                approval.get("approval_method") if isinstance(approval, dict) else None
            )
            approval_reason = approval.get("reason") if isinstance(approval, dict) else None
            package_files = package.get("files", []) if isinstance(package, dict) else []
            package_file_count = len(package_files) if isinstance(package_files, list) else 0
            trace_path = self.run_dir / "trace.jsonl"
            if trace_path.is_file():
                for line in trace_path.read_text(encoding="utf-8").splitlines():
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    trace_events.append(
                        {
                            "actor": event.get("actor_identity"),
                            "event": event.get("event_type"),
                            "sequence": event.get("sequence"),
                            "status": event.get("status"),
                        }
                    )

        return {
            "approval": {
                "method": approval_method,
                "reason": approval_reason,
                "required_role": APPROVER_ROLE,
            },
            "artifacts": {
                "audit_verdict": audit_verdict,
                "calculation_total_cny": calculation_total,
                "evidence": evidence_count,
                "package_files": package_file_count,
                "proposals": proposal_count,
                "rules": rule_count,
            },
            "benchmark": self._benchmark,
            "boundaries": {
                "agentteams_integrated": agentteams_integrated,
                "classification": "PUBLIC_SYNTHETIC",
                "external_side_effects_enabled": external_side_effects_enabled,
                "llm_enabled": False,
                "network_bind": BIND_HOST,
                "readyWorkers": 0,
                "workers": "Stopped",
            },
            "gate_probe": self._gate_probe,
            "pins": {
                "fixture_bundle": PINNED_FIXTURE_BUNDLE_DIGEST,
                "rule_catalog": PINNED_RULE_CATALOG_DIGEST,
                "signature_verified": False,
            },
            "run": {
                "run_id": run_id,
                "stage": stage,
                "subject_hash": subject_hash,
                "trace_id": trace_id,
            },
            "trace": trace_events,
            "verification": self._verification,
        }


class DemoHTTPServer(ThreadingHTTPServer):
    """HTTP server carrying the isolated application and exact same-origin value."""

    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        application: DemoApplication,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.application = application
        # This server is created with an IPv4 ``(host, port)`` address.  Typeshed
        # keeps ``server_address`` broad enough for IPv6 and Unix sockets, so
        # narrow the concrete address family at this boundary.
        host, port = cast(tuple[str, int], self.server_address)
        self.expected_origin = f"http://{host}:{port}"
        self.expected_host = f"{host}:{port}"


class DemoRequestHandler(BaseHTTPRequestHandler):
    """Closed-route, same-origin adapter with no CORS opt-in."""

    server: DemoHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        super().log_message(format, *args)

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'none'; font-src 'none'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'",
        )
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _problem(self, problem: ApiProblem) -> None:
        self._send_json(
            problem.status,
            {
                "error": {
                    "code": problem.code,
                    "message": problem.message,
                    "status": problem.status,
                },
                "ok": False,
                "state": problem.state
                if problem.state is not None
                else self.server.application.snapshot(),
            },
        )

    def _path(self) -> str:
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            raise ApiProblem(
                HTTPStatus.BAD_REQUEST,
                "QUERY_NOT_ALLOWED",
                "Demo routes do not accept query strings or fragments.",
            )
        return parsed.path

    def _require_host(self) -> None:
        if self.headers.get("Host") != self.server.expected_host:
            raise ApiProblem(
                HTTPStatus.FORBIDDEN,
                "HOST_REJECTED",
                "The Host header must match the loopback demo listener.",
            )

    def do_GET(self) -> None:
        try:
            self._require_host()
            path = self._path()
            if path == "/api/bootstrap":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "request_token": self.server.application.request_token,
                        "state": self.server.application.snapshot(),
                    },
                )
                return
            asset = STATIC_ROUTES.get(path)
            if asset is None:
                raise ApiProblem(
                    HTTPStatus.NOT_FOUND,
                    "ROUTE_NOT_FOUND",
                    "The requested route is not in the demo allowlist.",
                )
            file_name, content_type = asset
            self._send_bytes(HTTPStatus.OK, (ASSET_ROOT / file_name).read_bytes(), content_type)
        except ApiProblem as problem:
            self._problem(problem)
        except OSError:
            self._problem(
                ApiProblem(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "ASSET_UNAVAILABLE",
                    "A required local demo asset is unavailable.",
                )
            )

    def _read_payload(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding") is not None:
            raise ApiProblem(
                HTTPStatus.BAD_REQUEST,
                "TRANSFER_ENCODING_REJECTED",
                "Chunked request bodies are not accepted.",
            )
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ApiProblem(
                HTTPStatus.LENGTH_REQUIRED,
                "CONTENT_LENGTH_REQUIRED",
                "A bounded Content-Length header is required.",
            )
        try:
            content_length = int(raw_length)
        except ValueError as exc:
            raise ApiProblem(
                HTTPStatus.BAD_REQUEST,
                "INVALID_CONTENT_LENGTH",
                "Content-Length must be a non-negative integer.",
            ) from exc
        if content_length < 0:
            raise ApiProblem(
                HTTPStatus.BAD_REQUEST,
                "INVALID_CONTENT_LENGTH",
                "Content-Length must be a non-negative integer.",
            )
        if content_length > MAX_BODY_BYTES:
            raise ApiProblem(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "BODY_TOO_LARGE",
                f"Request body exceeds the {MAX_BODY_BYTES}-byte limit.",
            )
        content_type = self.headers.get("Content-Type", "").partition(";")[0].strip().lower()
        if content_type != "application/json":
            raise ApiProblem(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "JSON_REQUIRED",
                "Content-Type must be application/json.",
            )
        body = self.rfile.read(content_length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiProblem(
                HTTPStatus.BAD_REQUEST,
                "INVALID_JSON",
                "Request body must be one UTF-8 JSON object.",
            ) from exc
        if not isinstance(payload, dict):
            raise ApiProblem(
                HTTPStatus.BAD_REQUEST,
                "JSON_OBJECT_REQUIRED",
                "Request body must be a JSON object.",
            )
        return payload

    def _require_same_origin_token(self) -> None:
        if self.headers.get("Origin") != self.server.expected_origin:
            raise ApiProblem(
                HTTPStatus.FORBIDDEN,
                "ORIGIN_REJECTED",
                "Mutating requests must originate from this loopback demo.",
            )
        supplied = self.headers.get("X-ProofFlow-Request-Token", "")
        if not hmac.compare_digest(supplied, self.server.application.request_token):
            raise ApiProblem(
                HTTPStatus.FORBIDDEN,
                "REQUEST_TOKEN_REJECTED",
                "The per-process request token is missing or invalid.",
            )

    def do_POST(self) -> None:
        try:
            self._require_host()
            path = self._path()
            action = ACTION_ROUTES.get(path)
            if action is None:
                raise ApiProblem(
                    HTTPStatus.NOT_FOUND,
                    "ACTION_NOT_ALLOWED",
                    "The requested action is not in the demo allowlist.",
                )
            self._require_same_origin_token()
            payload = self._read_payload()
            response = self.server.application.dispatch(action, payload)
            self._send_json(HTTPStatus.OK, response)
        except ApiProblem as problem:
            self._problem(problem)
        except Exception:
            self._problem(
                ApiProblem(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "The local demo action failed closed.",
                )
            )

    def do_HEAD(self) -> None:
        self._problem(
            ApiProblem(
                HTTPStatus.METHOD_NOT_ALLOWED,
                "METHOD_NOT_ALLOWED",
                "HEAD is not exposed by the demo allowlist.",
            )
        )

    def do_OPTIONS(self) -> None:
        self._problem(
            ApiProblem(
                HTTPStatus.METHOD_NOT_ALLOWED,
                "CORS_NOT_ENABLED",
                "Cross-origin access is not enabled.",
            )
        )


def create_server(
    *,
    port: int = DEFAULT_PORT,
    application: DemoApplication | None = None,
) -> DemoHTTPServer:
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    return DemoHTTPServer(
        (BIND_HOST, port),
        DemoRequestHandler,
        application or DemoApplication(),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local-only ProofFlow semifinal demo")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)
    application = DemoApplication()
    server = create_server(port=args.port, application=application)
    try:
        print(f"ProofFlow local demo: {server.expected_origin}", flush=True)
        print("PUBLIC SYNTHETIC · NO LLM · LOCAL ONLY · NO EXTERNAL SIDE EFFECTS", flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        application.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
