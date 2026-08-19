"""Authenticated synthetic REST adapter with a process-local Evidence trust registry."""

from __future__ import annotations

import hmac
import json
import math
import os
import socket
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from hashlib import sha256
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BufferedReader
from pathlib import Path
from time import monotonic
from typing import Any, ClassVar, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ValidationError

from proofflow.canonical import canonicalize
from proofflow.contracts import (
    DeterministicCalculateToolCall,
    EvidenceIngestToolCall,
    RuleCatalog,
    RuleRetrieveToolCall,
)
from proofflow.models import SCHEMA_VERSION, SkillStatus
from proofflow.skills import deterministic_calculate, evidence_ingest, rule_retrieve
from proofflow.trusted_store import (
    DEFAULT_TRUSTED_ARTIFACT_CAPACITY,
    TrustedArtifactStore,
    TrustedArtifactStoreCapacityError,
    TrustedArtifactStoreError,
)

TOKEN_ENV_VAR = "PROOFFLOW_TOOL_API_TOKEN"
DEFAULT_MAX_BODY_BYTES = 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024
DEFAULT_MAX_CONCURRENT_REQUESTS = 32
DEFAULT_READ_TIMEOUT_SECONDS = 5.0
MAX_JSON_NESTING = 64
MAX_CHUNK_LINE_BYTES = 8192
MAX_CHUNK_TRAILER_BYTES = 16 * 1024
HEALTH_PATH = "/health"
EVIDENCE_INGEST_PATH = "/v1/tools/evidence-ingest"
RULE_RETRIEVE_PATH = "/v1/tools/rule-retrieve"
DETERMINISTIC_CALCULATE_PATH = "/v1/tools/deterministic-calculate"

Clock = Callable[[], datetime]
SocketRequest = socket.socket | tuple[bytes, socket.socket]

_OVERLOADED_BODY = b'{"error":{"code":"SERVER_BUSY","message":"request capacity exhausted"}}'
_RESPONSE_TOO_LARGE_BODY = (
    b'{"error":{"code":"RESPONSE_TOO_LARGE","message":"response exceeds configured limit"}}'
)
_REQUEST_TIMEOUT_BODY = (
    b'{"error":{"code":"REQUEST_TIMEOUT","message":"request was not received before the deadline"}}'
)
_HTTP_TOKEN_CHARACTERS = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_HEX_CHARACTERS = frozenset(b"0123456789ABCDEFabcdef")
_FORBIDDEN_TRAILER_FIELDS = frozenset(
    {
        b"authorization",
        b"connection",
        b"content-length",
        b"content-type",
        b"host",
        b"trailer",
        b"transfer-encoding",
    }
)


class ToolServerConfigurationError(RuntimeError):
    """Raised before binding when the service cannot start safely."""


class _RequestReadTimeout(TimeoutError):
    """Raised when the aggregate request-line/header/body deadline expires."""


class _BodyUnexpectedEOF(Exception):
    """Raised when the peer closes before a framed body is complete."""


class _BodyLineTooLong(Exception):
    """Raised before an attacker-controlled framing line can grow unbounded."""


class _InvalidJSONValue(ValueError):
    """Raised for JSON extensions or duplicate keys that this API forbids."""


class _BodyProtocolError(Exception):
    """Internal bounded error mapped to a public HTTP transport response."""

    def __init__(self, status: HTTPStatus, code: str, message: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message


class _DeadlineRequestReader:
    """Buffered input with one deadline across request line, headers, and body."""

    def __init__(
        self,
        stream: BufferedReader,
        connection: socket.socket,
        timeout_seconds: float,
    ) -> None:
        self._stream = stream
        self._connection = connection
        self._deadline = monotonic() + timeout_seconds
        self._buffer = bytearray()

    @property
    def closed(self) -> bool:
        return self._stream.closed

    def close(self) -> None:
        self._stream.close()

    def readline(self, size: int = -1) -> bytes:
        """Implement BinaryIO.readline semantics for the stdlib HTTP parser."""
        if size == 0:
            return b""
        limit = None if size < 0 else size
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                end = newline + 1
                if limit is not None:
                    end = min(end, limit)
                return self._take(end)
            if limit is not None and len(self._buffer) >= limit:
                return self._take(limit)
            max_bytes = 4096 if limit is None else min(4096, limit - len(self._buffer))
            try:
                self._buffer.extend(self._read_from_stream(max_bytes))
            except _BodyUnexpectedEOF:
                if not self._buffer:
                    return b""
                end = len(self._buffer) if limit is None else min(len(self._buffer), limit)
                return self._take(end)

    def read_exact(self, size: int) -> bytes:
        while len(self._buffer) < size:
            self._buffer.extend(self._read_from_stream(min(64 * 1024, size - len(self._buffer))))
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result

    def read_line(self, limit: int) -> bytes:
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                end = newline + 1
                if end > limit:
                    raise _BodyLineTooLong
                result = bytes(self._buffer[:end])
                del self._buffer[:end]
                return result
            if len(self._buffer) >= limit:
                raise _BodyLineTooLong
            self._buffer.extend(self._read_from_stream(min(4096, limit - len(self._buffer))))

    def _take(self, size: int) -> bytes:
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result

    def _read_from_stream(self, max_bytes: int) -> bytes:
        remaining = self._deadline - monotonic()
        if remaining <= 0:
            raise _RequestReadTimeout
        try:
            self._connection.settimeout(remaining)
            chunk = self._stream.read1(max_bytes)
        except TimeoutError as exc:
            raise _RequestReadTimeout from exc
        except OSError as exc:
            raise _BodyUnexpectedEOF from exc
        if not chunk:
            raise _BodyUnexpectedEOF
        return chunk


def utc_now() -> datetime:
    return datetime.now(UTC)


def api_token_from_environment(
    environ: Mapping[str, str] | None = None,
) -> str:
    """Load the backend token without accepting it on the command line."""
    source = os.environ if environ is None else environ
    token = source.get(TOKEN_ENV_VAR, "")
    if not token or token != token.strip() or any(character.isspace() for character in token):
        raise ToolServerConfigurationError(
            f"{TOKEN_ENV_VAR} must contain one non-empty Bearer token without whitespace"
        )
    return token


def load_rule_catalog(path: Path, expected_sha256: str) -> RuleCatalog:
    if not _is_sha256_digest(expected_sha256):
        raise ToolServerConfigurationError(
            "the expected rule catalog digest must be lowercase sha256:<64-hex>"
        )
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ToolServerConfigurationError(f"cannot read rule catalog: {path}") from exc
    actual_sha256 = f"sha256:{sha256(payload).hexdigest()}"
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise ToolServerConfigurationError("rule catalog does not match its configured digest pin")
    try:
        return RuleCatalog.model_validate_json(payload)
    except ValidationError as exc:
        raise ToolServerConfigurationError(f"invalid rule catalog: {path}") from exc


class ProofFlowToolHTTPServer(ThreadingHTTPServer):
    """HTTP state with a bounded, non-persistent synthetic Evidence registry."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        catalog: RuleCatalog,
        api_token: str,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
        trusted_artifact_capacity: int = DEFAULT_TRUSTED_ARTIFACT_CAPACITY,
        read_timeout_seconds: float = DEFAULT_READ_TIMEOUT_SECONDS,
        clock: Clock = utc_now,
    ) -> None:
        if not api_token:
            raise ToolServerConfigurationError("the backend Bearer token must not be empty")
        if max_body_bytes < 1:
            raise ToolServerConfigurationError("max_body_bytes must be positive")
        if max_response_bytes < len(_RESPONSE_TOO_LARGE_BODY):
            raise ToolServerConfigurationError("max_response_bytes is too small for errors")
        if max_concurrent_requests < 1:
            raise ToolServerConfigurationError("max_concurrent_requests must be positive")
        if trusted_artifact_capacity < 1:
            raise ToolServerConfigurationError("trusted_artifact_capacity must be positive")
        if not math.isfinite(read_timeout_seconds) or read_timeout_seconds <= 0:
            raise ToolServerConfigurationError("read_timeout_seconds must be finite and positive")
        self.catalog = catalog
        self.api_token = api_token
        self.max_body_bytes = max_body_bytes
        self.max_response_bytes = max_response_bytes
        self.max_concurrent_requests = max_concurrent_requests
        self.trusted_artifacts = TrustedArtifactStore(trusted_artifact_capacity)
        self.read_timeout_seconds = read_timeout_seconds
        self.clock = clock
        self._request_slots = threading.BoundedSemaphore(max_concurrent_requests)
        super().__init__(server_address, ProofFlowToolRequestHandler)

    def process_request(self, request: SocketRequest, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            connection = request[1] if isinstance(request, tuple) else request
            with suppress(OSError):
                connection.sendall(
                    _raw_http_response(HTTPStatus.SERVICE_UNAVAILABLE, _OVERLOADED_BODY)
                )
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request: SocketRequest, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class ProofFlowToolRequestHandler(BaseHTTPRequestHandler):
    """Strict JSON transport with deliberately silent request logging."""

    server_version = "ProofFlowToolService/0.1"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    protected_paths: ClassVar[frozenset[str]] = frozenset(
        {EVIDENCE_INGEST_PATH, RULE_RETRIEVE_PATH, DETERMINISTIC_CALCULATE_PATH}
    )

    @property
    def tool_server(self) -> ProofFlowToolHTTPServer:
        return cast(ProofFlowToolHTTPServer, self.server)

    def setup(self) -> None:
        super().setup()
        self._request_reader = _DeadlineRequestReader(
            cast(BufferedReader, self.rfile),
            self.connection,
            self.tool_server.read_timeout_seconds,
        )
        self.rfile = cast(Any, self._request_reader)

    def handle_one_request(self) -> None:
        """Apply one absolute deadline to stdlib request parsing and body reads."""
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                return
            method = getattr(self, "do_" + self.command, None)
            if method is None:
                self.send_error(
                    HTTPStatus.NOT_IMPLEMENTED,
                    f"Unsupported method ({self.command!r})",
                )
                return
            method()
            self.wfile.flush()
        except _RequestReadTimeout:
            with suppress(OSError):
                self.connection.settimeout(1.0)
                self.connection.sendall(
                    _raw_http_response(HTTPStatus.REQUEST_TIMEOUT, _REQUEST_TIMEOUT_BODY)
                )
            self.close_connection = True
        except TimeoutError:
            self.close_connection = True

    def log_message(self, format: str, *args: Any) -> None:
        """Do not log request paths, headers, bodies, tokens, or case identifiers."""
        del format, args

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path != HEALTH_PATH:
            self._send_error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "endpoint not found")
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "service": "proofflow-tool-service",
                "status": "ok",
                "schema_version": SCHEMA_VERSION,
                "catalog_version": self.tool_server.catalog.catalog_version,
                "side_effects": "IN_MEMORY_SYNTHETIC_ARTIFACT_REGISTRY",
            },
        )

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in self.protected_paths:
            self._send_error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "endpoint not found")
            return
        if len(self.headers.get_all("Authorization", [])) > 1:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "AMBIGUOUS_AUTHORIZATION",
                "exactly one Authorization header is allowed",
            )
            return
        if not self._authorized():
            self._send_error(
                HTTPStatus.UNAUTHORIZED,
                "UNAUTHORIZED",
                "valid Bearer authorization is required",
                extra_headers={"WWW-Authenticate": "Bearer"},
            )
            return
        body = self._read_json_body()
        if body is None:
            return
        try:
            result: BaseModel
            if path == EVIDENCE_INGEST_PATH:
                ingest_call = EvidenceIngestToolCall.model_validate_json(body)
                result = evidence_ingest(
                    ingest_call.context,
                    ingest_call.arguments.to_skill_request(),
                    now=self.tool_server.clock(),
                )
                if result.status == SkillStatus.SUCCESS and result.value is not None:
                    try:
                        self.tool_server.trusted_artifacts.register_all(
                            result.value.evidence_objects
                        )
                    except TrustedArtifactStoreCapacityError:
                        self._send_error(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            "TRUST_STORE_CAPACITY_EXHAUSTED",
                            "trusted Evidence registry capacity is exhausted",
                        )
                        return
                    except TrustedArtifactStoreError:
                        self._send_error(
                            HTTPStatus.INTERNAL_SERVER_ERROR,
                            "TRUST_STORE_REGISTRATION_FAILED",
                            "trusted Evidence could not be registered",
                        )
                        return
            elif path == RULE_RETRIEVE_PATH:
                rule_call = RuleRetrieveToolCall.model_validate_json(body)
                result = rule_retrieve(
                    rule_call.context,
                    rule_call.arguments,
                    catalog=self.tool_server.catalog,
                    now=self.tool_server.clock(),
                )
            else:
                calculate_call = DeterministicCalculateToolCall.model_validate_json(body)
                result = deterministic_calculate(
                    calculate_call.context,
                    calculate_call.arguments,
                    catalog=self.tool_server.catalog,
                    trusted_artifacts=self.tool_server.trusted_artifacts,
                    now=self.tool_server.clock(),
                )
        except ValidationError as exc:
            details = [
                {
                    "location": [str(part) for part in error["loc"]],
                    "type": error["type"],
                }
                for error in exc.errors(
                    include_url=False,
                    include_context=False,
                    include_input=False,
                )
            ]
            self._send_error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "SCHEMA_VALIDATION_FAILED",
                "request does not match the tool schema",
                details=details,
            )
            return
        except Exception:
            self._send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "request could not be completed",
            )
            return
        try:
            self._send_model(HTTPStatus.OK, result)
        except (TypeError, ValueError):
            self._send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "RESPONSE_SERIALIZATION_FAILED",
                "request could not be completed",
            )

    def _authorized(self) -> bool:
        authorization = self.headers.get("Authorization", "")
        scheme, separator, provided = authorization.partition(" ")
        return bool(
            separator
            and scheme.casefold() == "bearer"
            and provided
            and hmac.compare_digest(provided, self.tool_server.api_token)
        )

    def _read_json_body(self) -> bytes | None:
        raw_transfer_encodings = self.headers.get_all("Transfer-Encoding", [])
        raw_lengths = self.headers.get_all("Content-Length", [])
        if raw_transfer_encodings and raw_lengths:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "AMBIGUOUS_REQUEST_FRAMING",
                "Content-Length and Transfer-Encoding cannot be combined",
            )
            return None
        chunked = bool(raw_transfer_encodings)
        if len(raw_transfer_encodings) > 1:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "AMBIGUOUS_TRANSFER_ENCODING",
                "exactly one Transfer-Encoding is allowed",
            )
            return None
        transfer_encoding = _strict_http_ows_value(raw_transfer_encodings[0]) if chunked else None
        if chunked and transfer_encoding is None:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "INVALID_TRANSFER_ENCODING",
                "Transfer-Encoding contains invalid whitespace or control bytes",
            )
            return None
        if chunked and transfer_encoding is not None and "," in transfer_encoding:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "AMBIGUOUS_TRANSFER_ENCODING",
                "exactly one Transfer-Encoding is allowed",
            )
            return None
        if chunked and transfer_encoding is not None and transfer_encoding.casefold() != "chunked":
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "UNSUPPORTED_TRANSFER_ENCODING",
                "only Transfer-Encoding: chunked is supported",
            )
            return None
        raw_content_types = self.headers.get_all("Content-Type", [])
        if len(raw_content_types) > 1 or (raw_content_types and "," in raw_content_types[0]):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "AMBIGUOUS_CONTENT_TYPE",
                "exactly one Content-Type is allowed",
            )
            return None
        media_type = self.headers.get_content_type().casefold()
        if media_type != "application/json":
            self._send_error(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type must be application/json",
            )
            return None
        if not chunked and not raw_lengths:
            self._send_error(
                HTTPStatus.LENGTH_REQUIRED,
                "LENGTH_REQUIRED",
                "Content-Length or Transfer-Encoding: chunked is required",
            )
            return None
        if not chunked and (len(raw_lengths) != 1 or "," in raw_lengths[0]):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "AMBIGUOUS_CONTENT_LENGTH",
                "exactly one Content-Length is required",
            )
            return None
        raw_length = "" if chunked else _strict_http_ows_value(raw_lengths[0])
        if not chunked and (
            raw_length is None or not raw_length.isascii() or not raw_length.isdigit()
        ):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "INVALID_CONTENT_LENGTH",
                "Content-Length must be one non-negative decimal integer",
            )
            return None
        normalized_length = "0" if chunked else cast(str, raw_length).lstrip("0") or "0"
        max_body_length = str(self.tool_server.max_body_bytes)
        content_length_exceeds_limit = not chunked and (
            len(normalized_length) > len(max_body_length)
            or (
                len(normalized_length) == len(max_body_length)
                and normalized_length > max_body_length
            )
        )
        if content_length_exceeds_limit:
            self._send_error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "REQUEST_TOO_LARGE",
                "request body exceeds the configured limit",
            )
            return None
        content_length = 0 if chunked else int(normalized_length)
        reader = self._request_reader
        try:
            body = self._read_chunked_body(reader) if chunked else reader.read_exact(content_length)
        except _RequestReadTimeout:
            self._send_error(
                HTTPStatus.REQUEST_TIMEOUT,
                "REQUEST_TIMEOUT",
                "request body was not received before the read deadline",
            )
            return None
        except _BodyUnexpectedEOF:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "INCOMPLETE_CHUNKED_BODY" if chunked else "INCOMPLETE_REQUEST_BODY",
                "request body ended before its framing was complete",
            )
            return None
        except _BodyProtocolError as exc:
            self._send_error(exc.status, exc.code, exc.message)
            return None
        if _json_nesting_exceeds(body, MAX_JSON_NESTING):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "JSON_NESTING_TOO_DEEP",
                "request JSON exceeds the nesting limit",
            )
            return None
        try:
            json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (ValueError, RecursionError):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "INVALID_JSON",
                "request body must be valid UTF-8 JSON",
            )
            return None
        return body

    def _read_chunked_body(self, reader: _DeadlineRequestReader) -> bytes:
        body = bytearray()
        while True:
            try:
                size_line = reader.read_line(MAX_CHUNK_LINE_BYTES)
            except _BodyLineTooLong as exc:
                raise _BodyProtocolError(
                    HTTPStatus.BAD_REQUEST,
                    "INVALID_CHUNKED_BODY",
                    "chunk framing is malformed",
                ) from exc
            chunk_size = _parse_chunk_size(size_line)
            if chunk_size is None:
                raise _BodyProtocolError(
                    HTTPStatus.BAD_REQUEST,
                    "INVALID_CHUNKED_BODY",
                    "chunk framing is malformed",
                )
            if chunk_size == 0:
                break
            if chunk_size > self.tool_server.max_body_bytes - len(body):
                raise _BodyProtocolError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "REQUEST_TOO_LARGE",
                    "request body exceeds the configured limit",
                )
            body.extend(reader.read_exact(chunk_size))
            if reader.read_exact(2) != b"\r\n":
                raise _BodyProtocolError(
                    HTTPStatus.BAD_REQUEST,
                    "INVALID_CHUNKED_BODY",
                    "chunk framing is malformed",
                )

        trailer_bytes = 0
        while True:
            remaining = MAX_CHUNK_TRAILER_BYTES - trailer_bytes
            if remaining <= 0:
                raise _BodyProtocolError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "CHUNKED_TRAILERS_TOO_LARGE",
                    "chunk trailers exceed the configured limit",
                )
            try:
                trailer_line = reader.read_line(remaining)
            except _BodyLineTooLong as exc:
                raise _BodyProtocolError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "CHUNKED_TRAILERS_TOO_LARGE",
                    "chunk trailers exceed the configured limit",
                ) from exc
            trailer_bytes += len(trailer_line)
            if trailer_line == b"\r\n":
                return bytes(body)
            if not _valid_trailer_line(trailer_line):
                raise _BodyProtocolError(
                    HTTPStatus.BAD_REQUEST,
                    "INVALID_CHUNKED_BODY",
                    "chunk framing is malformed",
                )

    def _send_model(self, status: HTTPStatus, model: BaseModel) -> None:
        self._send_json(status, canonicalize(model))

    def _send_error(
        self,
        status: HTTPStatus,
        code: str,
        message: str,
        *,
        details: list[dict[str, Any]] | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if details:
            error["details"] = details
        self._send_json(status, {"error": error}, extra_headers=extra_headers)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: Any,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if len(body) > self.tool_server.max_response_bytes:
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            body = _RESPONSE_TOO_LARGE_BODY
            extra_headers = None
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


def serve_tool_service(
    *,
    host: str,
    port: int,
    catalog_path: Path,
    catalog_sha256: str,
    api_token: str,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    trusted_artifact_capacity: int = DEFAULT_TRUSTED_ARTIFACT_CAPACITY,
    read_timeout_seconds: float = DEFAULT_READ_TIMEOUT_SECONDS,
) -> None:
    """Bind and serve until interrupted; startup state contains no case data."""
    if not 0 <= port <= 65535:
        raise ToolServerConfigurationError("port must be between 0 and 65535")
    catalog = load_rule_catalog(catalog_path, catalog_sha256)
    try:
        with ProofFlowToolHTTPServer(
            (host, port),
            catalog=catalog,
            api_token=api_token,
            max_body_bytes=max_body_bytes,
            max_response_bytes=max_response_bytes,
            max_concurrent_requests=max_concurrent_requests,
            trusted_artifact_capacity=trusted_artifact_capacity,
            read_timeout_seconds=read_timeout_seconds,
        ) as server:
            server.serve_forever()
    except OSError as exc:
        raise ToolServerConfigurationError("cannot bind the tool service") from exc


def _json_nesting_exceeds(payload: bytes, limit: int) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for character in payload:
        if in_string:
            if escaped:
                escaped = False
            elif character == ord("\\"):
                escaped = True
            elif character == ord('"'):
                in_string = False
            continue
        if character == ord('"'):
            in_string = True
        elif character in (ord("["), ord("{")):
            depth += 1
            if depth > limit:
                return True
        elif character in (ord("]"), ord("}")):
            depth = max(0, depth - 1)
    return False


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidJSONValue("duplicate object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise _InvalidJSONValue(f"non-standard JSON constant: {value}")


def _is_sha256_digest(value: str) -> bool:
    prefix = "sha256:"
    digest = value.removeprefix(prefix)
    return (
        value.startswith(prefix)
        and len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest)
    )


def _strict_http_ows_value(value: str) -> str | None:
    """Strip only RFC OWS (SP/HTAB) and reject every other CTL/obs-text byte."""
    if any(
        ord(character) > 0x7E
        or ord(character) == 0x7F
        or (ord(character) < 0x20 and character != "\t")
        for character in value
    ):
        return None
    return value.strip(" \t")


def _parse_chunk_size(line: bytes) -> int | None:
    if not line.endswith(b"\r\n"):
        return None
    raw = line[:-2]
    extension_start = raw.find(b";")
    if extension_start < 0:
        size_token = raw
        extensions = b""
    else:
        size_token = raw[:extension_start]
        extensions = raw[extension_start:]
    if not size_token or any(character not in _HEX_CHARACTERS for character in size_token):
        return None
    if extensions and not _valid_chunk_extensions(extensions):
        return None
    return int(size_token, 16)


def _valid_chunk_extensions(extensions: bytes) -> bool:
    index = 0
    while index < len(extensions):
        index = _skip_optional_whitespace(extensions, index)
        if index >= len(extensions) or extensions[index] != ord(";"):
            return False
        index = _skip_optional_whitespace(extensions, index + 1)
        name_end = _consume_token(extensions, index)
        if name_end == index:
            return False
        index = _skip_optional_whitespace(extensions, name_end)
        if index < len(extensions) and extensions[index] == ord("="):
            index = _skip_optional_whitespace(extensions, index + 1)
            if index >= len(extensions):
                return False
            if extensions[index] == ord('"'):
                index = _consume_quoted_string(extensions, index)
                if index < 0:
                    return False
            else:
                value_end = _consume_token(extensions, index)
                if value_end == index:
                    return False
                index = value_end
        index = _skip_optional_whitespace(extensions, index)
        if index < len(extensions) and extensions[index] != ord(";"):
            return False
    return True


def _skip_optional_whitespace(value: bytes, index: int) -> int:
    while index < len(value) and value[index] in (ord(" "), ord("\t")):
        index += 1
    return index


def _consume_token(value: bytes, index: int) -> int:
    while index < len(value) and value[index] in _HTTP_TOKEN_CHARACTERS:
        index += 1
    return index


def _consume_quoted_string(value: bytes, index: int) -> int:
    index += 1
    while index < len(value):
        character = value[index]
        if character == ord('"'):
            return index + 1
        if character == ord("\\"):
            index += 1
            if index >= len(value) or not (
                value[index] == ord("\t") or 0x20 <= value[index] <= 0x7E
            ):
                return -1
        elif not (
            character == ord("\t")
            or 0x20 <= character <= 0x21
            or 0x23 <= character <= 0x5B
            or 0x5D <= character <= 0x7E
        ):
            return -1
        index += 1
    return -1


def _valid_trailer_line(line: bytes) -> bool:
    if not line.endswith(b"\r\n"):
        return False
    field = line[:-2]
    name, separator, value = field.partition(b":")
    if (
        not separator
        or not name
        or any(character not in _HTTP_TOKEN_CHARACTERS for character in name)
    ):
        return False
    if name.lower() in _FORBIDDEN_TRAILER_FIELDS:
        return False
    return all(character == ord("\t") or 0x20 <= character <= 0x7E for character in value)


def _raw_http_response(status: HTTPStatus, body: bytes) -> bytes:
    headers = (
        f"HTTP/1.1 {status.value} {status.phrase}\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "\r\n"
    ).encode("ascii")
    return headers + body
