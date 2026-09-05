#!/bin/sh
# Launch the fixed verifier image. A mutable tag is never accepted.
set -eu

DOCKER_BIN="/usr/bin/docker"
HOST_PYTHON_BIN="/usr/bin/python3"
IMAGE_REF=""
REPO_ROOT=""
ARTIFACT_ROOT=""
EXPECTED_ARTIFACT_COMMIT=""
EXPECTED_MANIFEST_SHA256=""
EXPECTED_SCHEMA_SHA256=""
EXPECTED_VALIDATOR_SHA256=""
EXPECTED_IMAGE_DIGEST=""
EXPECTED_IMAGE_CONFIG_DIGEST=""
RECEIPT_OUTPUT=""

die() {
    # Docker diagnostics can contain host paths, so only emit closed codes.
    printf 'proofflow OCI verifier: %s\n' "$1" >&2
    exit 2
}

usage() {
    cat >&2 <<'EOF'
usage: run.sh --image NAME@sha256:CHILD_DIGEST --repo-root ABSOLUTE_DIR \
  --artifact-root ABSOLUTE_DIR --expected-artifact-commit SHA \
  --expected-manifest-sha256 sha256:DIGEST --expected-schema-sha256 sha256:DIGEST \
  --expected-validator-sha256 sha256:DIGEST --expected-image-digest sha256:DIGEST \
  --expected-image-config-digest sha256:DIGEST [--receipt-output ABSOLUTE_FILE] \
  [--docker-bin ABSOLUTE_DOCKER] [--host-python-bin ABSOLUTE_PYTHON]
EOF
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --docker-bin) [ "$#" -ge 2 ] || usage; DOCKER_BIN="$2"; shift 2 ;;
        --host-python-bin) [ "$#" -ge 2 ] || usage; HOST_PYTHON_BIN="$2"; shift 2 ;;
        --image) [ "$#" -ge 2 ] || usage; IMAGE_REF="$2"; shift 2 ;;
        --repo-root) [ "$#" -ge 2 ] || usage; REPO_ROOT="$2"; shift 2 ;;
        --artifact-root) [ "$#" -ge 2 ] || usage; ARTIFACT_ROOT="$2"; shift 2 ;;
        --expected-artifact-commit) [ "$#" -ge 2 ] || usage; EXPECTED_ARTIFACT_COMMIT="$2"; shift 2 ;;
        --expected-manifest-sha256) [ "$#" -ge 2 ] || usage; EXPECTED_MANIFEST_SHA256="$2"; shift 2 ;;
        --expected-schema-sha256) [ "$#" -ge 2 ] || usage; EXPECTED_SCHEMA_SHA256="$2"; shift 2 ;;
        --expected-validator-sha256) [ "$#" -ge 2 ] || usage; EXPECTED_VALIDATOR_SHA256="$2"; shift 2 ;;
        --expected-image-digest) [ "$#" -ge 2 ] || usage; EXPECTED_IMAGE_DIGEST="$2"; shift 2 ;;
        --expected-image-config-digest) [ "$#" -ge 2 ] || usage; EXPECTED_IMAGE_CONFIG_DIGEST="$2"; shift 2 ;;
        --receipt-output) [ "$#" -ge 2 ] || usage; RECEIPT_OUTPUT="$2"; shift 2 ;;
        --help|-h) usage ;;
        *) usage ;;
    esac
done

case "$DOCKER_BIN" in /*) ;; *) die "DOCKER_BIN_MUST_BE_ABSOLUTE" ;; esac
case "$HOST_PYTHON_BIN" in /*) ;; *) die "HOST_PYTHON_BIN_MUST_BE_ABSOLUTE" ;; esac
[ "${IMAGE_REF#*@}" != "$IMAGE_REF" ] || die "IMAGE_MUST_USE_IMMUTABLE_CHILD_DIGEST"
IMAGE_DIGEST="${IMAGE_REF##*@}"
[ "${#IMAGE_DIGEST}" -eq 71 ] || die "IMAGE_MUST_USE_IMMUTABLE_CHILD_DIGEST"
case "$IMAGE_DIGEST" in sha256:*) ;; *) die "IMAGE_MUST_USE_IMMUTABLE_CHILD_DIGEST" ;; esac
case "${IMAGE_DIGEST#sha256:}" in *[!0-9a-f]*) die "IMAGE_MUST_USE_IMMUTABLE_CHILD_DIGEST" ;; esac
[ "${#EXPECTED_ARTIFACT_COMMIT}" -eq 40 ] || die "ARTIFACT_COMMIT_MUST_BE_FULL_SHA"
case "$EXPECTED_ARTIFACT_COMMIT" in *[!0-9a-f]*) die "ARTIFACT_COMMIT_MUST_BE_FULL_SHA" ;; esac
IMAGE_NAME="${IMAGE_REF%@*}"
case "${IMAGE_NAME##*/}" in *:*) die "IMAGE_TAG_FORBIDDEN" ;; esac
for digest in "$EXPECTED_MANIFEST_SHA256" "$EXPECTED_SCHEMA_SHA256" "$EXPECTED_VALIDATOR_SHA256" "$EXPECTED_IMAGE_DIGEST" "$EXPECTED_IMAGE_CONFIG_DIGEST"; do
    [ "${#digest}" -eq 71 ] || die "EXPECTED_DIGEST_INVALID"
    case "$digest" in sha256:*) ;; *) die "EXPECTED_DIGEST_INVALID" ;; esac
    digest_hex="${digest#sha256:}"
    case "$digest_hex" in *[!0-9a-f]*) die "EXPECTED_DIGEST_INVALID" ;; esac
done
[ "$EXPECTED_IMAGE_DIGEST" != "$EXPECTED_IMAGE_CONFIG_DIGEST" ] || die "IMAGE_DIGEST_CONFIG_COLLISION"
case "$REPO_ROOT" in /*) ;; *) die "REPO_ROOT_MUST_BE_ABSOLUTE" ;; esac
case "$ARTIFACT_ROOT" in /*) ;; *) die "ARTIFACT_ROOT_MUST_BE_ABSOLUTE" ;; esac
if [ ! -d "$REPO_ROOT" ] || [ -L "$REPO_ROOT" ] || [ ! -d "$ARTIFACT_ROOT" ] || [ -L "$ARTIFACT_ROOT" ]; then
    die "MOUNT_SOURCE_INVALID"
fi
if [ -n "$RECEIPT_OUTPUT" ]; then
    case "$RECEIPT_OUTPUT" in /*) ;; *) die "RECEIPT_OUTPUT_MUST_BE_ABSOLUTE" ;; esac
fi

SCRIPT_DIR="$(/usr/bin/dirname "$0")"
SCRIPT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR" && pwd)" || die "LAUNCHER_DIRECTORY_UNAVAILABLE"

TMP_ROOT="$(/usr/bin/mktemp -d /tmp/proofflow-oci-run.XXXXXX)" || die "TEMPORARY_DIRECTORY_FAILED"
trap '/bin/rm -rf "$TMP_ROOT"' EXIT HUP INT TERM
INSPECT_ERR="$TMP_ROOT/inspect.err"
RUN_OUTPUT="$TMP_ROOT/receipt.json"

inspect() {
    value=""
    if ! value="$($DOCKER_BIN image inspect --platform linux/amd64 "$IMAGE_REF" --format "$1" 2>"$INSPECT_ERR")"; then
        die "IMAGE_NOT_AVAILABLE_OR_INSPECT_FAILED"
    fi
    printf '%s' "$value"
}

IMAGE_ID="$(inspect '{{.Id}}')"
IMAGE_ARCH="$(inspect '{{.Architecture}}')"
IMAGE_OS="$(inspect '{{.Os}}')"
IMAGE_USER="$(inspect '{{.Config.User}}')"
IMAGE_REPO_DIGESTS="$(inspect '{{join .RepoDigests "\n"}}')"
case "$IMAGE_ID" in sha256:????????????????????????????????????????????????????????????????) ;; *) die "IMAGE_ID_INVALID" ;; esac
[ "$IMAGE_ARCH" = "amd64" ] || die "IMAGE_CHILD_ARCHITECTURE_MISMATCH"
[ "$IMAGE_OS" = "linux" ] || die "IMAGE_CHILD_OS_MISMATCH"
[ "$IMAGE_USER" = "65532:65532" ] || die "IMAGE_USER_MISMATCH"
case "$IMAGE_REPO_DIGESTS" in *"$IMAGE_REF"*) ;; *) die "IMAGE_REPO_DIGEST_NOT_CONFIRMED" ;; esac

IMAGE_ARCHIVE="$TMP_ROOT/image.oci.tar"
if ! "$DOCKER_BIN" save --platform linux/amd64 --output "$IMAGE_ARCHIVE" "$IMAGE_REF" 2>"$TMP_ROOT/save.err"; then
    die "IMAGE_ARCHIVE_EXPORT_FAILED"
fi
[ "$(/usr/bin/wc -c <"$IMAGE_ARCHIVE")" -le 1073741824 ] || die "IMAGE_ARCHIVE_OUTPUT_LIMIT_EXCEEDED"
if ! "$HOST_PYTHON_BIN" "$SCRIPT_DIR/inspect_oci_archive.py" \
    --archive "$IMAGE_ARCHIVE" \
    --expected-child-digest "$EXPECTED_IMAGE_DIGEST" \
    --expected-config-digest "$EXPECTED_IMAGE_CONFIG_DIGEST" \
    >"$TMP_ROOT/archive-inspection.json" 2>"$TMP_ROOT/archive-inspection.err"; then
    die "IMAGE_ARCHIVE_PIN_MISMATCH"
fi

set +e
"$DOCKER_BIN" run --rm --pull=never \
    --platform linux/amd64 \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --user 65532:65532 \
    --cpus 1 \
    --memory 536870912 \
    --memory-swap 536870912 \
    --pids-limit 128 \
    --ulimit nofile=1024:1024 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --mount "type=bind,src=$ARTIFACT_ROOT,dst=/input/reference-video,ro" \
    --mount "type=bind,src=$REPO_ROOT,dst=/input/repo,ro" \
    --env PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin \
    --env HOME=/nonexistent \
    --env LANG=C.UTF-8 \
    --env LC_ALL=C.UTF-8 \
    --env TZ=UTC \
    --env PYTHONNOUSERSITE=1 \
    --env PROOFFLOW_EXPECTED_ARTIFACT_COMMIT="$EXPECTED_ARTIFACT_COMMIT" \
    --env PROOFFLOW_EXPECTED_MANIFEST_SHA256="$EXPECTED_MANIFEST_SHA256" \
    --env PROOFFLOW_EXPECTED_SCHEMA_SHA256="$EXPECTED_SCHEMA_SHA256" \
    --env PROOFFLOW_EXPECTED_VALIDATOR_SHA256="$EXPECTED_VALIDATOR_SHA256" \
    --env PROOFFLOW_EXPECTED_IMAGE_DIGEST="$EXPECTED_IMAGE_DIGEST" \
    --env PROOFFLOW_EXPECTED_IMAGE_CONFIG_DIGEST="$EXPECTED_IMAGE_CONFIG_DIGEST" \
    "$IMAGE_REF" >"$RUN_OUTPUT" 2>"$TMP_ROOT/run.err"
DOCKER_STATUS="$?"
set -e
[ "$(/usr/bin/wc -c <"$RUN_OUTPUT")" -le 2097152 ] || die "RECEIPT_OUTPUT_LIMIT_EXCEEDED"
[ -s "$RUN_OUTPUT" ] || die "CONTAINER_DID_NOT_RETURN_RECEIPT"
if [ -n "$RECEIPT_OUTPUT" ]; then
    OUTPUT_DIR="$(/usr/bin/dirname "$RECEIPT_OUTPUT")"
    [ -d "$OUTPUT_DIR" ] || die "RECEIPT_OUTPUT_DIRECTORY_MISSING"
    if ! "$HOST_PYTHON_BIN" "$SCRIPT_DIR/write_receipt.py" \
        --source "$RUN_OUTPUT" --destination "$RECEIPT_OUTPUT" 2>"$TMP_ROOT/write.err"; then
        die "RECEIPT_OUTPUT_WRITE_FAILED"
    fi
fi
/bin/cat "$RUN_OUTPUT"
exit "$DOCKER_STATUS"
