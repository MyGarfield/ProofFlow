#!/usr/bin/env bash
# Verify the v1.2.2 llm-preflight redaction patch in an isolated temporary clone.
# This script never contacts a Manager, reads runtime environment/configuration,
# starts a Worker/LLM, or emits command/test output that could contain secrets.

set -u

EXPECTED_VERSION="v1.2.2"
EXPECTED_COMMIT="849182af8e017168a5a200a87b1062142caf462d"
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd)
PATCH_PATH="${SCRIPT_DIR}/../patches/v1.2.2-llm-preflight-help-redaction.patch"
SOURCE_DIR=""
OUTPUT="-"

usage() {
    cat <<'EOF'
Usage:
  verify-llm-preflight-patch.sh --source-dir PATH [--output FILE|-]

--source-dir PATH  Clean local Git checkout containing the pinned source commit.
--output FILE      Write machine evidence atomically; default: stdout.

The verifier creates a disposable clone, checks out only the pinned commit,
applies the patch, and runs only the scoped Go tests. It never inspects a
Manager, Worker, container environment, process list, logs, or live LLM.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-dir)
            if [ "$#" -lt 2 ]; then
                printf 'Missing value for --source-dir\n' >&2
                exit 2
            fi
            SOURCE_DIR=$2
            shift 2
            ;;
        --output)
            if [ "$#" -lt 2 ]; then
                printf 'Missing value for --output\n' >&2
                exit 2
            fi
            OUTPUT=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument was redacted.\n' >&2
            exit 2
            ;;
    esac
done

if [ -z "${SOURCE_DIR}" ]; then
    printf '%s\n' '--source-dir is required' >&2
    exit 2
fi
if [ ! -f "${PATCH_PATH}" ]; then
    printf '%s\n' 'llm-preflight patch is missing' >&2
    exit 2
fi
if ! command -v git >/dev/null 2>&1 || ! command -v shasum >/dev/null 2>&1 || \
   ! command -v mktemp >/dev/null 2>&1; then
    printf '%s\n' 'git, shasum, and mktemp are required' >&2
    exit 2
fi

SOURCE_COMMIT=$(git -C "${SOURCE_DIR}" rev-parse HEAD 2>/dev/null || printf '')
SOURCE_IS_CLEAN=false
if [ "${SOURCE_COMMIT}" = "${EXPECTED_COMMIT}" ] && \
   [ -z "$(git -C "${SOURCE_DIR}" status --porcelain 2>/dev/null)" ]; then
    SOURCE_IS_CLEAN=true
fi

PATCH_SHA256=$(shasum -a 256 "${PATCH_PATH}" | awk '{print $1}')
CLONE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentteams-llm-preflight-verify.XXXXXX")
CHECKOUT_DIR="${CLONE_ROOT}/checkout"
cleanup() {
    rm -rf "${CLONE_ROOT}"
}
trap cleanup EXIT

CLONE_OK=false
CHECKOUT_IS_CLEAN=false
APPLY_CHECK="NOT_RUN"
PATCH_APPLIED=false
GO_TESTS="NOT_RUN"

if [ "${SOURCE_IS_CLEAN}" = true ] && \
   git clone --quiet --no-local --no-checkout "${SOURCE_DIR}" "${CHECKOUT_DIR}" >/dev/null 2>&1 && \
   git -C "${CHECKOUT_DIR}" checkout --quiet --detach "${EXPECTED_COMMIT}" >/dev/null 2>&1; then
    CLONE_OK=true
fi
if [ "${CLONE_OK}" = true ] && \
   [ -z "$(git -C "${CHECKOUT_DIR}" status --porcelain 2>/dev/null)" ]; then
    CHECKOUT_IS_CLEAN=true
fi

if [ "${CHECKOUT_IS_CLEAN}" = true ] && \
   git -C "${CHECKOUT_DIR}" apply --check "${PATCH_PATH}" >/dev/null 2>&1; then
    APPLY_CHECK="PASS"
    if git -C "${CHECKOUT_DIR}" apply "${PATCH_PATH}" >/dev/null 2>&1; then
        PATCH_APPLIED=true
    fi
else
    APPLY_CHECK="FAIL"
fi

if [ "${PATCH_APPLIED}" = true ] && command -v go >/dev/null 2>&1; then
    if (cd "${CHECKOUT_DIR}/agentteams-controller" && \
        env -u AGENTTEAMS_LLM_API_KEY -u AGENTTEAMS_AUTH_TOKEN \
          GOPROXY=off GOSUMDB=off \
          GOTOOLCHAIN=local go test ./cmd/agt -run 'TestLLMPreflight' -count=1 \
          >/dev/null 2>&1); then
        GO_TESTS="PASS"
    else
        GO_TESTS="FAIL"
    fi
fi

OVERALL="FAIL"
if [ "${SOURCE_IS_CLEAN}" = true ] && [ "${CLONE_OK}" = true ] && \
   [ "${CHECKOUT_IS_CLEAN}" = true ] && [ "${APPLY_CHECK}" = PASS ] && \
   [ "${PATCH_APPLIED}" = true ] && [ "${GO_TESTS}" = PASS ]; then
    OVERALL="PASS"
fi

OBSERVED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf 'unknown')
JSON=$(cat <<EOF
{
  "schema_version": "agentteams-llm-preflight-patch-verification/v1",
  "observed_at_utc": "${OBSERVED_AT}",
  "status": "${OVERALL}",
  "source": {
    "version": "${EXPECTED_VERSION}",
    "commit": "${SOURCE_COMMIT}",
    "expected_commit": "${EXPECTED_COMMIT}",
    "source_worktree_clean": ${SOURCE_IS_CLEAN},
    "isolated_clone_created": ${CLONE_OK},
    "isolated_checkout_clean": ${CHECKOUT_IS_CLEAN}
  },
  "patch": {
    "name": "v1.2.2-llm-preflight-help-redaction.patch",
    "sha256": "${PATCH_SHA256}",
    "git_apply_check": "${APPLY_CHECK}",
    "applied_in_isolated_checkout": ${PATCH_APPLIED}
  },
  "tests": {
    "command": "go test ./cmd/agt -run TestLLMPreflight -count=1",
    "status": "${GO_TESTS}"
  },
  "runtime_boundary": {
    "live_manager_env_read": false,
    "live_manager_help_or_completion_run": false,
    "worker_started": false,
    "llm_started": false,
    "runtime_binary_fixed": false,
    "patch_deployed": false
  },
  "release_gate": {
    "old_exposed_credentials_revoked_and_rotated": false,
    "manager_rebuilt_and_replaced": false,
    "new_sbom_and_scan_verified": false,
    "runtime_verification_complete": false,
    "workers_may_start": false
  }
}
EOF
)

if [ "${OUTPUT}" = "-" ]; then
    printf '%s\n' "${JSON}"
else
    if [ -e "${OUTPUT}" ]; then
        printf '%s\n' 'Refusing to overwrite existing evidence file' >&2
        exit 2
    fi
    OUTPUT_DIR=$(dirname -- "${OUTPUT}")
    TMP_OUTPUT=$(mktemp "${OUTPUT_DIR}/.llm-preflight-verification.XXXXXX") || exit 2
    if ! printf '%s\n' "${JSON}" >"${TMP_OUTPUT}"; then
        rm -f "${TMP_OUTPUT}"
        exit 2
    fi
    if ! mv -n "${TMP_OUTPUT}" "${OUTPUT}" >/dev/null 2>&1; then
        rm -f "${TMP_OUTPUT}"
        exit 2
    fi
fi

if [ "${OVERALL}" = PASS ]; then
    exit 0
fi
exit 1
