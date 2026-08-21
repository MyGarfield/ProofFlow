#!/usr/bin/env bash
# Read-only preflight for the AgentTeams v1.2.2 local installer on macOS + Colima.
# This script never installs, patches, restarts, removes, or prints configuration.

set -u

EXPECTED_COMMIT="849182af8e017168a5a200a87b1062142caf462d"
SOURCE_DIR=""
PASS=0
FAIL=0
INFO=0

usage() {
    cat <<'EOF'
Usage: preflight-macos-colima.sh [--source-dir PATH]

Performs read-only checks. PATH may point to an AgentTeams v1.2.2 checkout.
The path itself is never printed.
EOF
}

pass() {
    printf '  [PASS] %s\n' "$1"
    PASS=$((PASS + 1))
}

fail() {
    printf '  [FAIL] %s\n' "$1"
    FAIL=$((FAIL + 1))
}

info() {
    printf '  [INFO] %s\n' "$1"
    INFO=$((INFO + 1))
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
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument was redacted.\n' >&2
            usage >&2
            exit 2
            ;;
    esac
done

printf '%s\n' '==> AgentTeams macOS + Colima read-only preflight'

if [ "$(uname -s 2>/dev/null || printf unknown)" = "Darwin" ]; then
    pass "host OS is macOS"
else
    fail "host OS is not macOS; this preflight does not apply"
fi

if command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1; then
    pass "Docker client can reach a daemon"
else
    fail "Docker client cannot reach a daemon"
fi

if command -v colima >/dev/null 2>&1 && colima status --json >/dev/null 2>&1; then
    pass "Colima reports a running profile"
else
    fail "Colima is unavailable or not running"
fi

CONTEXT_CLASS="unknown"
if command -v docker >/dev/null 2>&1; then
    CONTEXT_NAME=$(docker context show 2>/dev/null || printf '')
    CONTEXT_ENDPOINT=$(docker context inspect --format '{{.Endpoints.docker.Host}}' \
        "${CONTEXT_NAME}" 2>/dev/null || printf '')
    case "${CONTEXT_ENDPOINT}" in
        unix://*/.colima/*/docker.sock|*/.colima/*/docker.sock)
            CONTEXT_CLASS="colima-host-socket"
            pass "Docker context is a Colima host-side socket (path redacted)"
            ;;
        *)
            info "Docker context is not classified as a Colima host-side socket"
            ;;
    esac
fi

if command -v colima >/dev/null 2>&1 && \
   colima ssh -- test -S /var/run/docker.sock >/dev/null 2>&1; then
    pass "Colima VM daemon socket exists at /var/run/docker.sock"
else
    fail "Colima VM daemon socket is missing"
fi

if [ "${CONTEXT_CLASS}" = "colima-host-socket" ]; then
    info "v1.2.2 needs the daemon-local socket override before installer execution"
fi

if [ -n "${SOURCE_DIR}" ]; then
    if [ -d "${SOURCE_DIR}/.git" ]; then
        SOURCE_COMMIT=$(git -C "${SOURCE_DIR}" rev-parse HEAD 2>/dev/null || printf '')
        if [ "${SOURCE_COMMIT}" = "${EXPECTED_COMMIT}" ]; then
            pass "source checkout matches the pinned v1.2.2 commit"
        else
            fail "source checkout does not match the pinned v1.2.2 commit"
        fi

        INSTALLER="${SOURCE_DIR}/install/agentteams-install.sh"
        if [ -f "${INSTALLER}" ] && \
           grep -Fq "CONTAINER_SOCK=\"/var/run/docker.sock\"" "${INSTALLER}" && \
           grep -Fq "grep -q '/\\.colima/'" "${INSTALLER}"; then
            pass "source checkout contains the scoped Colima socket override"
        else
            fail "source checkout does not contain the scoped Colima socket override"
        fi
    else
        fail "source directory is not a Git checkout"
    fi
else
    info "source checkout was not supplied; commit and patch were not checked"
fi

printf '==> Result: pass=%d fail=%d info=%d\n' "${PASS}" "${FAIL}" "${INFO}"
printf '%s\n' 'No state was changed. Review patches/v1.2.2-macos-colima-daemon-socket.patch before any manual application.'

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
