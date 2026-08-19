#!/usr/bin/env bash
# Produce a deliberately narrow, public-safe AgentTeams infrastructure snapshot.
# The collector uses an explicit allowlist and never reads env files, container
# environment dumps, logs, Matrix messages, MinIO objects, or runtime workspaces.

set -u

MODE="dry-run"
OUTPUT="-"
STRICT=0
SOURCE_DIR=""

EXPECTED_VERSION="v1.2.2"
EXPECTED_COMMIT="849182af8e017168a5a200a87b1062142caf462d"
EMBEDDED_TAG="higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-embedded:v1.2.2"
EMBEDDED_LOCAL_IMAGE_ID="sha256:c7e467bfa5a2a733ea021c19f223180eef85e3e534873feceb8a7a132253125f"
EMBEDDED_REPO_DIGEST="higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-embedded@sha256:c7e467bfa5a2a733ea021c19f223180eef85e3e534873feceb8a7a132253125f"
MANAGER_TAG="higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-manager:v1.2.2"
MANAGER_LOCAL_IMAGE_ID="sha256:dd11878943e4a425ff38dcc152c9d44ea0e68d97bac89f711207134b8636c0fb"
MANAGER_REPO_DIGEST="higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-manager@sha256:dd11878943e4a425ff38dcc152c9d44ea0e68d97bac89f711207134b8636c0fb"
WORKER_TAG="higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-worker:v1.2.2"
WORKER_LOCAL_IMAGE_ID="sha256:301f9e311654eca203246fa666d63a126244ea8793f700603d2a6d37b7ffea75"
WORKER_REPO_DIGEST="higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-worker@sha256:301f9e311654eca203246fa666d63a126244ea8793f700603d2a6d37b7ffea75"
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd)
WORKER_SPEC="${SCRIPT_DIR}/../01-workers-stopped.yaml"
VALIDATOR="${SCRIPT_DIR}/validate_public_evidence.py"
COLIMA_PATCH="${SCRIPT_DIR}/../patches/v1.2.2-macos-colima-daemon-socket.patch"
EMBEDDED_CONSOLE_PATCH="${SCRIPT_DIR}/../patches/v1.2.2-embedded-higress-console-url.patch"

usage() {
    cat <<'EOF'
Usage:
  collect-public-evidence.sh --dry-run
  collect-public-evidence.sh --collect [--output FILE|-] [--source-dir PATH] [--strict]

--dry-run    List the allowlisted checks without touching Docker or Colima.
--collect    Run read-only checks and emit one JSON document.
--output     Write to a new file; existing files are never overwritten. Default: stdout.
--source-dir Optional AgentTeams source checkout. Its path is never emitted.
--strict     Return non-zero for health failures or key source, image, or
             resolver verification failures.

The script never reads or prints secrets, administrator passwords, env files,
container environment dumps, logs, Matrix content, MinIO content, or user paths.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --collect)
            MODE="collect"
            shift
            ;;
        --output)
            if [ "$#" -lt 2 ]; then
                printf 'Missing value for --output\n' >&2
                exit 2
            fi
            OUTPUT=$2
            shift 2
            ;;
        --source-dir)
            if [ "$#" -lt 2 ]; then
                printf 'Missing value for --source-dir\n' >&2
                exit 2
            fi
            SOURCE_DIR=$2
            shift 2
            ;;
        --strict)
            STRICT=1
            shift
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

if [ "${MODE}" = "dry-run" ]; then
    cat <<'EOF'
Read-only allowlist:
  1. Classify OS, Docker context, and Colima daemon-local socket presence.
  2. Check only the fixed resolver backup and current resolver syntax and
     normalization booleans; resolver addresses and file hashes are never emitted.
  3. Compare three observed local Docker image IDs and, separately, Docker's
     public RepoDigest metadata with point-in-time reference observations.
  4. Count AgentTeams Worker containers without emitting their names.
  5. Read only AGENTTEAMS_MANAGER_RUNTIME from the Manager container and reduce
     it to a known runtime enum.
  6. Probe Controller, MinIO, Matrix, Higress, Element, Docker socket API, and
     OpenClaw Manager health; response bodies are discarded.
  7. Optionally verify source commit and the scoped Colima patch without
     emitting the source path or diff. The independent embedded Higress Console
     URL override is checked separately.
  8. Parse OpenClaw health as strict JSON with top-level ok=true. The collector
     never runs agt llm-preflight help or any command-completion generator.

Explicitly excluded: env files, full container env, logs, messages, object data,
workspace files, credentials, administrator passwords, cleanup, restart, install,
resource application, and Worker creation.
EOF
    exit 0
fi

if ! command -v docker >/dev/null 2>&1 || ! docker version >/dev/null 2>&1; then
    printf 'Docker is required for --collect.\n' >&2
    exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
    printf 'curl is required for --collect.\n' >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    printf 'jq is required for --collect.\n' >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1 || [ ! -f "${VALIDATOR}" ] || \
   ! python3 -c 'import jsonschema' >/dev/null 2>&1; then
    printf 'The public evidence validator and its jsonschema dependency are required for --collect.\n' >&2
    exit 2
fi

bool() {
    if "$@" >/dev/null 2>&1; then
        printf true
    else
        printf false
    fi
}

safe_hash() {
    if [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        printf '%s' "$1"
    else
        printf ''
    fi
}

safe_repo_digest() {
    if [[ "$1" =~ ^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$ ]]; then
        printf '%s' "$1"
    else
        printf ''
    fi
}

safe_bool_or_null() {
    case "$1" in
        true|false) printf '%s' "$1" ;;
        *) printf null ;;
    esac
}

safe_http_code() {
    if [[ "$1" =~ ^(000|[1-5][0-9]{2})$ ]]; then
        printf '%s' "$1"
    else
        printf 000
    fi
}

json_nullable_string() {
    if [ -n "$1" ]; then
        printf '"%s"' "$1"
    else
        printf null
    fi
}

http_status_host() {
    result=$(curl --silent --show-error --noproxy '*' --output /dev/null \
        --write-out '%{http_code}' \
        --max-time 5 "$@" 2>/dev/null || true)
    safe_http_code "${result}"
}

http_status_container() {
    container=$1
    url=$2
    result=$(docker exec "${container}" curl --silent --show-error --noproxy '*' \
        --output /dev/null --write-out '%{http_code}' --max-time 5 "${url}" \
        2>/dev/null || true)
    safe_http_code "${result}"
}

status_for_code() {
    actual=$1
    expected=$2
    if [ "${actual}" = "${expected}" ]; then
        printf pass
    else
        printf fail
    fi
}

count_status() {
    case "$1" in
        pass) PASSED=$((PASSED + 1)) ;;
        fail) FAILED=$((FAILED + 1)) ;;
        skip) SKIPPED=$((SKIPPED + 1)) ;;
    esac
}

image_id() {
    value=$(docker image inspect --format '{{.Id}}' "$1" 2>/dev/null || printf '')
    safe_hash "${value}"
}

repo_digest() {
    image=$1
    repository=${image%:*}
    value=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
        "${image}" 2>/dev/null | awk -v prefix="${repository}@sha256:" \
        'index($0, prefix) == 1 {candidate = $0; count++} END {if (count == 1) print candidate}')
    safe_repo_digest "${value}"
}

container_running() {
    docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null | grep -qx true
}

HOST_OS="other"
case "$(uname -s 2>/dev/null || printf other)" in
    Darwin) HOST_OS="darwin" ;;
    Linux) HOST_OS="linux" ;;
esac

DOCKER_CONTEXT_CLASS="other"
CONTEXT_NAME=$(docker context show 2>/dev/null || printf '')
CONTEXT_ENDPOINT=$(docker context inspect --format '{{.Endpoints.docker.Host}}' \
    "${CONTEXT_NAME}" 2>/dev/null || printf '')
case "${CONTEXT_ENDPOINT}" in
    unix://*/.colima/*/docker.sock|*/.colima/*/docker.sock)
        DOCKER_CONTEXT_CLASS="colima-host-socket"
        ;;
    unix://*) DOCKER_CONTEXT_CLASS="unix-socket" ;;
    tcp://*) DOCKER_CONTEXT_CLASS="tcp" ;;
esac

COLIMA_RUNNING=false
COLIMA_DAEMON_SOCKET=false
if command -v colima >/dev/null 2>&1 && colima status --json >/dev/null 2>&1; then
    COLIMA_RUNNING=true
    COLIMA_DAEMON_SOCKET=$(bool colima ssh -- test -S /var/run/docker.sock)
fi

CONTROLLER_SOCKET=$(bool docker exec agentteams-controller test -S /var/run/docker.sock)
DOCKER_SOCKET_API=$(bool docker exec agentteams-controller sh -c \
    'curl --silent --show-error --noproxy "*" --fail --max-time 5 --unix-socket /var/run/docker.sock http://localhost/_ping >/dev/null')

RESOLVER_BACKUP_PRESENT=false
RESOLVER_BACKUP_INVALID_PREFIX=null
RESOLVER_CURRENT_SYNTAX=null
RESOLVER_NORMALIZED_MATCH=null
RESOLVER_VERIFICATION_STATUS=skip
if [ "${COLIMA_RUNNING}" = true ]; then
    # shellcheck disable=SC2016 # Expansion is intentionally deferred to the VM shell.
    RESOLVER_FACTS=$(colima ssh -- sh -c '
        backup="/etc/resolv.conf.proofflow-backup-20260820T0120"
        current="/etc/resolv.conf"
        if [ -f "${backup}" ]; then
            printf "backup_present=true\n"
            if head -n 1 "${backup}" | grep -Eq "^-e[[:space:]]+nameserver[[:space:]]+[^[:space:]]+$"; then
                printf "backup_invalid_prefix=true\n"
            else
                printf "backup_invalid_prefix=false\n"
            fi
        else
            printf "backup_present=false\n"
        fi
        if [ -f "${current}" ]; then
            if awk '\''
                NF == 0 { next }
                $1 == "nameserver" && NF == 2 { next }
                $1 == "domain" && NF == 2 { next }
                $1 == "search" && NF >= 2 { next }
                $1 == "options" && NF >= 2 { next }
                $1 == "sortlist" && NF >= 2 { next }
                { bad = 1 }
                END { exit bad ? 1 : 0 }
            '\'' "${current}"; then
                printf "current_syntax=true\n"
            else
                printf "current_syntax=false\n"
            fi
            if [ -f "${backup}" ] && \
               sed "1s/^-e[[:space:]]*//" "${backup}" | cmp -s - "${current}"; then
                printf "normalized_match=true\n"
            elif [ -f "${backup}" ]; then
                printf "normalized_match=false\n"
            fi
        fi
    ' 2>/dev/null || printf '')
    RESOLVER_BACKUP_PRESENT=$(printf '%s\n' "${RESOLVER_FACTS}" | awk -F= '$1=="backup_present"{print $2; exit}')
    RESOLVER_BACKUP_INVALID_PREFIX=$(printf '%s\n' "${RESOLVER_FACTS}" | awk -F= '$1=="backup_invalid_prefix"{print $2; exit}')
    RESOLVER_CURRENT_SYNTAX=$(printf '%s\n' "${RESOLVER_FACTS}" | awk -F= '$1=="current_syntax"{print $2; exit}')
    RESOLVER_NORMALIZED_MATCH=$(printf '%s\n' "${RESOLVER_FACTS}" | awk -F= '$1=="normalized_match"{print $2; exit}')
    RESOLVER_BACKUP_PRESENT=$(safe_bool_or_null "${RESOLVER_BACKUP_PRESENT:-}")
    if [ "${RESOLVER_BACKUP_PRESENT}" = null ]; then RESOLVER_BACKUP_PRESENT=false; fi
    RESOLVER_BACKUP_INVALID_PREFIX=$(safe_bool_or_null "${RESOLVER_BACKUP_INVALID_PREFIX:-}")
    RESOLVER_CURRENT_SYNTAX=$(safe_bool_or_null "${RESOLVER_CURRENT_SYNTAX:-}")
    RESOLVER_NORMALIZED_MATCH=$(safe_bool_or_null "${RESOLVER_NORMALIZED_MATCH:-}")
    if [ "${RESOLVER_CURRENT_SYNTAX}" = true ]; then
        if [ "${RESOLVER_BACKUP_PRESENT}" = false ]; then
            RESOLVER_BACKUP_INVALID_PREFIX=null
            RESOLVER_NORMALIZED_MATCH=null
            RESOLVER_VERIFICATION_STATUS=pass
        elif [ "${RESOLVER_BACKUP_INVALID_PREFIX}" = true ] && \
             [ "${RESOLVER_NORMALIZED_MATCH}" = true ]; then
            RESOLVER_VERIFICATION_STATUS=pass
        else
            RESOLVER_VERIFICATION_STATUS=fail
        fi
    else
        RESOLVER_VERIFICATION_STATUS=fail
    fi
fi

SOURCE_COMMIT=""
SOURCE_COMMIT_MATCH=false
SOURCE_LOCAL_PATCH=false
SOURCE_EMBEDDED_CONSOLE_PATCH=false
SOURCE_MODIFIED=false
SOURCE_CHECKOUT_SUPPLIED=false
SOURCE_VERIFICATION_STATUS=skip
if [ -n "${SOURCE_DIR}" ]; then
    SOURCE_CHECKOUT_SUPPLIED=true
fi
if [ -n "${SOURCE_DIR}" ] && [ -d "${SOURCE_DIR}/.git" ]; then
    SOURCE_COMMIT=$(git -C "${SOURCE_DIR}" rev-parse HEAD 2>/dev/null || printf '')
    if ! printf '%s\n' "${SOURCE_COMMIT}" | grep -Eq '^[0-9a-f]{40}$'; then
        SOURCE_COMMIT=""
    fi
    if [ "${SOURCE_COMMIT}" = "${EXPECTED_COMMIT}" ]; then
        SOURCE_COMMIT_MATCH=true
    fi
    if [ -f "${COLIMA_PATCH}" ] && \
       git -C "${SOURCE_DIR}" apply --reverse --check "${COLIMA_PATCH}" \
           >/dev/null 2>&1; then
        SOURCE_LOCAL_PATCH=true
    fi
    if [ -f "${EMBEDDED_CONSOLE_PATCH}" ] && \
       git -C "${SOURCE_DIR}" apply --reverse --check "${EMBEDDED_CONSOLE_PATCH}" \
           >/dev/null 2>&1; then
        SOURCE_EMBEDDED_CONSOLE_PATCH=true
    fi
    if [ -n "$(git -C "${SOURCE_DIR}" status --porcelain 2>/dev/null || printf '')" ]; then
        SOURCE_MODIFIED=true
    fi
    if [ "${SOURCE_COMMIT_MATCH}" = true ] && \
       [ "${SOURCE_LOCAL_PATCH}" = true ] && \
       [ "${SOURCE_EMBEDDED_CONSOLE_PATCH}" = true ]; then
        SOURCE_VERIFICATION_STATUS=pass
    else
        SOURCE_VERIFICATION_STATUS=fail
    fi
elif [ -n "${SOURCE_DIR}" ]; then
    SOURCE_VERIFICATION_STATUS=fail
fi

EMBEDDED_OBSERVED=$(image_id "${EMBEDDED_TAG}")
MANAGER_OBSERVED=$(image_id "${MANAGER_TAG}")
WORKER_OBSERVED=$(image_id "${WORKER_TAG}")
EMBEDDED_REPO_OBSERVED=$(repo_digest "${EMBEDDED_TAG}")
MANAGER_REPO_OBSERVED=$(repo_digest "${MANAGER_TAG}")
WORKER_REPO_OBSERVED=$(repo_digest "${WORKER_TAG}")
EMBEDDED_LOCAL_ID_MATCH=false
MANAGER_LOCAL_ID_MATCH=false
WORKER_LOCAL_ID_MATCH=false
EMBEDDED_REPO_MATCH=false
MANAGER_REPO_MATCH=false
WORKER_REPO_MATCH=false
[ "${EMBEDDED_OBSERVED}" = "${EMBEDDED_LOCAL_IMAGE_ID}" ] && EMBEDDED_LOCAL_ID_MATCH=true
[ "${MANAGER_OBSERVED}" = "${MANAGER_LOCAL_IMAGE_ID}" ] && MANAGER_LOCAL_ID_MATCH=true
[ "${WORKER_OBSERVED}" = "${WORKER_LOCAL_IMAGE_ID}" ] && WORKER_LOCAL_ID_MATCH=true
[ "${EMBEDDED_REPO_OBSERVED}" = "${EMBEDDED_REPO_DIGEST}" ] && EMBEDDED_REPO_MATCH=true
[ "${MANAGER_REPO_OBSERVED}" = "${MANAGER_REPO_DIGEST}" ] && MANAGER_REPO_MATCH=true
[ "${WORKER_REPO_OBSERVED}" = "${WORKER_REPO_DIGEST}" ] && WORKER_REPO_MATCH=true

WORKER_COUNT=$(docker ps -a --format '{{.Names}}' 2>/dev/null | \
    awk '/^agentteams-worker-/{n++} END{print n+0}')
case "${WORKER_COUNT}" in
    ''|*[!0-9]*) WORKER_COUNT=0 ;;
esac

WORKER_RUNTIME_CONTRACT="unknown"
WORKER_RESOURCES_DECLARED_STOPPED=false
if [ -f "${WORKER_SPEC}" ]; then
    RUNTIME_LINES=$(grep -Ec '^[[:space:]]+runtime:[[:space:]]+' "${WORKER_SPEC}" || true)
    OPENCLAW_LINES=$(grep -Ec '^[[:space:]]+runtime:[[:space:]]+openclaw[[:space:]]*$' \
        "${WORKER_SPEC}" || true)
    STOPPED_LINES=$(grep -Ec '^[[:space:]]+state:[[:space:]]+Stopped[[:space:]]*$' \
        "${WORKER_SPEC}" || true)
    if [ "${RUNTIME_LINES}" -eq 6 ] && [ "${OPENCLAW_LINES}" -eq 6 ]; then
        WORKER_RUNTIME_CONTRACT="openclaw"
    fi
    if [ "${STOPPED_LINES}" -eq 6 ]; then
        WORKER_RESOURCES_DECLARED_STOPPED=true
    fi
fi

PROOFFLOW_RUNNING_COUNT=0
for worker_name in case-manager evidence-agent rule-agent calculation-agent strategy-agent audit-agent; do
    if container_running "agentteams-worker-${worker_name}"; then
        PROOFFLOW_RUNNING_COUNT=$((PROOFFLOW_RUNNING_COUNT + 1))
    fi
done
ALL_SIX_PROOFFLOW_WORKERS_RUNNING=false
if [ "${PROOFFLOW_RUNNING_COUNT}" -eq 6 ]; then
    ALL_SIX_PROOFFLOW_WORKERS_RUNNING=true
fi

MANAGER_RUNTIME_RAW=$(docker exec agentteams-manager printenv \
    AGENTTEAMS_MANAGER_RUNTIME 2>/dev/null || printf '')
case "${MANAGER_RUNTIME_RAW}" in
    openclaw|copaw|qwenpaw|hermes) MANAGER_RUNTIME="${MANAGER_RUNTIME_RAW}" ;;
    *) MANAGER_RUNTIME="unknown" ;;
esac

if [ "${WORKER_COUNT}" -eq 0 ]; then
    WORKER_RUNTIME_OBSERVED="none-zero-workers"
else
    WORKER_RUNTIME_OBSERVED="unknown"
fi

CONTROLLER_CONTAINER=$(bool container_running agentteams-controller)
MANAGER_CONTAINER=$(bool container_running agentteams-manager)
CONTROLLER_HTTP=$(http_status_container agentteams-controller http://127.0.0.1:8090/healthz)
MINIO_HTTP=$(http_status_container agentteams-controller http://127.0.0.1:9000/minio/health/live)
MATRIX_HTTP=$(http_status_container agentteams-controller http://127.0.0.1:6167/_matrix/client/versions)
GATEWAY_HTTP=$(http_status_host --header 'Host: matrix-local.agentteams.io' \
    http://127.0.0.1:18080/_matrix/client/versions)
CONSOLE_HTTP=$(http_status_host http://127.0.0.1:18001/)
ELEMENT_HTTP=$(http_status_host http://127.0.0.1:18088/)

if [ "${CONTROLLER_CONTAINER}" = true ]; then CONTROLLER_CONTAINER_STATUS=pass; else CONTROLLER_CONTAINER_STATUS=fail; fi
if [ "${MANAGER_CONTAINER}" = true ]; then MANAGER_CONTAINER_STATUS=pass; else MANAGER_CONTAINER_STATUS=fail; fi
CONTROLLER_STATUS=$(status_for_code "${CONTROLLER_HTTP}" 200)
MINIO_STATUS=$(status_for_code "${MINIO_HTTP}" 200)
MATRIX_STATUS=$(status_for_code "${MATRIX_HTTP}" 200)
GATEWAY_STATUS=$(status_for_code "${GATEWAY_HTTP}" 200)
CONSOLE_STATUS=$(status_for_code "${CONSOLE_HTTP}" 200)
ELEMENT_STATUS=$(status_for_code "${ELEMENT_HTTP}" 200)
if [ "${DOCKER_SOCKET_API}" = true ]; then SOCKET_STATUS=pass; else SOCKET_STATUS=fail; fi

MANAGER_HEALTH_STATUS=fail
MANAGER_HEALTH_OBSERVATION=false
if [ "${MANAGER_CONTAINER}" = true ] && [ "${MANAGER_RUNTIME}" = "openclaw" ]; then
    # Parse only a literal top-level boolean. A nested or string-valued "ok"
    # must not turn a malformed health response into a pass.
    if docker exec agentteams-manager sh -c \
        'timeout 15 openclaw gateway health --json 2>/dev/null' 2>/dev/null | \
        jq -e -s 'length == 1 and (.[0] | type == "object" and .ok == true)' \
            >/dev/null 2>&1; then
        MANAGER_HEALTH_OBSERVATION=true
        MANAGER_HEALTH_STATUS=pass
    fi
fi

PASSED=0
FAILED=0
SKIPPED=0
for item in \
    "${CONTROLLER_CONTAINER_STATUS}" "${CONTROLLER_STATUS}" "${MINIO_STATUS}" \
    "${MATRIX_STATUS}" "${GATEWAY_STATUS}" "${CONSOLE_STATUS}" "${ELEMENT_STATUS}" \
    "${SOCKET_STATUS}" "${MANAGER_CONTAINER_STATUS}" "${MANAGER_HEALTH_STATUS}"; do
    count_status "${item}"
done
ALL_HEALTHY=false
if [ "${FAILED}" -eq 0 ]; then ALL_HEALTHY=true; fi

STRICT_COLLECTION_GATE_PASSED=true
if [ "${FAILED}" -gt 0 ] || \
   [ "${SOURCE_VERIFICATION_STATUS}" = fail ] || \
   [ "${RESOLVER_VERIFICATION_STATUS}" = fail ] || \
   [ "${EMBEDDED_LOCAL_ID_MATCH}" != true ] || \
   [ "${MANAGER_LOCAL_ID_MATCH}" != true ] || \
   [ "${WORKER_LOCAL_ID_MATCH}" != true ] || \
   [ "${EMBEDDED_REPO_MATCH}" != true ] || \
   [ "${MANAGER_REPO_MATCH}" != true ] || \
   [ "${WORKER_REPO_MATCH}" != true ]; then
    STRICT_COLLECTION_GATE_PASSED=false
fi

COLLECTED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
EVIDENCE_JSON=$(cat <<EOF
{
  "schema_version": "1.2",
  "evidence_kind": "agentteams-local-infra-smoke",
  "collected_at": "${COLLECTED_AT}",
  "collector": {
    "name": "collect-public-evidence.sh",
    "version": "1.2",
    "read_only_runtime_checks": true
  },
  "scope": {
    "host_os": "${HOST_OS}",
    "deployment_mode": "docker-embedded-local",
    "synthetic_data_only": true
  },
  "source": {
    "expected_version": "${EXPECTED_VERSION}",
    "expected_commit": "${EXPECTED_COMMIT}",
    "checkout_supplied": ${SOURCE_CHECKOUT_SUPPLIED},
    "observed_commit": $(json_nullable_string "${SOURCE_COMMIT}"),
    "commit_matches": ${SOURCE_COMMIT_MATCH},
    "local_colima_socket_patch_present": ${SOURCE_LOCAL_PATCH},
    "local_embedded_console_patch_present": ${SOURCE_EMBEDDED_CONSOLE_PATCH},
    "checkout_has_local_modifications": ${SOURCE_MODIFIED},
    "verification_status": "${SOURCE_VERIFICATION_STATUS}"
  },
  "runtime": {
    "manager_runtime_observed": "${MANAGER_RUNTIME}",
    "worker_runtime_contract": "${WORKER_RUNTIME_CONTRACT}",
    "worker_resources_declared_stopped": ${WORKER_RESOURCES_DECLARED_STOPPED},
    "worker_runtime_observed": "${WORKER_RUNTIME_OBSERVED}",
    "worker_containers_observed": ${WORKER_COUNT},
    "proof_flow_worker_containers_running": ${PROOFFLOW_RUNNING_COUNT}
  },
  "container_socket": {
    "docker_context_class": "${DOCKER_CONTEXT_CLASS}",
    "colima_running": ${COLIMA_RUNNING},
    "colima_daemon_local_socket_present": ${COLIMA_DAEMON_SOCKET},
    "controller_socket_present": ${CONTROLLER_SOCKET},
    "controller_docker_api_ping_ok": ${DOCKER_SOCKET_API}
  },
  "resolver": {
    "backup_present": ${RESOLVER_BACKUP_PRESENT},
    "backup_first_line_has_invalid_dash_e_prefix": ${RESOLVER_BACKUP_INVALID_PREFIX},
    "current_syntax_allowlist_ok": ${RESOLVER_CURRENT_SYNTAX},
    "normalized_backup_matches_current": ${RESOLVER_NORMALIZED_MATCH},
    "resolver_addresses_emitted": false,
    "resolver_file_hashes_emitted": false,
    "verification_status": "${RESOLVER_VERIFICATION_STATUS}"
  },
  "images": [
    {
      "component": "controller-embedded",
      "tag": "${EMBEDDED_TAG}",
      "reference_local_image_id": "${EMBEDDED_LOCAL_IMAGE_ID}",
      "observed_local_image_id": $(json_nullable_string "${EMBEDDED_OBSERVED}"),
      "local_image_id_matches_reference": ${EMBEDDED_LOCAL_ID_MATCH},
      "reference_repo_digest": "${EMBEDDED_REPO_DIGEST}",
      "observed_repo_digest": $(json_nullable_string "${EMBEDDED_REPO_OBSERVED}"),
      "repo_digest_matches_reference": ${EMBEDDED_REPO_MATCH}
    },
    {
      "component": "manager-openclaw",
      "tag": "${MANAGER_TAG}",
      "reference_local_image_id": "${MANAGER_LOCAL_IMAGE_ID}",
      "observed_local_image_id": $(json_nullable_string "${MANAGER_OBSERVED}"),
      "local_image_id_matches_reference": ${MANAGER_LOCAL_ID_MATCH},
      "reference_repo_digest": "${MANAGER_REPO_DIGEST}",
      "observed_repo_digest": $(json_nullable_string "${MANAGER_REPO_OBSERVED}"),
      "repo_digest_matches_reference": ${MANAGER_REPO_MATCH}
    },
    {
      "component": "worker-openclaw",
      "tag": "${WORKER_TAG}",
      "reference_local_image_id": "${WORKER_LOCAL_IMAGE_ID}",
      "observed_local_image_id": $(json_nullable_string "${WORKER_OBSERVED}"),
      "local_image_id_matches_reference": ${WORKER_LOCAL_ID_MATCH},
      "reference_repo_digest": "${WORKER_REPO_DIGEST}",
      "observed_repo_digest": $(json_nullable_string "${WORKER_REPO_OBSERVED}"),
      "repo_digest_matches_reference": ${WORKER_REPO_MATCH}
    }
  ],
  "health_checks": [
    {"check_id": "controller-container", "status": "${CONTROLLER_CONTAINER_STATUS}", "expected_http_status": null, "http_status": null, "observation": ${CONTROLLER_CONTAINER}},
    {"check_id": "controller-api", "status": "${CONTROLLER_STATUS}", "expected_http_status": "200", "http_status": "${CONTROLLER_HTTP}", "observation": null},
    {"check_id": "minio-live", "status": "${MINIO_STATUS}", "expected_http_status": "200", "http_status": "${MINIO_HTTP}", "observation": null},
    {"check_id": "matrix-versions", "status": "${MATRIX_STATUS}", "expected_http_status": "200", "http_status": "${MATRIX_HTTP}", "observation": null},
    {"check_id": "higress-matrix-route", "status": "${GATEWAY_STATUS}", "expected_http_status": "200", "http_status": "${GATEWAY_HTTP}", "observation": null},
    {"check_id": "higress-console", "status": "${CONSOLE_STATUS}", "expected_http_status": "200", "http_status": "${CONSOLE_HTTP}", "observation": null},
    {"check_id": "element-web", "status": "${ELEMENT_STATUS}", "expected_http_status": "200", "http_status": "${ELEMENT_HTTP}", "observation": null},
    {"check_id": "controller-docker-socket-api", "status": "${SOCKET_STATUS}", "expected_http_status": null, "http_status": null, "observation": ${DOCKER_SOCKET_API}},
    {"check_id": "manager-container", "status": "${MANAGER_CONTAINER_STATUS}", "expected_http_status": null, "http_status": null, "observation": ${MANAGER_CONTAINER}},
    {"check_id": "manager-openclaw-gateway", "status": "${MANAGER_HEALTH_STATUS}", "expected_http_status": null, "http_status": null, "observation": ${MANAGER_HEALTH_OBSERVATION}}
  ],
  "summary": {
    "passed": ${PASSED},
    "failed": ${FAILED},
    "skipped": ${SKIPPED},
    "all_observed_components_healthy": ${ALL_HEALTHY},
    "all_six_proof_flow_workers_running": ${ALL_SIX_PROOFFLOW_WORKERS_RUNNING},
    "strict_collection_gate_passed": ${STRICT_COLLECTION_GATE_PASSED},
    "claim_level": "local-infrastructure-smoke-only"
  },
  "limitations": [
    "No ProofFlow Worker, Team, Human, Skill distribution, MCP authorization, Matrix collaboration, model inference, or end-to-end case execution was verified.",
    "A healthy endpoint proves point-in-time reachability only; it is not an availability, security, or production-readiness claim.",
    "Resolver evidence publishes only syntax and normalization booleans, not resolver contents or file hashes; it does not prove how an invalid line was originally introduced.",
    "The strict collection gate is a narrow consistency gate, not a security audit; it does not execute llm-preflight help, inspect secrets, or verify MCP and Worker integration."
  ]
}
EOF
)

VALIDATOR_ARGS=()
if [ "${STRICT}" -eq 1 ]; then
    VALIDATOR_ARGS+=(--strict)
fi
printf '%s\n' "${EVIDENCE_JSON}" | python3 "${VALIDATOR}" "${VALIDATOR_ARGS[@]}" -
VALIDATION_STATUS=$?
if [ "${VALIDATION_STATUS}" -ne 0 ]; then
    exit "${VALIDATION_STATUS}"
fi

if [ "${OUTPUT}" = "-" ]; then
    printf '%s\n' "${EVIDENCE_JSON}"
else
    if [ -e "${OUTPUT}" ]; then
        printf 'Refusing to overwrite existing output file.\n' >&2
        exit 2
    fi
    set -C
    if ! printf '%s\n' "${EVIDENCE_JSON}" >"${OUTPUT}"; then
        printf 'Could not create output file.\n' >&2
        exit 2
    fi
    set +C
fi

exit 0
