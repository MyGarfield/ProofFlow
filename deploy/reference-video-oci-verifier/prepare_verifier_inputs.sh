#!/bin/sh
# Prepare the byte-locked APK and wheel inputs before a network-disabled build.
set -eu

DOCKER_BIN="/usr/bin/docker"
REPO_ROOT=""
OUTPUT=""
BASE_IMAGE="python:3.12-alpine@sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb"

die() {
    printf 'proofflow verifier inputs: %s\n' "$1" >&2
    exit 2
}

usage() {
    cat >&2 <<'EOF'
usage: prepare_verifier_inputs.sh --repo-root ABSOLUTE_DIR --output ABSOLUTE_DIR
  [--docker-bin ABSOLUTE_DOCKER]
EOF
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --docker-bin) [ "$#" -ge 2 ] || usage; DOCKER_BIN="$2"; shift 2 ;;
        --repo-root) [ "$#" -ge 2 ] || usage; REPO_ROOT="$2"; shift 2 ;;
        --output) [ "$#" -ge 2 ] || usage; OUTPUT="$2"; shift 2 ;;
        --help|-h) usage ;;
        *) usage ;;
    esac
done

case "$DOCKER_BIN" in /*) ;; *) die "DOCKER_BIN_MUST_BE_ABSOLUTE" ;; esac
case "$REPO_ROOT" in /*) ;; *) die "REPO_ROOT_MUST_BE_ABSOLUTE" ;; esac
case "$OUTPUT" in /*) ;; *) die "OUTPUT_MUST_BE_ABSOLUTE" ;; esac
[ -x "$DOCKER_BIN" ] || die "DOCKER_BIN_UNAVAILABLE"
[ -d "$REPO_ROOT" ] && [ ! -L "$REPO_ROOT" ] || die "REPO_ROOT_INVALID"
[ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || die "OUTPUT_ALREADY_EXISTS"

OUTPUT_PARENT="$(/usr/bin/dirname "$OUTPUT")"
OUTPUT_NAME="$(/usr/bin/basename "$OUTPUT")"
[ -d "$OUTPUT_PARENT" ] && [ ! -L "$OUTPUT_PARENT" ] || die "OUTPUT_PARENT_INVALID"
case "$OUTPUT_NAME" in ""|.|..|*[!A-Za-z0-9._-]*) die "OUTPUT_NAME_INVALID" ;; esac
if /usr/bin/find "$OUTPUT_PARENT" -mindepth 1 -maxdepth 1 -print | /usr/bin/grep -q .; then
    die "OUTPUT_PARENT_MUST_BE_DEDICATED_EMPTY_DIRECTORY"
fi

INPUT_ROOT="$REPO_ROOT/deploy/reference-video-oci-verifier"
for input in fetch_apk_closure.py apk-closure.lock.json requirements.lock verify_wheel_closure.py wheel-closure.lock.json; do
    [ -f "$INPUT_ROOT/$input" ] && [ ! -L "$INPUT_ROOT/$input" ] || die "REQUIRED_INPUT_INVALID"
done

"$DOCKER_BIN" pull "$BASE_IMAGE" >/dev/null || die "BASE_IMAGE_PULL_FAILED"

if ! "$DOCKER_BIN" run --rm \
    --network bridge \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --cpus 1 \
    --memory 536870912 \
    --memory-swap 536870912 \
    --pids-limit 128 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --mount "type=bind,src=$INPUT_ROOT,dst=/input,ro" \
    --mount "type=bind,src=$OUTPUT_PARENT,dst=/output" \
    --env HOME=/nonexistent \
    --env PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin \
    "$BASE_IMAGE" /bin/sh -eu -c '
        target="/output/$1"
        python /input/fetch_apk_closure.py \
          --lock /input/apk-closure.lock.json --output "$target"
        mkdir -m 0700 "$target/wheels"
        python -m pip download \
          --disable-pip-version-check \
          --only-binary=:all: \
          --require-hashes \
          --requirement /input/requirements.lock \
          --dest "$target/wheels"
        python /input/verify_wheel_closure.py \
          --lock /input/wheel-closure.lock.json \
          --directory "$target/wheels"
    ' prepare-inputs "$OUTPUT_NAME"; then
    die "INPUT_PREPARATION_FAILED"
fi

[ -d "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || die "OUTPUT_NOT_CREATED"
if /usr/bin/find "$OUTPUT" -type l -o -name '*.part' | /usr/bin/grep -q .; then
    die "OUTPUT_CONTAINS_UNSAFE_MEMBER"
fi
printf '{"schema":"proofflow.reference-video.verifier-input-preparation.v1","status":"PASS"}\n'
