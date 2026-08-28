#!/bin/sh
# Run the bounded Aliyun Skill preflight under an OS-level egress deny.

set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

script_dir=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && /bin/pwd -P)
source_root="$repo_root/third_party/aliyun/alibabacloud-openclaw-skill-security-scan/upstream"
skills_root="$repo_root/deploy/agentteams/skills"

if [ "$#" -ne 1 ]; then
    printf 'usage: %s <RFC3339-collected-at>\n' "$0" >&2
    exit 2
fi
collected_at=$1

if [ "$(/usr/bin/uname -s)" != "Darwin" ] || [ ! -x /usr/bin/sandbox-exec ]; then
    printf '%s\n' "offline collection requires macOS sandbox-exec network denial" >&2
    exit 1
fi

python_bin=/usr/bin/python3
expected_python_sha256=179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818
if [ ! -x "$python_bin" ]; then
    printf '%s\n' "root-owned system python3 is unavailable" >&2
    exit 1
fi
python_uid=$(/usr/bin/stat -f '%u' "$python_bin")
python_gid=$(/usr/bin/stat -f '%g' "$python_bin")
python_mode=$(/usr/bin/stat -f '%Lp' "$python_bin")
python_sha256=$(
    /usr/bin/env -i PATH="$PATH" HOME=/var/empty LANG=C LC_ALL=C \
        /usr/bin/shasum -a 256 "$python_bin" | /usr/bin/cut -d ' ' -f 1
)
if [ "$python_uid" != 0 ] || [ "$python_gid" != 0 ] || [ "$python_mode" != 755 ]; then
    printf '%s\n' "system python3 ownership or mode differs from the audited boundary" >&2
    exit 1
fi
if [ "$python_sha256" != "$expected_python_sha256" ]; then
    printf '%s\n' "system python3 launcher digest differs from the audited boundary" >&2
    exit 1
fi
if ! /usr/bin/env -i PATH="$PATH" HOME=/var/empty LANG=C LC_ALL=C \
    "$python_bin" -I -S -c \
    'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'
then
    printf '%s\n' "root-owned isolated system python3 is too old" >&2
    exit 1
fi

task_tmp=$(/usr/bin/mktemp -d /tmp/proofflow-aliyun-official-skill-gate.XXXXXX)
case "$task_tmp" in
    /tmp/proofflow-aliyun-official-skill-gate.*) ;;
    *) printf '%s\n' "unexpected temporary directory" >&2; exit 1 ;;
esac

cleanup() {
    case "$task_tmp" in
        /tmp/proofflow-aliyun-official-skill-gate.*)
            /bin/chmod -R u+w "$task_tmp" 2>/dev/null || true
            /bin/rm -rf "$task_tmp"
            ;;
    esac
}
trap cleanup EXIT HUP INT TERM

if [ -n "$(/usr/bin/find "$source_root" "$skills_root" -type l -print -quit)" ]; then
    printf '%s\n' "symlinked scan input is forbidden" >&2
    exit 1
fi

/bin/mkdir -p "$task_tmp/source" "$task_tmp/skills"
/bin/cp -R "$source_root/." "$task_tmp/source/"
/bin/cp "$script_dir/collect_aliyun_official_skill_evidence.py" "$task_tmp/collector.py"

for skill_name in \
    conflict_detect \
    decision_audit \
    deterministic_calculate \
    document_package \
    evidence_ingest \
    human_approval \
    rule_retrieve \
    timeline_build
do
    /bin/cp -R "$skills_root/$skill_name" "$task_tmp/skills/$skill_name"
done

positive_control=$(
    /usr/bin/env -i \
        PATH="$PATH" \
        HOME=/var/empty \
        LANG=C \
        LC_ALL=C \
        "$python_bin" -I -S "$task_tmp/collector.py" --positive-control-only
)
if [ "$positive_control" != "LOOPBACK_IPV4_TCP_CONNECT_SUCCEEDED" ]; then
    printf '%s\n' "pre-sandbox IPv4 TCP positive control failed" >&2
    exit 1
fi

set +e
/usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    HOME=/var/empty \
    TMPDIR="$task_tmp" \
    LANG=C \
    LC_ALL=C \
    ALIYUN_SKILL_SEC_CLOUD=false \
    REPORT_LANG=zh \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PROOFFLOW_NETWORK_POSITIVE_CONTROL="$positive_control" \
    PROOFFLOW_NETWORK_SANDBOX=macos-sandbox-exec-deny-network-v1 \
    /usr/bin/sandbox-exec \
    -p '(version 1) (allow default) (deny network*)' \
    "$python_bin" -I -S "$task_tmp/collector.py" \
    --source-root "$task_tmp/source" \
    --skills-root "$task_tmp/skills" \
    --collected-at "$collected_at"
sandbox_exit_code=$?
set -e

if [ "$sandbox_exit_code" -ne 0 ]; then
    printf '%s\n' "sandboxed collector failed" >&2
    exit "$sandbox_exit_code"
fi

exit 0
