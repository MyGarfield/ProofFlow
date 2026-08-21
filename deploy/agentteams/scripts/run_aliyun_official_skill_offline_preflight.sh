#!/bin/sh
# Run the bounded Aliyun Skill preflight under an OS-level egress deny.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
source_root="$repo_root/third_party/aliyun/alibabacloud-openclaw-skill-security-scan/upstream"
skills_root="$repo_root/deploy/agentteams/skills"

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <RFC3339-collected-at>" >&2
    exit 2
fi
collected_at=$1

if [ "$(uname -s)" != "Darwin" ] || [ ! -x /usr/bin/sandbox-exec ]; then
    echo "offline collection requires macOS sandbox-exec network denial" >&2
    exit 1
fi

if [ -x /usr/local/bin/python3 ]; then
    python_bin=/usr/local/bin/python3
elif [ -x /usr/bin/python3 ]; then
    python_bin=/usr/bin/python3
else
    echo "python3 is unavailable" >&2
    exit 1
fi

task_tmp=$(/usr/bin/mktemp -d /tmp/proofflow-aliyun-official-skill-gate.XXXXXX)
case "$task_tmp" in
    /tmp/proofflow-aliyun-official-skill-gate.*) ;;
    *) echo "unexpected temporary directory" >&2; exit 1 ;;
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
    echo "symlinked scan input is forbidden" >&2
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
    PROOFFLOW_NETWORK_SANDBOX=macos-sandbox-exec-deny-network-v1 \
    /usr/bin/sandbox-exec \
    -p '(version 1) (allow default) (deny network*)' \
    "$python_bin" "$task_tmp/collector.py" \
    --source-root "$task_tmp/source" \
    --skills-root "$task_tmp/skills" \
    --collected-at "$collected_at"
sandbox_exit_code=$?
set -e

if [ "$sandbox_exit_code" -ne 0 ]; then
    echo "sandboxed collector failed" >&2
    exit "$sandbox_exit_code"
fi

exit 0
