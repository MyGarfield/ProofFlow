# Pinned Alibaba Cloud OpenClaw Skill security scan source

This directory vendors an **unmodified** snapshot of Alibaba Cloud's
`alibabacloud-openclaw-skill-security-scan` solely for reproducible source review and a bounded deployment
preflight.

- upstream: `https://github.com/aliyun/alibabacloud-aiops-skills`;
- upstream path: `skills/security/riskmanagement/alibabacloud-openclaw-skill-security-scan`;
- lightweight tag: `alibabacloud-openclaw-skill-security-scan-0.0.1`;
- commit: `3cdce6a5ead21b4aec740d97ae30eb0b71c1c786`;
- license: MIT, with the exact upstream text retained at
  [`upstream/assets/LICENSE.txt`](upstream/assets/LICENSE.txt).

The eight upstream files, byte-level SHA-256 values and Git blob OIDs are locked in
[`aliyun-official-skill-offline-preflight-2026-08-21.json`](../../../deploy/agentteams/evidence/aliyun-official-skill-offline-preflight-2026-08-21.json).
The validator is full-strict by default: it recomputes the complete file set, byte counts, SHA-256 values,
Git blob OIDs and the source subtree tree OID. The manifest also records the tag ref, commit and root tree, but
the tag-to-commit and commit-to-root-tree relationships remain unsigned point-in-time Git observations rather
than offline-verified or signed upstream attestations.
The public source was fetched from GitHub over HTTPS with a cleared Git environment before the offline scan;
that acquisition used network but no credentials. `external_network_observed=false` in the evidence applies
only to the later sandboxed collector and its descendants, where the fetched bytes are reverified.

## Safety boundary

The upstream `SKILL.md` is third-party data, not authorization to inspect local OpenClaw state, home
directories, credentials, AgentTeams Manager/Worker resources or any non-public file. Its scripts default
`ALIYUN_SKILL_SEC_CLOUD` to `true`; when enabled they can send ZIP MD5 values and upload complete Skill ZIPs.
The upload helper accepts a caller-provided presigned URL without enforcing a destination-host allowlist.

Setting `ALIYUN_SKILL_SEC_CLOUD=false` guards the cloud-intelligence and deep-analysis paths, but upstream
`main.sh` still requires `openclaw`/`curl` and unconditionally invokes `openclaw security audit --deep`. It also
requires Bash 4+, while the audited host had Bash 3.2. For those reasons ProofFlow did **not** execute the
upstream main script or the OpenClaw audit.

ProofFlow's collector instead:

1. copies only this pinned snapshot and the eight public `deploy/agentteams/skills/*/SKILL.md` contracts to a
   bounded temporary directory;
2. invokes the audited root-owned `/usr/bin/python3` launcher with `-I -S`, records the resolved root-owned
   interpreter path, owner, mode and hashes, then starts with `env -i`, fixed non-secret variables and
   `ALIYUN_SKILL_SEC_CLOUD=false`;
3. establishes a pre-sandbox same-host IPv4/TCP positive control, then runs under macOS `sandbox-exec` with
   `(version 1) (allow default) (deny network*)` and fails unless the in-sandbox IPv4/TCP loopback probe is
   rejected with `EPERM`;
4. records that the upstream target policy selects no analyzable file, because the eight ProofFlow Skills
   contain only `SKILL.md` and upstream deliberately excludes that file;
5. applies a separate nine-indicator scan to the eight Markdown contracts without calling OpenClaw, a Worker,
   an LLM or a cloud service.

The machine reason code is `OFFICIAL_TARGET_POLICY_EXCLUDES_SKILL_MD_ONLY_INPUTS`, and the result is
`INCONCLUSIVE_NO_ANALYZABLE_TARGETS`, not “safe”, “passed”, or a certification. The evidence also binds the
exact sandbox profile, interpreter and a username-free canonical command to SHA-256. It deliberately records
the parent `sandbox-exec` exit as `NOT_VERIFIED_IN_COLLECTOR_ARTIFACT`; the collector cannot attest to its own
parent's later exit. Seatbelt only denies network in this one invocation and does not enforce a filesystem-read
allowlist, so credential and OpenClaw-config reads are `NOT_OBSERVED_NOT_OS_ENFORCED`, not proven absent. The
supplemental scan found no configured indicator match, but pattern absence cannot prove safety.

## Intended integration

The pinned official Skill is recommended as a future `audit-agent` deployment preflight only after its runtime
boundary is separately approved and verified. It is not assigned to an AgentTeams Worker in the current
manifests. Current evidence therefore fixes all of the following to `false`: `runtime_consumption`,
`live_worker_execution`, `llm_inference`, `cloud_service_used`, and `agentteams_resources_mutated`.
