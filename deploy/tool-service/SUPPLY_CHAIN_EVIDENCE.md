# Tool-service supply-chain evidence

> **Current status: historical snapshot, stale for this branch.** ActionCertificate v0.1 adds
> `cryptography`, `cffi`, and `pycparser` and changes the copied `src/` tree. The published image,
> SBOMs, Trivy report, image digest, and build-input hashes predate those changes. They remain a
> pinned historical record and are not evidence for the current build, a current release image,
> or release safety. This branch intentionally does not rebuild the image or rewrite those
> artifacts. A later release must rebuild, rescan, and independently bind fresh evidence.

Document status: `HISTORICAL_POINT_IN_TIME_PACKAGE_SCAN / UNSIGNED_INPUT_HASHES`

## Point-in-time result

The published evidence set covers the `linux/amd64` image observed on 2026-08-20,
`proofflow-tool-service:0.1.0a0` with image ID
`sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775`.
The Dockerfile pins the official Python platform manifest directly:

`python:3.12-alpine@sha256:285a71327884a4d50efbea30104473b0fa43ecefa499458899670ca30dae76e5`

The snapshot image uses Alpine 3.24.1. It installs the hash-locked runtime dependencies and then
uninstalls `pip`; the build fails if the `pip` module remains importable. Runtime behavior is not a
field in this evidence Schema: the machine manifest explicitly records
`runtime_container_inspected=false` and must not be cited as proof of the runtime profile or HTTP
behavior.

The snapshot Trivy report contains zero vulnerability records at every reported severity:

| UNKNOWN | LOW | MEDIUM | HIGH | CRITICAL |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 0 | 0 | 0 | 0 |

This means that the pinned scanner and database did not report a known package vulnerability in
this image at collection time. It is not a claim that the image is vulnerability-free, secure in
production, or free from future advisories.

## Pinned tools and database

Official immutable release pages identify Syft v1.51.0 as released on 2026-08-10 and Trivy
v0.74.0 as released on 2026-08-14:

- [Anchore Syft v1.51.0](https://github.com/anchore/syft/releases/tag/v1.51.0)
- [Aqua Security Trivy v0.74.0](https://github.com/aquasecurity/trivy/releases/tag/v0.74.0)

| Tool | Version | Multi-platform index digest | Resolved `linux/amd64` manifest |
| --- | --- | --- | --- |
| Syft | 1.51.0 | `sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0` | `sha256:41f8289664101d6ebab30a97ac8df6b6f86b92d8343285ca90f428e2bc353106` |
| Trivy | 0.74.0 | `sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969` | `sha256:ee940acbf1f58ebadb42d01434ce4609530bf1b52536afbd1eee66cd7123c5c9` |

The Trivy database used by the snapshot report was updated at
`2026-08-20T07:02:00.71353677Z`. Its unpacked database hash is
`sha256:97c9b035c6d1685c9406ec4500d08d38214734136f23fcccd400833ec9cafbba`.
The complete database is not committed; its version, update/download times, byte count, and hash
are recorded in the evidence manifest.

The database declared its next update at `2026-08-21T07:02:00Z`. As of 2026-08-29 this is a
historical consistency snapshot, not a current release scan. Consistency mode reports
`release_eligible=false`; release mode rejects Schema v1.1 with the stable code
`HISTORICAL_SCHEMA_NOT_RELEASE_ELIGIBLE` before considering any finding count. It does not prove
that no newer advisory exists.

## Unsigned build-input hashes

Schema version 1.1 records strict SHA-256 and byte-count entries for `.dockerignore`, the
Dockerfile, the hash-locked requirements, notices and licenses, plus deterministic directory-bundle
hashes for `src` and `data/rules`. The validator recomputes all eight entries from repository bytes
and rejects missing, reordered, duplicated, unexpected, or changed inputs. The directory hash uses
sorted relative paths with explicit unsigned 64-bit big-endian path/content lengths before each
byte sequence.

These hashes make the local input snapshot independently recomputable. They are not digital
signatures, SLSA provenance, a registry attestation, or cryptographic proof that a registry image
was produced from those inputs. The manifest therefore records both
`hashes_are_digital_signatures=false` and `build_relationship_attested=false`.

## Published historical artifacts

- `evidence/sbom.cyclonedx.json`: CycloneDX 1.7 SBOM, 937 components.
- `evidence/sbom.spdx.json`: SPDX 2.3 SBOM, 45 packages.
- `evidence/vulnerabilities.trivy.json`: Trivy JSON vulnerability report.
- `evidence/supply-chain-evidence.json`: subject, tool, database, artifact-hash, count, and
  limitation manifest.
- `evidence/supply-chain-evidence.schema.json`: strict Draft 2020-12 contract accepting the frozen
  v1.1 historical shape and the separately gated v1.2 release-binding shape.
- `evidence/supply-chain-release-policy.schema.json`: strict external policy shape for v1.2 release
  verification. It is a schema, not a policy instance and not release evidence.

Artifact SHA-256 values and byte counts live in `supply-chain-evidence.json`. The semantic
validator recomputes them, reconciles both SBOMs and the Trivy report, verifies severity and target
summaries from the raw report, checks the non-root image config, enforces the exact tool/base image
pins, and rejects claim escalation plus the repository's selected private-path, entrant-data and
credential patterns. Public upstream package attribution such as maintainer metadata is not treated
as entrant private data.

## Reproduce and validate

The collector requires Docker, outbound registry access for the isolated Trivy database download,
and the exact subject image already built locally. It exports only the image to an archive. Neither
scanner receives the Docker socket. The networked Trivy phase does not mount the target; target
analysis runs with `--network none`, `--offline-scan`, and `--skip-db-update`. Its task-specific
temporary Docker volume is removed after collection.

```bash
uv run python deploy/tool-service/scripts/validate_supply_chain_evidence.py --mode consistency
uv run python deploy/tool-service/scripts/validate_supply_chain_evidence.py \
  --mode release \
  --release-policy /approved/external/release-policy.json \
  --release-policy-sha256 'sha256:<independently-approved-policy-digest>'
uv run pytest tests/contract/test_tool_service_supply_chain.py -q
```

可安装发行包的 release builder 也必须使用同一组显式、外部绑定的 v1.2 输入。它会原样调用上面的
validator；policy 文件的 SHA-256 必须由独立信任域提供，builder 不从 policy 内容自报或推导摘要：

```bash
uv run --frozen python scripts/build_installable_distribution.py \
  --output /approved/new/proofflow-release \
  --release \
  --supply-chain-evidence /approved/evidence/supply-chain-evidence-v1.2.json \
  --release-policy /approved/policy/release-policy-v1.2.json \
  --release-policy-sha256 'sha256:<independently-approved-policy-digest>'
```

builder release 缺少任一显式输入，或 validator 拒绝 v1.1/stale evidence、错误 policy pin、HIGH/CRITICAL
finding 时，流程 fail closed 且不创建 output 目录。`--evidence` 是 evidence 参数的兼容别名；包版本
`0.1.0a0`、版本/tag 与 registry 发布仍是独立门禁，不由此 release gate 自动满足。成功构建的
`artifact-manifest.json` 只在 `supply_chain_release_gate_receipt` 中记录 validator 返回的
`evidence_file_sha256`、`evidence_set_id`、`evidence_schema_version=1.2.0`、`mode=release` 和外部
`release_policy_sha256`，不写 evidence/policy 本机路径。builder 在 validator 前后通过 no-follow
regular-file FD 稳定读取并比较 bytes/stat；验证完成后路径替换不会改写已捕获 receipt，但原始
evidence/policy 文件必须留存，供 receipt 复核。validator subprocess 设有 300 秒 timeout 和 16 KiB
stdout 上限。output 目录同样通过持有的 no-follow directory FD
创建/打开，以 `O_CREAT|O_EXCL|O_NOFOLLOW` 发布、fsync，并在完成前复核路径 inode 与精确成员闭集；
rename、symlink、sentinel 或覆盖竞态会以 `BUILD_OUTPUT_RACE_DETECTED` 拒绝。

The first command validates the exact v1.1 historical manifest, raw artifacts and historical
build-input snapshot, then returns `HISTORICAL_CONSISTENT_STALE` with
`release_eligible=false`. `--expect-stale-build-inputs` remains only as a compatibility assertion
for that v1.1 path. The second command intentionally fails because v1.1 can never become release
eligible. No release-policy instance is committed.

The collector is not run by ordinary CI. When an operator deliberately runs it, it writes a v1.2
candidate into a same-filesystem staging directory, validates consistency, and only then promotes
the directory. It cannot accept or create a release policy and cannot assert release eligibility.
A different trust domain must review the candidate, fix an external policy and independently pass
the exact policy-file SHA-256 to a later release-verifier invocation. A scan, refresh, or validation
failure leaves the previous historical directory intact. This repository change did not run the
networked collector and did not rewrite any SBOM or Trivy report.

## v1.2 freshness and release binding contract

No v1.2 evidence instance is committed. The schema and verifier define what a later exact-build
run must produce:

- one scan window, exact source commit and tree, deterministic aggregate build-input digest,
  immutable image subject and platform;
- one exact raw-artifact set, vulnerability-database identity and explicit refresh result;
- one `evidence_set_id` recomputed over those fields with canonical JSON SHA-256;
- an external policy binding the expected source, build-input digest, subject, exact SHA-256/media
  type/byte count for every raw artifact, exact database identity and timestamps, and the expected
  `evidence_set_id`;
- maximum ages of six hours for the completed snapshot and 24 hours for the database, a maximum
  30-minute scan window and at most five minutes of future clock skew;
- strict `now < database.next_update`; equality is refresh-due, while equality at a maximum-age or
  duration limit remains valid;
- recomputation of HIGH/CRITICAL findings from the bound raw Trivy report.

Only library callers and tests may inject `now`. The production CLI has no `--now` option and uses
the system UTC clock. A path-based production policy is rejected unless its raw file bytes match a
separately supplied `sha256:<64hex>` trust anchor. A self-consistent digest inside evidence is not
an external trust anchor. Release validation checks all policy pins before the finding decision and
fails closed with stable codes for missing/invalid policy, historical schema, timestamp order,
future skew, expired snapshot/database, due or failed database refresh,
source/build/subject/artifact/binding mismatch, and HIGH/CRITICAL findings.

The disabled workflow design in `.github/workflows/release-supply-chain-evidence.yml` documents the
intended exact-SHA sequence, separate external policy digest input and approval environment. It has
no publication step and cannot publish historical or merely consistency-valid evidence.

## Rejected Debian baseline and remediation

The previous Debian 13.6 image
`sha256:fef1b1c05aa7ac403ce2d85a992ce3a70001d86c4a7a41a478de8fad7996a42e`
was rejected after the same Trivy version reported 191 package-advisory records: 4 CRITICAL, 22
HIGH, 68 MEDIUM, 67 LOW, and 30 UNKNOWN. All 26 HIGH/CRITICAL records were Debian OS packages; no
Python package was HIGH or CRITICAL. The 4 CRITICAL records were `perl-base 5.40.1-6` advisories.
Nine HIGH records were `CVE-2026-53615` across util-linux binary packages with Debian fix
`2.41.5-0+deb13u1`; the remaining HIGH/CRITICAL records were affected or fix-deferred advisories
for gzip, libacl, ncurses, OpenSSL, and Perl packages.

Updating to the then-current official `python:3.12-slim` image did not reduce those counts. The
official pinned Alpine platform candidate reduced the report to four MEDIUM and one LOW record,
all from runtime-unneeded `pip 25.0.1`, while preserving the locked `pydantic-core` musllinux wheel
and passing the image HTTP flow. Removing `pip` produced the snapshot zero-record report.

The rejected Debian and intermediate Alpine raw reports are not included in this repository. The
counts and package examples in this remediation narrative are operator-maintained historical
observations and cannot be independently reproduced from the final-image evidence bundle alone;
only the current final-image result is schema-bound to the published raw artifacts.

The switch replaces glibc with musl. Repository tests cover the current dependency set, but dynamic
container behavior is separate evidence; future native dependencies, DNS/locale behavior, and
performance still require regression testing.

## Boundaries

This package scan does not inspect running-container environment values or credentials. Trivy does
record the public image configuration embedded in the archive; the validator restricts its
environment variable names to the expected Python/runtime allowlist and rejects a runtime API-token
key. The scan does not assess dynamic behavior, exploitability, application logic, TLS/gateway
configuration, orchestration policy, registry signatures, signed build provenance, or production
deployment security. Database and scanner false positives, false negatives, and coverage gaps
remain possible. The unsigned build-input hashes bind this manifest to local repository bytes at
collection time, but do not attest the build relationship between those bytes and the image. A new
image build requires new input hashes, SBOMs, vulnerability evidence, and cross-bound runtime
evidence before it may be called the current release image.
