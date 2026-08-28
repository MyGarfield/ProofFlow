# Tool-service supply-chain evidence

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
historical consistency snapshot, not a current release scan. The validator's optional
`--release-gate` only rejects HIGH/CRITICAL records inside this snapshot; it does not enforce a
maximum age or prove that no newer advisory exists.

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

## Published artifacts

- `evidence/sbom.cyclonedx.json`: CycloneDX 1.7 SBOM, 937 components.
- `evidence/sbom.spdx.json`: SPDX 2.3 SBOM, 45 packages.
- `evidence/vulnerabilities.trivy.json`: Trivy JSON vulnerability report.
- `evidence/supply-chain-evidence.json`: subject, tool, database, artifact-hash, count, and
  limitation manifest.
- `evidence/supply-chain-evidence.schema.json`: strict Draft 2020-12 schema.

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
uv run python deploy/tool-service/scripts/collect_supply_chain_evidence.py
uv run python deploy/tool-service/scripts/validate_supply_chain_evidence.py
uv run pytest tests/contract/test_tool_service_supply_chain.py -q
```

The optional `--release-gate` rejects any recomputed HIGH or CRITICAL record, but still does not
check snapshot age. A real release must rebuild the exact image, refresh the database and evidence,
and enforce an explicit maximum-age policy before treating the result as a release decision.

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
