# Fixed OCI verifier for the reference video

This directory contains a fixed `linux/amd64` OCI verifier for the synthetic
ProofFlow reference-runtime video. It is an evidence boundary, not a video
renderer and not proof of AgentTeams Worker or LLM execution.

## Security contract

`run.sh` rejects mutable tags and requires a registry-resolved child digest and
the separately observed image config digest. It checks both Docker
`Descriptor.digest` and `RepoDigests`, then sends `docker save --platform
linux/amd64` through `inspect_oci_archive.py`. The inspector reads the OCI
archive without extraction and verifies `oci-layout`, `index.json`, the
expected child manifest blob/media type, the config descriptor, and the config
blob SHA-256/size/platform/user. It uses only Python's standard library and
does not depend on `jq`.

It uses Docker with:

- `linux/amd64`, `--pull=never`, `--network none`, read-only rootfs;
- `65532:65532`, dropped capabilities, Docker's default seccomp profile and
  `no-new-privileges` (the launcher does not pass a host profile path);
- `--cpus 1`, `--memory 536870912`, no swap, `--pids-limit 128`, and
  `nofile=1024:1024`;
- a 64 MiB `tmpfs` at `/tmp` with `noexec,nosuid,nodev`;
- only two read-only bind mounts: the artifact at
  `/input/reference-video` and the Git repository at `/input/repo`.

There is no Docker socket, environment-file, host `PATH` tool lookup, or
network-capable Docker option. The in-image runner repeats the identity,
mount, capability, seccomp, network-route and cgroup checks.

The manifest's `tooling` object is retained as
`CAPTURE_TOOLING_PROVENANCE` (the original macOS capture tools). In OCI mode
the trusted validator receives a separate, externally pinned
`/etc/proofflow/toolchain.json`; it verifies fixed Linux tool paths, versions,
binary hashes, locale, Tesseract data and fonts before decoding. The legacy
validator invocation without that identity remains capture-exact.

## Build

Build from the repository root with the exact Dockerfile and platform:

```sh
docker build --platform linux/amd64 \
  -f deploy/reference-video-oci-verifier/Dockerfile \
  -t proofflow-reference-video-verifier:local \
  .
```

The Dockerfile pins the current Python Alpine `linux/amd64` child digest:

```text
python:3.12-alpine@sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb
```

Python wheels are selected from `requirements.lock` with hashes and only
binary wheels. Alpine package names and versions are in
`ALPINE_PACKAGES.lock`; the build preflights the v3.24 `main` and `community`
APKINDEX digests. The resulting image embeds the complete `/lib/apk/db/installed`
package closure digest and package list in `/etc/proofflow/toolchain.json`.

This does not yet claim a bit-for-bit reproducible rebuild: `apk add` resolves
through its configured repository and re-fetches the index after the preflight
download. The installed closure and preflight index digests make this drift
observable, but an offline bundle of exact `.apk` files is still required for a
reproducible release.

The image identity records the base child, artifact/schema/validator pins,
package-lock digests, platform, fixed tool paths, binary SHA-256 and versions,
JSON Schema version, locale inventory, Tesseract language data and font
inventory. The image config digest is deliberately not guessed during the
build. Docker 29 may report the child manifest digest for both `.Id` and
`.Descriptor.digest`; obtain the config digest from the saved OCI manifest's
`config.digest` (the inspector does this) and keep it separate from the
registry child manifest digest.

## Run and receipt

The launcher requires all pins explicitly. `IMAGE_REF` must contain the final
registry child digest (`name@sha256:...`), not a local tag. A local Docker build
normally has an empty `RepoDigests` list and is intentionally rejected; this
prevents a local candidate from masquerading as a registry-pinned image.

```sh
deploy/reference-video-oci-verifier/run.sh \
  --docker-bin /absolute/path/to/docker \
  --image ghcr.io/mygarfield/proofflow-reference-video-verifier@sha256:CHILD \
  --repo-root /absolute/path/to/ProofFlow \
  --artifact-root /absolute/path/to/ProofFlow/reference-video \
  --expected-artifact-commit 506c4d38de7fd6826dcc3170686668b4ed75ca25 \
  --expected-manifest-sha256 sha256:b427dc4eeeecc04f2d14e4c3e1a8059ac63e7c45c7054c86ebe772c88a1e01ac \
  --expected-schema-sha256 sha256:3af014e66ce304a5f205e5cb9b2900157d6469b72ff5601e1c7a1d447224c104 \
  --expected-validator-sha256 sha256:bba1e9d75c5694a148da96f77f2e431bc23ce1248e6bac3f3a1db3bca8940051 \
  --expected-image-digest sha256:CHILD \
  --expected-image-config-digest sha256:CONFIG \
  --receipt-output /absolute/private/path/receipt.json
```

The receipt is a closed JSON object validated against `receipt.schema.json` and
has a canonical payload integrity digest. It contains no host paths. A changed
receipt fails integrity verification. The command exits zero only for an
independently schema-valid `PASS`; `FAIL` and `UNKNOWN` both exit non-zero.

`blocked-build-receipt.json` is a committed negative contract fixture for an
unavailable-image failure. Its zero pins are intentional, its status is
`FAIL`, and its only check is `BLOCKED_BY_IMAGE_BUILD`; it does not describe
the current environment and is not a media or supply-chain result.

The runner independently recomputes ffprobe metadata and both full framemd5
streams. It executes fixed-path Tesseract with `eng+chi_sim`, but the macOS
manifest has no comparable OCR-output digest, so `observed.ocr_parity` remains
`UNKNOWN`; the check itself is `PASS / OCR_EXECUTION_OBSERVED` when the fixed
Linux OCR actually runs. Forbidden-claim scanning remains the trusted
validator's live OCR responsibility. Any Linux frame/audio mismatch is
`FAIL`; no threshold or video mutation is permitted.

## Local validation checkpoint (not a Draft exit)

On 2026-09-04, an isolated local-only registry resolved one candidate to OCI
child digest
`sha256:a33bdc1d9e98677ca6e4f61034d67cf4c711eb0a2688b3aed49703a63f2adb3e`
and config digest
`sha256:003fe877ac46415d049edddaf284e0b209b537d1a952dc9992e370ac5e4ac123`.
Two strict runs each returned 19/19 checks `PASS`; the persisted receipt has
SHA-256 `74dc4bbe8b572095c5c57fff2470b793a8729255b33984a14a05b48853f76b3f`.
This is local execution evidence only: the image was not published to an
external registry or independently downloaded, and `observed.ocr_parity`
remains `UNKNOWN` by design.

## Draft boundary

The OCI implementation and contract tests do not create a portable verifier
receipt by themselves. The video PR remains Draft until a separate trusted
environment builds and resolves the image, records child and config digests,
downloads the exact image, runs this launcher against the exact artifact
commit, and preserves the resulting receipt. A run with a local tag, mutable
child, writable mount, host tool, missing security profile, timeout or output
limit cannot satisfy that gate.
