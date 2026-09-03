# Fixed OCI verifier for the reference video

This directory contains a fixed `linux/amd64` OCI verifier for the synthetic
ProofFlow reference-runtime video. It is an evidence boundary, not a video
renderer and not proof of AgentTeams Worker or LLM execution.

## Security contract

`run.sh` rejects mutable tags and requires a registry-resolved child digest and
the separately observed image config digest. It uses Docker with:

- `linux/amd64`, `--pull=never`, `--network none`, read-only rootfs;
- `65532:65532`, dropped capabilities, default seccomp and
  `no-new-privileges`;
- `--cpus 1`, `--memory 536870912`, no swap, `--pids-limit 128`, and
  `nofile=1024:1024`;
- a 64 MiB `tmpfs` at `/tmp` with `noexec,nosuid,nodev`;
- only two read-only bind mounts: the artifact at
  `/input/reference-video` and the Git repository at `/input/repo`.

There is no Docker socket, environment-file, host `PATH` tool lookup, or
network-capable Docker option. The in-image runner repeats the identity,
mount, capability, seccomp, network-route and cgroup checks.

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
build: obtain it from an exact post-build `docker image inspect .Id` and keep
it separate from the registry child manifest digest.

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
  --expected-artifact-commit 69faa8ae7884c6cf69e583488e39afac4b9cd052 \
  --expected-manifest-sha256 sha256:9bfd38adab4bd05418ff137b615741956ba1c365d26f01accbf62a85d4075bba \
  --expected-schema-sha256 sha256:3af014e66ce304a5f205e5cb9b2900157d6469b72ff5601e1c7a1d447224c104 \
  --expected-validator-sha256 sha256:759b57258662b6e2e7e612a1235b650f70d65f107903e77a78dd0f51a7cd3654 \
  --expected-image-digest sha256:CHILD \
  --expected-image-config-digest sha256:CONFIG \
  --receipt-output /absolute/private/path/receipt.json
```

The receipt is a closed JSON object validated against `receipt.schema.json` and
has a canonical payload integrity digest. It contains no host paths. A changed
receipt fails integrity verification. The command exits zero only for an
independently schema-valid `PASS`; `FAIL` and `UNKNOWN` both exit non-zero.

The runner independently recomputes ffprobe metadata and both full framemd5
streams. It executes fixed-path Tesseract with `eng+chi_sim`, but the macOS
manifest has no comparable OCR-output digest, so OCR parity remains
`UNKNOWN`. Any Linux frame/audio mismatch is `FAIL`; no threshold or video
mutation is permitted.

## Draft boundary

The OCI implementation and contract tests do not create a portable verifier
receipt by themselves. The video PR remains Draft until a separate trusted
environment builds and resolves the image, records child and config digests,
downloads the exact image, runs this launcher against the exact artifact
commit, and preserves the resulting receipt. A run with a local tag, mutable
child, writable mount, host tool, missing security profile, timeout or output
limit cannot satisfy that gate.
