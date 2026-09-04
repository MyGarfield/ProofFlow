# syntax=docker/dockerfile:1.7
# Build only for the immutable amd64 child, never for a multi-platform index.
FROM --platform=linux/amd64 python:3.12-alpine@sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb

ARG ARTIFACT_COMMIT=290ef94caf96cf3f1e4568cf8f19a52a8b460bc0
ARG MANIFEST_SHA256=sha256:d031c112d517d1a6931c97fed6fc667a7fd2fd29872e04d901829b6bcfe2b92a
ARG SCHEMA_SHA256=sha256:3af014e66ce304a5f205e5cb9b2900157d6469b72ff5601e1c7a1d447224c104
ARG VALIDATOR_SHA256=sha256:bba1e9d75c5694a148da96f77f2e431bc23ce1248e6bac3f3a1db3bca8940051
ARG MAIN_APKINDEX_SHA256=sha256:d06e04b2a46b8f669cd1fa5244ed3786a63efd41d9a2403433a9e6a21d9d7ce1
ARG COMMUNITY_APKINDEX_SHA256=sha256:d5fda4c2f0c2ed5c537a1a3aeeb7e642e5aabf7e22b2ae2be9d99d341f1fcef7

LABEL org.opencontainers.image.title="ProofFlow reference-video OCI verifier" \
      org.opencontainers.image.description="Fixed, fail-closed linux/amd64 verifier for synthetic reference evidence" \
      org.opencontainers.image.base.name="python:3.12-alpine" \
      org.opencontainers.image.base.digest="sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb" \
      org.proofflow.platform="linux/amd64" \
      org.proofflow.artifact.commit="$ARTIFACT_COMMIT" \
      org.proofflow.manifest.sha256="$MANIFEST_SHA256" \
      org.proofflow.schema.sha256="$SCHEMA_SHA256" \
      org.proofflow.validator.sha256="$VALIDATOR_SHA256"

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    PYTHONNOUSERSITE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin

WORKDIR /opt/proofflow

COPY deploy/reference-video-oci-verifier/requirements.lock /opt/proofflow/requirements.lock
COPY deploy/reference-video-oci-verifier/ALPINE_PACKAGES.lock /opt/proofflow/ALPINE_PACKAGES.lock

# The index bytes are checked before resolution.  Package names and versions
# are separately committed in ALPINE_PACKAGES.lock; a changed index fails the
# build instead of silently selecting another package set.
RUN set -eux; \
    apk_arch="$(apk --print-arch)"; test "$apk_arch" = "x86_64"; \
    printf '%s\n%s\n' \
      https://dl-cdn.alpinelinux.org/alpine/v3.24/main \
      https://dl-cdn.alpinelinux.org/alpine/v3.24/community \
      > /etc/apk/repositories; \
    wget -q -O /tmp/main-index.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/APKINDEX.tar.gz; \
    echo "${MAIN_APKINDEX_SHA256#sha256:}  /tmp/main-index.tar.gz" | sha256sum -c -; \
    wget -q -O /tmp/community-index.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.24/community/x86_64/APKINDEX.tar.gz; \
    echo "${COMMUNITY_APKINDEX_SHA256#sha256:}  /tmp/community-index.tar.gz" | sha256sum -c -; \
    apk add --no-cache --no-progress $(sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' /opt/proofflow/ALPINE_PACKAGES.lock); \
    rm -f /tmp/main-index.tar.gz /tmp/community-index.tar.gz

RUN python -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      --only-binary=:all: \
      --require-hashes \
      --requirement /opt/proofflow/requirements.lock \
    && python -m pip uninstall --yes pip \
    && python -c "import importlib.util; assert importlib.util.find_spec('pip') is None"

COPY deploy/reference-video-oci-verifier/runner.py /opt/proofflow/runner.py
COPY deploy/reference-video-oci-verifier/policy.py /opt/proofflow/policy.py
COPY deploy/reference-video-oci-verifier/build_identity.py /opt/proofflow/build_identity.py
COPY deploy/reference-video-oci-verifier/receipt.schema.json /opt/proofflow/receipt.schema.json

RUN set -eux; \
    mkdir -p /etc/proofflow; \
    python /opt/proofflow/build_identity.py \
      --output /etc/proofflow/toolchain.json \
      --artifact-commit "$ARTIFACT_COMMIT" \
      --manifest-sha256 "$MANIFEST_SHA256" \
      --schema-sha256 "$SCHEMA_SHA256" \
      --validator-sha256 "$VALIDATOR_SHA256" \
      --alpine-lock /opt/proofflow/ALPINE_PACKAGES.lock \
      --python-lock /opt/proofflow/requirements.lock; \
    sha256sum /opt/proofflow/runner.py | cut -d ' ' -f 1 > /etc/proofflow/runner.sha256; \
    rm -f /opt/proofflow/build_identity.py /opt/proofflow/ALPINE_PACKAGES.lock /opt/proofflow/requirements.lock; \
    chmod 0444 /etc/proofflow/toolchain.json /etc/proofflow/runner.sha256 /opt/proofflow/receipt.schema.json

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/python3.12", "/opt/proofflow/runner.py"]
