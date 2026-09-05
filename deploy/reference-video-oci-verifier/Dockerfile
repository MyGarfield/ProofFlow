# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Build only for the immutable amd64 child, never for a multi-platform index.
ARG SOURCE_DATE_EPOCH=1788519180
FROM --platform=linux/amd64 python:3.12-alpine@sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb
ARG SOURCE_DATE_EPOCH

ARG ARTIFACT_COMMIT=290ef94caf96cf3f1e4568cf8f19a52a8b460bc0
ARG MANIFEST_SHA256=sha256:d031c112d517d1a6931c97fed6fc667a7fd2fd29872e04d901829b6bcfe2b92a
ARG SCHEMA_SHA256=sha256:3af014e66ce304a5f205e5cb9b2900157d6469b72ff5601e1c7a1d447224c104
ARG VALIDATOR_SHA256=sha256:bba1e9d75c5694a148da96f77f2e431bc23ce1248e6bac3f3a1db3bca8940051
ARG APK_CLOSURE_LOCK_SHA256=sha256:80cc09b5b86f8f3a6b55ab9495b65fbf1f0919fc30b8b2a3597324438595d5b5
ARG WHEEL_CLOSURE_LOCK_SHA256=sha256:2b826aceb2a3c536e602dc6907fc1ddce860987138398478ccec4595d04fe361

LABEL org.opencontainers.image.title="ProofFlow reference-video OCI verifier" \
      org.opencontainers.image.description="Fixed, fail-closed linux/amd64 verifier for synthetic reference evidence" \
      org.opencontainers.image.base.name="python:3.12-alpine" \
      org.opencontainers.image.base.digest="sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb" \
      org.proofflow.platform="linux/amd64" \
      org.proofflow.artifact.commit="$ARTIFACT_COMMIT" \
      org.proofflow.manifest.sha256="$MANIFEST_SHA256" \
      org.proofflow.schema.sha256="$SCHEMA_SHA256" \
      org.proofflow.validator.sha256="$VALIDATOR_SHA256" \
      org.proofflow.apk-closure.sha256="$APK_CLOSURE_LOCK_SHA256" \
      org.proofflow.wheel-closure.sha256="$WHEEL_CLOSURE_LOCK_SHA256"

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    PYTHONNOUSERSITE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin

WORKDIR /opt/proofflow

COPY deploy/reference-video-oci-verifier/requirements.lock /opt/proofflow/requirements.lock
COPY deploy/reference-video-oci-verifier/ALPINE_PACKAGES.lock /opt/proofflow/ALPINE_PACKAGES.lock
COPY deploy/reference-video-oci-verifier/apk-closure.lock.json /opt/proofflow/apk-closure.lock.json
COPY deploy/reference-video-oci-verifier/wheel-closure.lock.json /opt/proofflow/wheel-closure.lock.json

# The named context is prepared and signature-verified outside the build.  It
# is mounted read-only and never becomes an image layer.  All RUN networking is
# disabled by the caller and apk is independently forced into no-network mode.
RUN --mount=type=bind,from=verifier_inputs,source=.,target=/opt/proofflow-inputs,ro \
    set -eux; \
    apk_arch="$(apk --print-arch)"; test "$apk_arch" = "x86_64"; \
    echo "${APK_CLOSURE_LOCK_SHA256#sha256:}  /opt/proofflow/apk-closure.lock.json" | sha256sum -c -; \
    printf '%s\n%s\n' \
      file:///opt/proofflow-inputs/v3.24/main \
      file:///opt/proofflow-inputs/v3.24/community \
      > /etc/apk/repositories; \
    apk --no-network add --no-cache --no-progress \
      $(sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' /opt/proofflow/ALPINE_PACKAGES.lock); \
    rm -f /var/log/apk.log /var/cache/fontconfig/*

RUN --mount=type=bind,from=verifier_inputs,source=wheels,target=/opt/proofflow-wheels,ro \
    echo "${WHEEL_CLOSURE_LOCK_SHA256#sha256:}  /opt/proofflow/wheel-closure.lock.json" | sha256sum -c - \
    && python -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      --no-index \
      --find-links /opt/proofflow-wheels \
      --no-compile \
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
    rm -f /opt/proofflow/build_identity.py /opt/proofflow/ALPINE_PACKAGES.lock \
      /opt/proofflow/requirements.lock /opt/proofflow/apk-closure.lock.json; \
    rm -f /opt/proofflow/wheel-closure.lock.json; \
    chmod 0444 /etc/proofflow/toolchain.json /etc/proofflow/runner.sha256 /opt/proofflow/receipt.schema.json

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/python3.12", "/opt/proofflow/runner.py"]
