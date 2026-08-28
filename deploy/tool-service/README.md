# ProofFlow tool-service container

This image exposes the synthetic evidence-ingest, rule-retrieval, and deterministic-calculation
adapters. Evidence ingest writes only to a bounded in-memory registry. Runtime dependencies are
hash-locked, the Alpine `linux/amd64` base manifest is pinned by digest, and `pip` is removed after
installation to reduce final-image attack surface.

Build from the repository root:

```bash
docker build -f deploy/tool-service/Dockerfile -t proofflow-tool-service:0.1.0a0 .
```

For the AgentTeams embedded runtime, attach the container to `agentteams-net`. Supply a strong
Bearer token through the environment; never commit it or pass it as a command-line argument.

```bash
docker run -d --name proofflow-tool-service \
  --network agentteams-net \
  --network-alias proofflow-tool-service.local \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 256m \
  --cpus 1 \
  --env-file /absolute/private/path/proofflow-tool-api.env \
  proofflow-tool-service:0.1.0a0
```

The service is reference infrastructure, not a production perimeter. It has no TLS termination,
rate limiter, token rotation controller, or durable idempotency store. Put a trusted gateway in
front of it, keep the Docker network private, and accept only `PUBLIC_SYNTHETIC` fixtures.

The point-in-time CycloneDX/SPDX SBOMs, Trivy report, unsigned reproducible build-input hashes,
strict historical-consistency and v1.2 freshness contracts, fail-closed validator, exact tool pins,
atomic staged collector, and limitations are documented in
[SUPPLY_CHAIN_EVIDENCE.md](SUPPLY_CHAIN_EVIDENCE.md).

The committed 2026-08-20 evidence is historical and cannot authorize a release. No v1.2 evidence
or release-policy instance is committed; creating either requires a new exact-source image build
and database refresh. The disabled workflow design contains no publication step.
