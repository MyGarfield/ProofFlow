# AgentTeams v1.2.2 local patches

These patches target upstream AgentTeams tag `v1.2.2`, commit
`849182af8e017168a5a200a87b1062142caf462d`. AgentTeams declares the Apache License 2.0 in its
root `LICENSE`; the small modified source excerpts in these patch files remain subject to that
license. ProofFlow is not claiming upstream authorship, endorsement, or merge status.

| Patch | ProofFlow modification | Runtime claim |
|---|---|---|
| `v1.2.2-macos-colima-daemon-socket.patch` | Use the daemon-local socket only for Darwin + Colima installer detection | Local checkout compatibility patch; not an upstream fix |
| `v1.2.2-embedded-higress-console-url.patch` | Permit an explicit Higress Console URL while preserving the loopback default | Local embedded compatibility patch; not an upstream fix |
| `v1.2.2-llm-preflight-help-redaction.patch` | Keep secret env values out of Cobra flag defaults and resolve the API key only in `RunE` | Candidate security fix only; the currently observed v1.2.2 image was not rebuilt with it |

Review and check a patch before any manual application:

```bash
test "$(git -C /path/to/AgentTeams-v1.2.2 rev-parse HEAD)" = \
  849182af8e017168a5a200a87b1062142caf462d
git -C /path/to/AgentTeams-v1.2.2 apply --check \
  /path/to/ProofFlow/deploy/agentteams/patches/PATCH_NAME.patch
```

The `llm-preflight` patch includes Go tests for these security properties:

1. `--help`, `agt help llm-preflight`, Bash/Zsh completion, command errors, and every recursive
   Cobra flag default/value do not contain an API-key sentinel supplied by env;
2. an env-only key is read only at command execution and reaches an isolated httptest HTTP
   Authorization header;
3. an explicitly changed flag preserves the existing flag-over-env precedence;
4. an HTTP error body containing the key remains redacted.

Run the scoped upstream tests after applying it to a disposable clean checkout:

```bash
cd /path/to/AgentTeams-v1.2.2/agentteams-controller
go test ./cmd/agt -run 'TestLLMPreflight' -count=1
```

The repeatable source-only verifier is
[`scripts/verify-llm-preflight-patch.sh`](../scripts/verify-llm-preflight-patch.sh). It requires a clean
local checkout at the pinned commit, creates its own disposable clone, runs `git apply --check`, applies
the patch, and runs only the scoped Go tests with `GOPROXY=off GOSUMDB=off` (a missing module cache fails
closed rather than downloading). It emits no source path, test output, sentinel, or runtime configuration.
The machine evidence is
[`evidence/llm-preflight-patch-verification-2026-08-21.json`](../evidence/llm-preflight-patch-verification-2026-08-21.json)
with patch SHA-256
`5974fdcf569ae8a70392a151cec8ed38407408cdd5e0e9b556f732427b470567`.
This is source-level patch evidence only; it does not say the observed Controller or Manager image
contains the change.

Until a rebuilt binary containing the fix is verified, immediately revoke and rotate every credential
that may have reached captured help, completion, error, log, or evidence output. Do not run the live
v1.2.2 `agt llm-preflight` help/completion paths, pass a key with `--api-key`, inspect full container
env/process state, or capture raw preflight output. This candidate patch is not deployed. Workers and
LLM calls remain disabled until the Manager is rebuilt and replaced, a new SBOM and vulnerability scan
are verified for that replacement, and the patched runtime is separately verified. Only then may the
Worker-start gate be considered.
