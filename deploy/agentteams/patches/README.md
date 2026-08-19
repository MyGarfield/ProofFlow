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

The `llm-preflight` patch includes Go tests for three security properties:

1. `--help` and the Cobra `Flag.DefValue` do not contain an API-key sentinel supplied by env;
2. an env-only key is still read at command execution and reaches the HTTP Authorization header;
3. an explicitly changed flag preserves the existing flag-over-env precedence.

Run the scoped upstream tests after applying it to a disposable clean checkout:

```bash
cd /path/to/AgentTeams-v1.2.2/agentteams-controller
go test ./cmd/agt -run 'TestLLMPreflight' -count=1
```

During ProofFlow authoring on 2026-08-20, this patch passed `git apply --check` against the pinned
commit and the scoped Go command above passed in a disposable local clone. That is source-level patch
evidence only; it does not say the observed Controller or Manager image contains the change.

Until a rebuilt binary containing the fix is verified, rotate any credential that may have reached
captured help output. Do not run `agt llm-preflight --help`, `agt help llm-preflight`, completion/help
generators, `--api-key`, full container-env inspection, or environment-bearing process listings.
For a required preflight, rely on the already configured container environment, suppress raw output,
and retain only a fixed PASS/FAIL result:

```bash
if docker exec agentteams-manager agt llm-preflight --strict >/dev/null 2>&1; then
  printf '%s\n' 'LLM_PREFLIGHT=PASS'
else
  printf '%s\n' 'LLM_PREFLIGHT=FAIL'
fi
```

This command does not pass a key in host argv; it uses the container's already configured environment.
It is a containment measure, not a binary fix. Do not capture raw command output. If static help is
unavoidable, first remove the secret only for that process with
`docker exec agentteams-manager env -u AGENTTEAMS_LLM_API_KEY agt llm-preflight --help` and still do
not archive the output. The public evidence collector never invokes the vulnerable help path.
