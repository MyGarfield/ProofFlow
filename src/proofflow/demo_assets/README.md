# ProofFlow installed CLI demo

This directory contains only frozen, fictional `PUBLIC_SYNTHETIC` inputs. It is not legal
advice, does not measure legal accuracy, does not call an LLM or AgentTeams Worker, and cannot
perform an external business-system side effect.

From this directory, run:

```bash
proofflow prepare \
  --manifest case/manifest.json \
  --rules rules/cn_labor_contract_law.catalog.json \
  --run-dir run

proofflow approve \
  --run-dir run \
  --approver-id synthetic-reviewer \
  --role legal-reviewer \
  --decision APPROVE \
  --reason "Reviewed the synthetic evidence, rules, calculation, risks, and uncertainties."

proofflow package --run-dir run
proofflow verify --run-dir run
```

`prepare` must stop at `AWAITING_APPROVAL`; approval is never inferred or simulated. Successful
verification returns `"valid": true`.

The repository-only browser demo and its Git-bound validator are not part of the installed
distribution contract.
