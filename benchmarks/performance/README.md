# Local HTTP performance benchmark

This package measures the local REST tool service with Python stdlib only. See
[`docs/08_PERFORMANCE_BENCHMARK.md`](../../docs/08_PERFORMANCE_BENCHMARK.md) for the protocol,
commands, report semantics, and limitations.

The default target is loopback, all request bodies are frozen public synthetic fixtures, and the
runner never calls an LLM or an external service. Results are a local single-run observation, not a
production SLA or capacity claim.
