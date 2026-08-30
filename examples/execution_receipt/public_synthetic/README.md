# PUBLIC_SYNTHETIC local observer fixture

The executable fixture is constructed by
[`tests/unit/test_execution_receipt.py`](../../../tests/unit/test_execution_receipt.py). It creates
ephemeral Ed25519 keys in memory and verifies this closed local flow:

1. an ActionCertificate is signed by distinct synthetic issuer and Human-approval roots;
2. `verify_action_certificate` accepts and process-locally reserves it;
3. a distinct synthetic `EXECUTION_OBSERVER` signs one exact-byte ExecutionReceipt;
4. `verify_execution_receipt` cross-checks the exact ActionCertificate envelope, canonical result
   digest, trusted expected binding, observer independence, and append-only index;
5. the local receipt keeps model invocation, usage, cost, and effect evidence `UNKNOWN` and records
   only an observer-evidenced duration.

Keys are generated per test run; no private signing key is committed. The fixture contains no real
person, organization, tenant, case, prompt, provider operation, network endpoint, Worker, LLM,
MCP/A2A/OTLP connection, or external side effect. It is a contract and attack fixture, not a
production attestation.
