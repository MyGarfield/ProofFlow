"use strict";

(function configure(factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  if (typeof document !== "undefined") {
    const recordGeometry = () => {
      document.documentElement.dataset.horizontalOverflow = String(
        api.hasHorizontalOverflow(document.documentElement),
      );
    };
    document.addEventListener("DOMContentLoaded", recordGeometry, { once: true });
    window.addEventListener("resize", recordGeometry, { passive: true });
  }
})(function createPublicSnapshotApi() {
  const EXPECTED_SOURCE_COMMIT = "2edfe55d88abac3cc4d56dc74375b698dce7a476";

  function hasHorizontalOverflow(root) {
    return root.scrollWidth > root.clientWidth;
  }

  function hasExactStaticBoundary(snapshot) {
    return Boolean(
      snapshot &&
        snapshot.source &&
        snapshot.source.commit === EXPECTED_SOURCE_COMMIT &&
        snapshot.landing &&
        snapshot.landing.included_in_source_commit === false &&
        snapshot.landing.self_authenticating === false &&
        snapshot.runtime_boundary &&
        snapshot.runtime_boundary.workers === "Stopped" &&
        snapshot.runtime_boundary.readyWorkers === 0 &&
        snapshot.runtime_boundary.llm_enabled === false &&
        snapshot.evaluation_boundary &&
        snapshot.evaluation_boundary.status === "PROTOCOL_VALIDATED_NOT_EXECUTED" &&
        snapshot.supply_chain_boundary &&
        snapshot.supply_chain_boundary.status === "STALE" &&
        snapshot.supply_chain_boundary.release_eligible === false &&
        snapshot.non_claims &&
        snapshot.non_claims.execution_receipt_implemented === true &&
        snapshot.non_claims.outcome_closure_implemented === true &&
        snapshot.non_claims.operator_handoff_signed === false &&
        snapshot.non_claims.same_process_observer_is_independent_truth === false &&
        snapshot.non_claims.indexes_process_local_only === true,
    );
  }

  return Object.freeze({
    EXPECTED_SOURCE_COMMIT,
    hasExactStaticBoundary,
    hasHorizontalOverflow,
  });
});
