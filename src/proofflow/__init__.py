"""ProofFlow's deterministic reference core.

This package is an early, synthetic-data-only implementation. It is not a legal
decision maker and it does not perform external side effects.
"""

from proofflow.models import SCHEMA_VERSION

__all__ = ["SCHEMA_VERSION"]
__version__ = "0.1.0a1"
