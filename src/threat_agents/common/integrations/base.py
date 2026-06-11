"""Stage-0 integration adapter interfaces (B7).

The system must deliver into tools the SOC already runs — gates publish into the existing
approval queue (XSOAR/ServiceNow), telemetry is read via existing SIEM/EDR APIs under existing
RBAC. Graphs depend only on these Protocols; concrete connectors live alongside.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ApprovalQueueAdapter(Protocol):
    def submit(self, artifact: dict) -> str:
        """Publish an artifact into the human approval queue; return a ticket/correlation id."""
        ...


@runtime_checkable
class TelemetryAdapter(Protocol):
    def query(self, q: str) -> list[dict]:
        """Read-only query against already-authorized telemetry (does NOT gate; relevant from D5)."""
        ...
