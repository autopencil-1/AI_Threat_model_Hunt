"""Dev/offline stub connectors. Replace with real XSOAR/ServiceNow + Splunk/Sentinel adapters."""

from __future__ import annotations


class StdoutApprovalQueue:
    """Collects submissions and returns deterministic ticket ids (no randomness — replayable)."""

    def __init__(self):
        self.submitted: list[dict] = []

    def submit(self, artifact: dict) -> str:
        self.submitted.append(artifact)
        ticket = f"TCK-{len(self.submitted):04d}"
        print(f"[approval-queue] submitted {artifact.get('type')} ({artifact.get('graph')}) -> {ticket}")
        return ticket


class NullTelemetry:
    def query(self, q: str) -> list[dict]:
        return []
