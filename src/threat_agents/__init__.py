"""Threat-modeling & threat-hunting agents.

Stage 1 (built): D1 STRIDE/PASTA + D3 recursive AND/OR attack-trees — independent,
framework-as-state-machine LangGraph graphs, each with its own critic, on a lightweight
versioned ATT&CK reference index. No dispatcher / substrate / cross-task coupling: those
are Stage 2+ and gated behind the offline decision spike. See ../../IMPLEMENTATION_STRATEGY.md.
"""

__version__ = "0.1.0"
