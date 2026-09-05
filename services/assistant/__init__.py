"""Retrieval, narration and citations.

This package may import `packages.schema` and NOTHING ELSE from this repository.
It receives AttackPath objects as data and returns text. It cannot construct a
graph edge because it cannot reach the code that constructs edges.

Enforced by tests/architecture/test_import_firewall.py.
"""
