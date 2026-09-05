# services/assistant

Retrieval, narration, and citations. The only place a language model is called.

## The firewall

This package may import `packages.schema` and nothing else from this repository.
No `services.graph`, no `services.enrichment`, no `services.scanners`.

It receives proven `AttackPath` objects as data and returns text. It cannot create
an edge, because it cannot reach the code that creates edges. This is enforced by
`tests/architecture/test_import_firewall.py`, which fails CI on any violating import.

If you find yourself needing to import the graph builder here, the design is wrong.
The path should be passed in as an argument.

## Rules

1. The model narrates paths that already exist. It never infers them.
2. Every answer carries `Citation` objects pointing at observations, findings or paths.
3. When the data does not support an answer, say so. "I don't have that data" is a
   correct answer and the golden dataset grades for it.
