# Contributing

## Branches

```
main            always working
feat/<thing>    features
fix/<thing>     fixes
docs/<thing>    documentation
```

Branch from `main`. One review before merge. Keep PRs small enough that someone will actually
read them.

## Commits

```
feat: add nuclei scanner adapter
fix: correct CPE version comparison for tilde ranges
docs: update enrichment source table
refactor: extract path scoring from graph builder
test: add dedup cases for cross-scanner findings
chore: bump celery
```

## Before you open a PR

- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `mypy packages services` passes
- [ ] `pytest tests` passes, including `tests/architecture`
- [ ] New logic in `services/graph` or `services/enrichment` has tests
- [ ] No secrets, no real target hostnames, no scan output committed
- [ ] `THIRD_PARTY.md` updated if you touched `vendor/`
- [ ] `DECISIONS.md` updated if this diverges from the scope doc

## Things that will get a PR sent back

- Third-party code outside `vendor/`
- Code copied from an AGPL or GPL project
- Anything letting a scan run without an authorization record
- LLM output used to construct graph edges
- Fabricated metrics or placeholder data presented as measured results
- Weakening or skipping a test in `tests/architecture/` instead of fixing the violation

## Review

Reviewing means reading it, not approving it. This applies especially to AI-generated code —
generated code nobody read is how a subtle bug survives to December.

Look for: does it hold the three hard rules? Is data provenance preserved? Would this still
make sense in four months?
