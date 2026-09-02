# SeekThreat — agent rules

Antigravity and other AI coding agents: the project rules live in **[CLAUDE.md](./CLAUDE.md)**.

Read that file before generating code. It is the single source of truth for this repo's
constraints, and it is kept deliberately in one place so the rules cannot drift apart
between tools.

Quick summary of the non-negotiables, in case you read nothing else:

1. **The LLM never creates graph edges.** Attack paths are built deterministically by the
   rules engine. The model narrates proven paths, it never infers them.
2. **No scanning without an authorization record.** Test targets come from `lab/` only.
3. **Never copy code from AGPL or GPL projects.** Copy only from MIT/BSD/Apache, only into
   `vendor/`, and always with a `THIRD_PARTY.md` entry in the same change.
4. **No autonomous exploitation.** Report and reference exploits, never execute them.

Everything else — architecture, stack, conventions — is in `CLAUDE.md`.
