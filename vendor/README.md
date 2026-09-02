# vendor/

**All third-party code lives here. Nowhere else in the tree.**

This makes borrowed code visible in every diff. Code copied into `services/` or `apps/`
disappears — and in month six, when we write the attribution appendix, nobody remembers it.

## Rules

1. **Only permissive licences.** MIT, BSD, Apache-2.0. Never AGPL or GPL.
2. **One directory per project**, named for the project.
3. **Keep their LICENSE file** inside that directory. Unmodified.
4. **Add a `THIRD_PARTY.md` row in the same PR.** CI fails the build otherwise.
5. **Note your modifications** in a `MODIFICATIONS.md` inside the directory.

## Layout

```
vendor/
  <project-name>/
    LICENSE           their original, untouched
    MODIFICATIONS.md  what we changed and why
    ...their code
```

If you're about to copy from an AGPL or GPL project: don't. Read it, understand it, write our
own. See `docs/01-open-source-policy.md`.
