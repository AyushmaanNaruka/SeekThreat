# apps/web

Next.js + TypeScript frontend.

## Screens

- Engagements — define target, authorization, scope
- Scan progress — live status
- Findings — filter, triage, provenance visible
- **Attack paths — interactive graph. Every edge clicks through to its evidence**
- Assistant — chat with citations
- Reports

## Rules

- Every score shows its breakdown on click. No opaque numbers.
- Every assistant answer shows its sources.
- Never render a metric we haven't measured.

## Running the dev server

Bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to see the result. `app/page.tsx` is the entry
point; the page hot-reloads as you edit.
