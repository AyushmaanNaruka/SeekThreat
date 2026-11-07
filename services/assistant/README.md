# services/assistant

Retrieval, narration, and citations. The only place a language model is called.

## The firewall

This package may import `packages.schema` and nothing else from this repository.
No `services.graph`, no `services.enrichment`, no `services.scanners`, no `apps.api`.

It receives proven `AttackPath` objects as data and returns text. It cannot create
an edge, because it cannot reach the code that creates edges. This is enforced by
`tests/architecture/test_import_firewall.py`, which fails CI on any violating import
(both a deny-list of the edge-building packages and an allow-list: `packages.schema`
is the only repo-internal import permitted).

If you find yourself needing to import the graph builder here, the design is wrong.
The path should be passed in as an argument.

## Rules

1. The model narrates paths that already exist. It never infers them.
2. Every answer carries `Citation` objects pointing at observations, findings or paths.
3. When the data does not support an answer, say so. "I don't have that data" is a
   correct answer and the golden dataset grades for it.

## Modules

| Module | Public API |
|---|---|
| `interfaces.py` | `ModelClient`, `VectorStore` protocols (the contract) |
| `client.py` | `OllamaModelClient`, `FakeModelClient`, `ModelUnavailableError` |
| `documents.py` | `observation_document`, `enriched_finding_document`, `path_document`, `chokepoint_document`, `topology_document`, `documents_for_engagement` |
| `retrieval.py` | `InMemoryVectorStore`, `Retriever`, `extract_terms` |
| `citations.py` | `parse_citation_ids`, `build_citations`, `check_grounding` |
| `answer.py` | `answer_question`, `REFUSAL_TEXT` |
| `narration.py` | `narrate_path` |
| `prompts.py` | system prompts and document framing shared by the above |

## Chunking: one fact per document

Every retrievable unit is one record with one citable id (DECISIONS.md D-048), so a
citation resolves to exactly one thing the analyst can open:

| Document | `doc_id` | `kind` |
|---|---|---|
| Observation | `obs:sha256:...` (the observation id) | `observation` |
| Enriched finding | `finding:<finding_id>` | `finding` |
| Attack path | `path:...` (the path id) | `path` |
| Chokepoint | `chokepoint:<finding_id>` | `finding` |
| Declared topology | `topology:sha256:...` | `topology` |

The ids match the evidence ids the graph engine puts on edges (`obs:...`,
`finding:...`, `topology:...`), so every piece of path evidence is itself a citable
document. Builders are pure: no clock, no randomness, no model. The same record always
produces the same bytes. Finding documents name the source of every fused value
("CVSS 9.8 (cve.org, high confidence)") and carry the ERS with its component
explanations; a missing score says "not scored", never 0. Path documents render each
step as `from -[rule_name, confidence]-> to: description` with its evidence ids, and
mark assumption steps (`Assumed, not observed`) as `ASSUMPTION`.

## Hybrid retrieval

Security questions turn on exact identifiers, and embeddings blur them
(CVE-2021-41773 and CVE-2021-42013 embed almost identically). So `Retriever.retrieve`:

1. extracts exact terms from the question (`extract_terms`: CVE ids, IPv4/IPv6
   addresses, `port/proto`, bare ports after "port", host-name-like tokens);
2. takes lexical hits first, ranked by how many distinct terms a document contains
   (whole-identifier matching: `172.20.1.1` never matches `172.20.1.13`). Method is
   `lexical`, or `hybrid` if vector search also found the document;
3. fills remaining slots with vector hits scoring at least `min_vector_score` (cosine);
4. de-duplicates, orders deterministically (ties by `doc_id`), caps at `limit`.

Everything is scoped to one `engagement_id`; no query can see another engagement's
documents. `InMemoryVectorStore` is the reference store; the pgvector store (D-005)
lives in `apps/api` and must behave the same.

## Refusal policy

- **Nothing retrieved**: refuse with `REFUSAL_TEXT` and reason
  `nothing relevant retrieved`. The model is not called.
- **Model refuses**: the system prompt tells it to reply exactly `REFUSAL_TEXT` when the
  documents do not answer the question. If the reply contains that sentence the answer is
  `refused=True`, text normalised to `REFUSAL_TEXT`, no citations.
- The model is told never to invent CVEs, hosts, attack steps or paths, and that an
  attack path exists only if a `path` document says so.

## Grounding check

After generation, deterministically (no model):

- citation markers `[cite:<doc_id>]` are parsed; ids that were not supplied are listed
  in `GroundingCheck.invalid_citations` and never become `Citation` objects;
- every exact entity in the text (same `extract_terms`) must appear in a document the
  text actually cites, or in the question. Anything else is listed in
  `unsupported_entities`.

`grounded` is true only when both lists are empty. The check flags; it does not
rewrite the answer. The analyst sees the flags.

## Path narration

`narrate_path` sends the model exactly one path (rendered from its own edges) and the
evidence documents supplied for it. It is told to narrate the steps in order, add
nothing, label assumption steps as assumptions, and cite. Post-check: the grounding
check against the path document and the evidence, plus a stricter CVE check: a CVE id
in the narration that is not on this path's edges or in the evidence those edges cite
is flagged even if some other supplied document mentions it. The `AttackPath` is never
mutated; narration comes back as a separate `PathNarration`.

## Models

`OllamaModelClient` calls `/api/chat` (temperature 0, seed 0, no streaming) and
`/api/embed`, strips `<think>...</think>` blocks from reasoning-model output, and maps
connection errors, timeouts, non-200 responses and malformed bodies to
`ModelUnavailableError` (D-006). `FakeModelClient` is deterministic (hashed
bag-of-words embeddings, echo-the-first-document generation) and records every call;
it is for tests and CI only.
