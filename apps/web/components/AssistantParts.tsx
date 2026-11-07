"use client";

/**
 * Rendering for model-written text (assistant answers and path narrations):
 * citation chips, the cited-records list and the grounding warning. Shared by
 * AssistantView and AttackPathsView.
 */

import React, { useMemo } from "react";
import { parseEvidenceId, shortEvidenceLabel } from "../lib/attackGraph";
import { citedIdsInOrder, isGrounded, renderSegments } from "../lib/assistant";
import type { Citation, GroundingCheck } from "../lib/assistant";
import type { OpenEvidence } from "./PathParts";

function CiteChip({
  docId,
  n,
  invalid,
  context,
  onOpen,
}: {
  docId: string;
  n: number;
  invalid: boolean;
  context: string;
  onOpen: OpenEvidence;
}) {
  const ref = parseEvidenceId(docId);
  const cls = `as-chip ${invalid ? "as-chip-invalid" : ""}`;
  if (ref.kind === "unknown") {
    return (
      <span className={`${cls} as-chip-unknown`} title={`Unrecognized citation id: ${docId}`}>
        [{n}]
      </span>
    );
  }
  return (
    <button
      type="button"
      className={cls}
      title={`${invalid ? "Not among the records supplied to the model. " : ""}Open ${ref.kind} ${docId}`}
      onClick={() => onOpen(ref, context)}
    >
      [{n}]
    </button>
  );
}

/**
 * Model text with every `[cite:<doc_id>]` marker replaced by a numbered chip
 * (numbered by first appearance). Clicking a chip opens the cited record.
 */
export function CitedText({
  text,
  grounding,
  citations,
  context,
  onOpen,
}: {
  text: string;
  grounding: GroundingCheck;
  citations: Citation[];
  context: string;
  onOpen: OpenEvidence;
}) {
  const segments = useMemo(() => renderSegments(text), [text]);
  const order = useMemo(() => citedIdsInOrder(segments), [segments]);
  const excerpts = useMemo(() => new Map(citations.map((c) => [c.ref_id, c])), [citations]);
  // Citations the server listed that the text never marks inline still belong in the list.
  const extra = citations.filter((c) => !order.includes(c.ref_id));
  return (
    <>
      <div className="as-text">
        {segments.map((s, i) =>
          s.type === "text" ? (
            <React.Fragment key={i}>{s.text}</React.Fragment>
          ) : (
            <CiteChip
              key={i}
              docId={s.docId}
              n={s.n}
              invalid={grounding.invalid_citations.includes(s.docId)}
              context={context}
              onOpen={onOpen}
            />
          )
        )}
      </div>
      {order.length + extra.length > 0 && (
        <div className="as-citations">
          <div className="ap-subhead">Cited records</div>
          <ol className="as-cite-list">
            {order.map((id, i) => (
              <CitationRow
                key={id}
                n={i + 1}
                id={id}
                citation={excerpts.get(id) ?? null}
                invalid={grounding.invalid_citations.includes(id)}
                context={context}
                onOpen={onOpen}
              />
            ))}
            {extra.map((c, i) => (
              <CitationRow
                key={c.ref_id}
                n={null}
                id={c.ref_id}
                citation={c}
                invalid={grounding.invalid_citations.includes(c.ref_id)}
                context={context}
                onOpen={onOpen}
                ordinal={order.length + i + 1}
              />
            ))}
          </ol>
        </div>
      )}
    </>
  );
}

function CitationRow({
  n,
  id,
  citation,
  invalid,
  context,
  onOpen,
  ordinal,
}: {
  n: number | null;
  id: string;
  citation: Citation | null;
  invalid: boolean;
  context: string;
  onOpen: OpenEvidence;
  ordinal?: number;
}) {
  const ref = parseEvidenceId(id);
  return (
    <li className="as-cite-row" value={n ?? ordinal}>
      <div className="as-cite-head">
        {ref.kind === "unknown" ? (
          <span className="ap-evidence ap-evidence-unknown" title={`Unrecognized citation id: ${id}`}>
            unrecognized: {id}
          </span>
        ) : (
          <button
            type="button"
            className={`ap-evidence ap-evidence-${ref.kind}`}
            title={`Open ${ref.kind} ${id}`}
            onClick={() => onOpen(ref, context)}
          >
            <span className="ap-evidence-kind">{ref.kind === "observation" ? "obs" : ref.kind}</span>
            {shortEvidenceLabel(ref)}
          </button>
        )}
        {n === null && <span className="ap-badge ap-badge-neutral">listed, not marked in the text</span>}
        {invalid && <span className="ap-badge ap-badge-low">not among the supplied records</span>}
      </div>
      {citation?.excerpt ? (
        <div className="as-excerpt">{citation.excerpt}</div>
      ) : (
        <div className="ap-muted as-excerpt-none">No excerpt returned for this citation.</div>
      )}
    </li>
  );
}

/** Visible warning when the deterministic grounding check found anything. Nothing otherwise. */
export function GroundingWarning({ grounding }: { grounding: GroundingCheck }) {
  if (isGrounded(grounding)) {
    return (
      <div className="as-grounded ap-muted">
        Grounding check: every CVE id, IP address and port in this text appears in the records it cites
        {grounding.checked_entities.length > 0 ? ` (${grounding.checked_entities.length} checked)` : " (none mentioned)"}
        .
      </div>
    );
  }
  return (
    <div className="ap-warn as-ground-warn" role="alert">
      <strong>Grounding check failed.</strong> Treat the text above with caution and rely on the cited records.
      {grounding.unsupported_entities.length > 0 && (
        <div>
          Not found in the cited records:{" "}
          {grounding.unsupported_entities.map((e) => (
            <code key={e} className="ap-mono as-entity">
              {e}
            </code>
          ))}
        </div>
      )}
      {grounding.invalid_citations.length > 0 && (
        <div>
          Citations to records that were not supplied to the model:{" "}
          {grounding.invalid_citations.map((e) => (
            <code key={e} className="ap-mono as-entity">
              {e}
            </code>
          ))}
        </div>
      )}
    </div>
  );
}
