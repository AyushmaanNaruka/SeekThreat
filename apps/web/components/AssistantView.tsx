"use client";

/**
 * Assistant (Layer 4) for the selected engagement: index the engagement's records,
 * ask questions, and read answers whose every claim is a clickable citation to a
 * real record. The model answers from retrieved records only; it never creates
 * attack paths (Hard Rule 1). Conversation is in memory only.
 */

import React, { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../lib/api";
import type { EngagementItem } from "../lib/api";
import { parseEvidenceId, shortEvidenceLabel } from "../lib/attackGraph";
import { formatSimilarity, isGrounded, modelListed } from "../lib/assistant";
import type { Answer, AssistantStatus, IndexResult } from "../lib/assistant";
import { describeError, isAbortError, useEvidencePanel } from "./EvidencePanel";
import type { OpenEvidence } from "./PathParts";
import { CitedText, GroundingWarning } from "./AssistantParts";

interface AssistantViewProps {
  activeEngagement: EngagementItem | null;
  onSelectEngagementPrompt?: () => void;
}

type StatusState =
  | { status: "loading" }
  | { status: "ok"; data: AssistantStatus }
  | { status: "error"; message: string };

type IndexState =
  | { status: "loading" }
  | { status: "ok"; result: IndexResult }
  | { status: "error"; message: string };

type TurnState =
  | { status: "pending" }
  | { status: "answer"; answer: Answer }
  /** 409: the engagement has no retrieval index yet. */
  | { status: "not-indexed"; message: string }
  /** 503: the model server could not be reached. */
  | { status: "unavailable"; message: string }
  | { status: "error"; message: string };

interface Turn {
  id: number;
  question: string;
  state: TurnState;
}

function OllamaHelp({ baseUrl, model, embedModel }: { baseUrl: string | null; model: string | null; embedModel: string | null }) {
  return (
    <div className="as-help">
      To start the model server: run <code className="ap-mono">ollama serve</code>
      {baseUrl ? (
        <>
          {" "}
          so it listens on <code className="ap-mono">{baseUrl}</code>
        </>
      ) : null}
      , then pull the models with{" "}
      <code className="ap-mono">ollama pull {model ?? "<model>"}</code> and{" "}
      <code className="ap-mono">ollama pull {embedModel ?? "<embed model>"}</code>. Press Recheck when it is up.
    </div>
  );
}

function StatusLine({ state, onRecheck }: { state: StatusState; onRecheck: () => void }) {
  return (
    <div className="db-card ap-card as-status">
      <div className="as-status-row">
        <span className="ap-subhead" style={{ margin: 0 }}>
          Model server
        </span>
        {state.status === "loading" && <span className="ap-muted">Checking…</span>}
        {state.status === "ok" && (
          <>
            <span className={`as-dot ${state.data.reachable ? "as-dot-ok" : "as-dot-down"}`} aria-hidden="true" />
            <span>{state.data.reachable ? "reachable" : "unreachable"}</span>
            <span className="ap-muted">·</span>
            <span>
              model <code className="ap-mono">{state.data.model}</code>
            </span>
            <span className="ap-muted">·</span>
            <span>
              embedding model <code className="ap-mono">{state.data.embed_model}</code>
            </span>
            <span className="ap-muted ap-mono">{state.data.ollama_base_url}</span>
          </>
        )}
        <button type="button" className="ap-linkbtn as-push" onClick={onRecheck} disabled={state.status === "loading"}>
          Recheck
        </button>
      </div>
      {state.status === "error" && (
        <div className="ap-error" role="alert">
          <span>{state.message}</span>
        </div>
      )}
      {state.status === "ok" && !state.data.reachable && (
        <div className="ap-warn as-col" role="status">
          <div>
            The model server at <code className="ap-mono">{state.data.ollama_base_url}</code> did not respond.
            {state.data.message ? ` Server: ${state.data.message}` : ""} Questions will fail until it is up.
          </div>
          <OllamaHelp baseUrl={state.data.ollama_base_url} model={state.data.model} embedModel={state.data.embed_model} />
        </div>
      )}
      {state.status === "ok" && state.data.reachable && (
        <MissingModels data={state.data} />
      )}
    </div>
  );
}

function MissingModels({ data }: { data: AssistantStatus }) {
  const missing = [data.model, data.embed_model].filter((m) => !modelListed(m, data.models_available));
  if (missing.length === 0) return null;
  return (
    <div className="ap-warn" role="status">
      The server does not list {missing.map((m) => `"${m}"`).join(" or ")} among its installed models
      {data.models_available.length > 0 ? ` (${data.models_available.join(", ")})` : ""}. Pull{" "}
      {missing.map((m, i) => (
        <React.Fragment key={m}>
          {i > 0 ? " and " : ""}
          <code className="ap-mono">ollama pull {m}</code>
        </React.Fragment>
      ))}
      .
    </div>
  );
}

function RetrievedList({ answer, onOpen }: { answer: Answer; onOpen: OpenEvidence }) {
  return (
    <details className="as-retrieved">
      <summary>Retrieved context ({answer.retrieved.length})</summary>
      <div className="ap-muted ap-note">
        The records retrieval handed to the model, in the server&apos;s order. Retrieval similarity says how close a
        record is to the question; it is not a confidence in the answer.
      </div>
      {answer.retrieved.length === 0 ? (
        <div className="ap-muted">Nothing was retrieved.</div>
      ) : (
        <div className="ap-table-wrap">
          <table className="ap-table">
            <thead>
              <tr>
                <th>Doc id</th>
                <th>Kind</th>
                <th>Title</th>
                <th>Method</th>
                <th>Retrieval similarity</th>
              </tr>
            </thead>
            <tbody>
              {answer.retrieved.map((r, i) => {
                const ref = parseEvidenceId(r.document.doc_id);
                return (
                  <tr key={`${i}-${r.document.doc_id}`}>
                    <td>
                      {ref.kind === "unknown" ? (
                        <span className="ap-mono">{r.document.doc_id}</span>
                      ) : (
                        <button
                          type="button"
                          className={`ap-evidence ap-evidence-${ref.kind}`}
                          title={r.document.doc_id}
                          onClick={() => onOpen(ref, `Retrieved for: ${answer.question}`)}
                        >
                          {shortEvidenceLabel(ref)}
                        </button>
                      )}
                    </td>
                    <td>{r.document.kind}</td>
                    <td>{r.document.title}</td>
                    <td className="ap-mono">{r.method}</td>
                    <td className="ap-mono" title="Retrieval similarity to the question (not answer confidence)">
                      {formatSimilarity(r.score)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </details>
  );
}

function AnswerBlock({
  answer,
  engagementId,
  onOpen,
}: {
  answer: Answer;
  engagementId: string;
  onOpen: OpenEvidence;
}) {
  const context = `Answer to: ${answer.question}`;
  return (
    <div className="as-answer">
      {answer.engagement_id !== engagementId && (
        <div className="ap-warn" role="alert">
          This answer is for engagement {answer.engagement_id}, not {engagementId}.
        </div>
      )}
      {answer.refused ? (
        <div className="as-refused" role="status">
          <strong>Refused:</strong> {answer.refusal_reason || "no reason given by the server"}
          {answer.text.trim() !== "" && answer.text.trim() !== (answer.refusal_reason ?? "").trim() && (
            <div className="as-refused-text">
              <CitedText
                text={answer.text}
                grounding={answer.grounding}
                citations={answer.citations}
                context={context}
                onOpen={onOpen}
              />
            </div>
          )}
        </div>
      ) : (
        <CitedText
          text={answer.text}
          grounding={answer.grounding}
          citations={answer.citations}
          context={context}
          onOpen={onOpen}
        />
      )}
      {(!answer.refused || !isGrounded(answer.grounding)) && <GroundingWarning grounding={answer.grounding} />}
      <div className="as-meta ap-muted">
        Generated by <code className="ap-mono">{answer.model}</code> from the retrieved records only.
      </div>
      <RetrievedList answer={answer} onOpen={onOpen} />
    </div>
  );
}

export default function AssistantView({ activeEngagement, onSelectEngagementPrompt }: AssistantViewProps) {
  const engagementId = activeEngagement?.engagement_id ?? null;
  const [statusToken, setStatusToken] = useState(0);
  const [status, setStatus] = useState<{ token: number; state: StatusState } | null>(null);
  const [indexes, setIndexes] = useState<Record<string, IndexState>>({});
  const [turns, setTurns] = useState<Record<string, Turn[]>>({});
  const [question, setQuestion] = useState("");
  const nextTurnId = useRef(1);
  const { openEvidence, panel } = useEvidencePanel(engagementId);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const data = await api.getAssistantStatus(controller.signal);
        setStatus({ token: statusToken, state: { status: "ok", data } });
      } catch (err: unknown) {
        if (isAbortError(err)) return;
        setStatus({ token: statusToken, state: { status: "error", message: describeError(err, "Checking the assistant status") } });
      }
    })();
    return () => controller.abort();
  }, [statusToken]);

  const statusState: StatusState = status && status.token === statusToken ? status.state : { status: "loading" };
  const statusData = statusState.status === "ok" ? statusState.data : null;

  const runIndex = useCallback(async () => {
    if (!engagementId) return;
    const eid = engagementId;
    setIndexes((s) => ({ ...s, [eid]: { status: "loading" } }));
    try {
      const result = await api.indexAssistant(eid);
      setIndexes((s) => ({ ...s, [eid]: { status: "ok", result } }));
    } catch (err: unknown) {
      setIndexes((s) => ({ ...s, [eid]: { status: "error", message: describeError(err, "Indexing") } }));
    }
  }, [engagementId]);

  const setTurn = (eid: string, id: number, state: TurnState) =>
    setTurns((t) => ({ ...t, [eid]: (t[eid] ?? []).map((x) => (x.id === id ? { ...x, state } : x)) }));

  const ask = async (e: React.FormEvent) => {
    e.preventDefault();
    const q = question.trim();
    if (!engagementId || q === "") return;
    const eid = engagementId;
    const id = nextTurnId.current++;
    setTurns((t) => ({ ...t, [eid]: [...(t[eid] ?? []), { id, question: q, state: { status: "pending" } }] }));
    setQuestion("");
    try {
      const answer = await api.askAssistant(eid, q);
      setTurn(eid, id, { status: "answer", answer });
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 409) {
        setTurn(eid, id, { status: "not-indexed", message: err.message });
      } else if (err instanceof ApiError && err.status === 503) {
        setTurn(eid, id, { status: "unavailable", message: err.message });
      } else {
        setTurn(eid, id, { status: "error", message: describeError(err, "Asking") });
      }
    }
  };

  if (!activeEngagement || !engagementId) {
    return (
      <div className="db-card ap-empty">
        <h2 className="ap-h2">Engagement Required</h2>
        <p className="ap-empty-text">
          The assistant answers from one authorized engagement&apos;s records. Select or create an engagement first.
        </p>
        {onSelectEngagementPrompt && (
          <button onClick={onSelectEngagementPrompt} className="db-btn-create-eng" style={{ margin: "0 auto" }}>
            Create Engagement
          </button>
        )}
      </div>
    );
  }

  const index = indexes[engagementId];
  const conversation = turns[engagementId] ?? [];
  const pending = conversation.some((t) => t.state.status === "pending");

  return (
    <div className="ap-root">
      <div className="ap-header">
        <div>
          <h2 className="ap-h2">Assistant</h2>
          <div className="ap-muted" style={{ fontSize: "0.85rem" }}>
            Answers come only from {activeEngagement.name}&apos;s indexed records: observations, findings, the declared
            topology, and the paths and chokepoints the rules engine already proved. Each numbered citation opens the
            record it rests on. The model narrates; it does not create paths.
          </div>
        </div>
      </div>

      <StatusLine state={statusState} onRecheck={() => setStatusToken((t) => t + 1)} />

      {/* ---------- Index ---------- */}
      <div className="db-card ap-card">
        <div className="as-status-row">
          <span className="ap-subhead" style={{ margin: 0 }}>
            Retrieval index
          </span>
          <span className="ap-muted">
            Rebuild after new scans, enrichment or a graph rebuild so answers see the current records.
          </span>
          <button
            type="button"
            className="db-btn-secondary as-push"
            disabled={index?.status === "loading"}
            onClick={() => void runIndex()}
          >
            {index?.status === "loading" ? "Indexing…" : "Index engagement"}
          </button>
        </div>
        {index?.status === "error" && (
          <div className="ap-error" role="alert">
            <span>{index.message}</span>
          </div>
        )}
        {index?.status === "ok" && (
          <div className="as-index-result">
            <div>
              Indexed <strong>{index.result.indexed}</strong> record{index.result.indexed === 1 ? "" : "s"} with{" "}
              <code className="ap-mono">{index.result.embed_model}</code>
              {index.result.engagement_id !== engagementId ? ` (for engagement ${index.result.engagement_id})` : ""}.
            </div>
            <div className="ap-zones">
              {Object.entries(index.result.by_kind)
                .sort(([a], [b]) => a.localeCompare(b, "en"))
                .map(([kind, n]) => (
                  <span key={kind} className="ap-zone">
                    <span className="ap-mono">{kind}</span>
                    <span className="ap-count">{n}</span>
                  </span>
                ))}
            </div>
          </div>
        )}
      </div>

      {/* ---------- Conversation (newest last) ---------- */}
      {conversation.length > 0 && (
        <div className="as-convo">
          {conversation.map((t) => (
            <div key={t.id} className="db-card ap-card as-turn">
              <div className="as-question">
                <span className="ap-subhead" style={{ margin: 0 }}>
                  Question
                </span>
                <div>{t.question}</div>
              </div>
              {t.state.status === "pending" && <div className="ap-muted">Retrieving records and generating…</div>}
              {t.state.status === "answer" && (
                <AnswerBlock answer={t.state.answer} engagementId={engagementId} onOpen={openEvidence} />
              )}
              {t.state.status === "not-indexed" && (
                <div className="ap-warn as-col" role="status">
                  <div>
                    This engagement has not been indexed yet. Server: {t.state.message}
                  </div>
                  <button
                    type="button"
                    className="db-btn-secondary ap-sim-btn"
                    disabled={index?.status === "loading"}
                    onClick={() => void runIndex()}
                  >
                    {index?.status === "loading" ? "Indexing…" : "Index engagement now"}
                  </button>
                  <div className="ap-muted">Then ask the question again.</div>
                </div>
              )}
              {t.state.status === "unavailable" && (
                <div className="ap-error as-col" role="alert">
                  <span>The model server is unavailable. Server: {t.state.message}</span>
                  <OllamaHelp
                    baseUrl={statusData?.ollama_base_url ?? null}
                    model={statusData?.model ?? null}
                    embedModel={statusData?.embed_model ?? null}
                  />
                </div>
              )}
              {t.state.status === "error" && (
                <div className="ap-error" role="alert">
                  <span>{t.state.message}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ---------- Question box ---------- */}
      <form className="db-card ap-card as-ask" onSubmit={(e) => void ask(e)}>
        <label htmlFor="as-question" className="ap-subhead" style={{ margin: 0 }}>
          Ask about this engagement
        </label>
        <textarea
          id="as-question"
          className="as-input"
          rows={3}
          value={question}
          placeholder="e.g. Which hosts expose SSH, and which findings are on a path to a crown-jewel zone?"
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
              e.preventDefault();
              e.currentTarget.form?.requestSubmit();
            }
          }}
        />
        <div className="as-status-row">
          <span className="ap-muted" style={{ fontSize: "0.75rem" }}>
            Ctrl+Enter to send. If the records do not support an answer, the assistant says so.
          </span>
          <button type="submit" className="db-btn-create-eng as-push" disabled={pending || question.trim() === ""}>
            {pending ? "Answering…" : "Ask"}
          </button>
        </div>
      </form>

      {panel}
    </div>
  );
}
