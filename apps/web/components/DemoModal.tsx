"use client";

import React, { useState } from "react";

interface DemoModalProps {
  isOpen: boolean;
  onClose: () => void;
  mode: "demo" | "explore" | "auth";
}

export default function DemoModal({ isOpen, onClose, mode }: DemoModalProps) {
  const [activeTab, setActiveTab] = useState("attack-graph");

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div className="modal-header">
          <div className="modal-brand">
            <span className="modal-badge-dot"></span>
            <span className="modal-title">
              {mode === "demo" && "SEEKTHREAT INTERACTIVE PLATFORM DEMO"}
              {mode === "explore" && "SEEKTHREAT ATTACK-PATH INTELLIGENCE ENGINE"}
              {mode === "auth" && "INITIALIZE ENGAGEMENT / AUTHORIZATION"}
            </span>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            ✕
          </button>
        </div>

        {/* Modal Content */}
        <div className="modal-body">
          {mode === "demo" && (
            <div className="demo-view">
              <div className="demo-terminal">
                <div className="terminal-bar">
                  <div className="terminal-dots">
                    <span className="dot dot-red"></span>
                    <span className="dot dot-yellow"></span>
                    <span className="dot dot-green"></span>
                  </div>
                  <span className="terminal-title">engine://deterministic-attack-path-evaluator</span>
                </div>
                <div className="terminal-content">
                  <p className="term-line text-cyan">$ seekthreat scan --target lab.internal.corp --auth-id ENG-2026-904</p>
                  <p className="term-line text-slate-400">[+] Scanners active: Nmap, Nuclei, Nikto, OpenVAS, ZAP</p>
                  <p className="term-line text-yellow">[!] Host identified: 10.10.20.15 (Nginx 1.18.0, OpenSSH 8.2p1)</p>
                  <p className="term-line text-red">[CRITICAL] CVE-2024-XXXX detected on port 8443 (CVSS 9.8)</p>
                  <p className="term-line text-purple">[*] Deterministic Graph Engine: 4 hops mapped to Domain Controller</p>
                  <p className="term-line text-green">[✓] Proven attack chain established: Ingress &rarr; Remote Code Exec &rarr; Credential Extraction &rarr; Critical Asset</p>
                </div>
              </div>
            </div>
          )}

          {mode === "explore" && (
            <div className="explore-view">
              <div className="explore-tabs">
                <button
                  className={`tab-btn ${activeTab === "attack-graph" ? "active" : ""}`}
                  onClick={() => setActiveTab("attack-graph")}
                >
                  Attack Graph
                </button>
                <button
                  className={`tab-btn ${activeTab === "findings" ? "active" : ""}`}
                  onClick={() => setActiveTab("findings")}
                >
                  Fused Findings (4.8M)
                </button>
                <button
                  className={`tab-btn ${activeTab === "rag" ? "active" : ""}`}
                  onClick={() => setActiveTab("rag")}
                >
                  RAG Threat Copilot
                </button>
              </div>

              <div className="tab-pane">
                {activeTab === "attack-graph" && (
                  <div className="graph-preview">
                    <div className="graph-node-chip node-red">Node: CVE-2024-XXXX [CVSS 9.8]</div>
                    <div className="graph-arrow">&rarr;</div>
                    <div className="graph-node-chip node-cyan">Asset: Web Server [10.10.20.15]</div>
                    <div className="graph-arrow">&rarr;</div>
                    <div className="graph-node-chip node-purple">Asset: Database Cluster [2.4M records]</div>
                  </div>
                )}

                {activeTab === "findings" && (
                  <div className="findings-table">
                    <div className="finding-row">
                      <span className="badge-crit">CRITICAL</span>
                      <span className="font-mono text-cyan">CVE-2024-XXXX</span>
                      <span className="text-slate-300">Unauthenticated RCE in Spring Framework</span>
                      <span className="text-slate-400">Provenance: Nuclei + NVD</span>
                    </div>
                  </div>
                )}

                {activeTab === "rag" && (
                  <div className="rag-chat-preview">
                    <p className="text-slate-300">
                      <strong>AI Assistant:</strong> Based on the deterministic attack graph for engagement #ENG-2026-904, the primary vector chains through port 8443 on 10.10.20.15. Patching this single perimeter node reduces critical risk exposure by 92%.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {mode === "auth" && (
            <div className="auth-form">
              <h4 className="text-sm font-semibold text-slate-200 mb-2">Initialize Threat Intelligence Engagement</h4>
              <p className="text-xs text-slate-400 mb-4">Every scan strictly adheres to rules: verified authorization and deterministic path narration.</p>
              <div className="input-group">
                <label className="text-xs text-slate-300">Engagement ID / Name</label>
                <input type="text" defaultValue="ENG-2026-ALPHA" className="modal-input" />
              </div>
              <div className="input-group">
                <label className="text-xs text-slate-300">Target Range (Allowlisted Hosts)</label>
                <input type="text" defaultValue="10.10.20.0/24" className="modal-input" />
              </div>
              <button className="btn-confirm-action" onClick={onClose}>
                Confirm & Launch Telemetry
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
