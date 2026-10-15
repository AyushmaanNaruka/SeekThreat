"use client";

import React from "react";

interface FeatureItem {
  id: string;
  title: string;
  desc: string;
  icon: React.ReactNode;
}

// Each card describes a capability that exists today. Do not add a card for
// something that is planned but not built (attack paths, assistant, reports).
export default function FeatureDock() {
  const features: FeatureItem[] = [
    {
      id: "authorization",
      title: "Authorized Scanning",
      desc: "Named authorizer, target allowlist and time window, enforced by the API",
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
      ),
    },
    {
      id: "scanners",
      title: "Four Scanners",
      desc: "Nmap, Nuclei, Nikto, ssh-audit. Intrusive Nuclei templates excluded",
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <circle cx="12" cy="12" r="10" />
          <circle cx="12" cy="12" r="6" />
          <circle cx="12" cy="12" r="2" fill="currentColor" />
          <line x1="12" y1="2" x2="12" y2="6" />
          <line x1="12" y1="18" x2="12" y2="22" />
          <line x1="2" y1="12" x2="6" y2="12" />
          <line x1="18" y1="12" x2="22" y2="12" />
        </svg>
      ),
    },
    {
      id: "observations",
      title: "Raw Observations",
      desc: "Hosts, ports, services and checks, each with source and confidence",
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <rect x="2" y="3" width="20" height="7" rx="2" />
          <rect x="2" y="14" width="20" height="7" rx="2" />
          <line x1="6" y1="6.5" x2="6.01" y2="6.5" />
          <line x1="6" y1="17.5" x2="6.01" y2="17.5" />
        </svg>
      ),
    },
    {
      id: "enrichment",
      title: "Fused Enrichment",
      desc: "CVSS, EPSS, CISA KEV, ExploitDB, Metasploit, NVD, CVE.org, EUVD",
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <ellipse cx="12" cy="5" rx="9" ry="3" />
          <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
          <path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3" />
        </svg>
      ),
    },
    {
      id: "ers",
      title: "Explainable Risk Score",
      desc: "Every score shows the components it was built from",
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <line x1="6" y1="20" x2="6" y2="12" />
          <line x1="12" y1="20" x2="12" y2="6" />
          <line x1="18" y1="20" x2="18" y2="14" />
        </svg>
      ),
    },
  ];

  return (
    <div className="feature-dock-wrapper">
      <div className="feature-dock-container">
        {/* Dock Header */}
        <div className="feature-dock-header">
          <h2 className="dock-title">Scan. Enrich. Explain.</h2>
          <p className="dock-subtitle">Every finding traced back to where it came from.</p>
        </div>

        {/* Feature cards (informational, not links) */}
        <div className="feature-dock-grid">
          {features.map((f) => (
            <div key={f.id} className="feature-card" style={{ cursor: "default" }}>
              <div className="feature-icon-circle">{f.icon}</div>
              <div className="feature-info">
                <h3 className="feature-name">{f.title}</h3>
                <p className="feature-desc">{f.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
