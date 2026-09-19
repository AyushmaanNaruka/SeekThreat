"use client";

import React from "react";

interface FeatureItem {
  id: string;
  title: string;
  desc: string;
  icon: React.ReactNode;
}

export default function FeatureDock() {
  const features: FeatureItem[] = [
    {
      id: "scanning",
      title: "Multi-Tool Scanning",
      desc: "Nmap, Nuclei, Nikto, OpenVAS, ZAP",
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
      id: "graph",
      title: "Knowledge Graph",
      desc: "Visualize relationships and attack paths",
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <circle cx="6" cy="6" r="3" />
          <circle cx="18" cy="6" r="3" />
          <circle cx="12" cy="18" r="3" />
          <line x1="8.5" y1="7.5" x2="15.5" y2="7.5" />
          <line x1="7.5" y1="8.5" x2="10.5" y2="15.5" />
          <line x1="16.5" y1="8.5" x2="13.5" y2="15.5" />
        </svg>
      ),
    },
    {
      id: "intel",
      title: "Threat Intelligence",
      desc: "Real-time threat feeds and enrichment",
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
      ),
    },
    {
      id: "ai",
      title: "AI Assistant",
      desc: "Natural language queries & expert insights",
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 4.44-2.04z" />
          <path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-4.44-2.04z" />
        </svg>
      ),
    },
    {
      id: "insights",
      title: "Actionable Insights",
      desc: "Prioritize, remediate, reduce risk",
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" fill="currentColor" />
        </svg>
      ),
    },
  ];

  return (
    <div className="feature-dock-wrapper">
      <div className="feature-dock-container">
        {/* Dock Header */}
        <div className="feature-dock-header">
          <h2 className="dock-title">Comprehensive Security. Unified.</h2>
          <p className="dock-subtitle">Detect. Analyze. Understand. Stay Ahead.</p>
        </div>

        {/* 5 Feature Cards */}
        <div className="feature-dock-grid">
          {features.map((f) => (
            <div key={f.id} className="feature-card">
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
