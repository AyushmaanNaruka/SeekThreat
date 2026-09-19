"use client";

import React, { useState, useEffect } from "react";

interface FeedItem {
  id: string;
  title: string;
  time: string;
  type: "cve" | "domain" | "breach" | "activity";
}

export default function LiveThreatFeed() {
  const [items, setItems] = useState<FeedItem[]>([
    { id: "1", title: "New CVE Published", time: "2m ago", type: "cve" },
    { id: "2", title: "Malicious Domain Detected", time: "5m ago", type: "domain" },
    { id: "3", title: "Data Breach Reported", time: "12m ago", type: "breach" },
    { id: "4", title: "Suspicious Activity", time: "18m ago", type: "activity" },
  ]);

  // Subtle live feed pulse
  useEffect(() => {
    const timer = setInterval(() => {
      // Optional subtle time progression or simulated new feed items
    }, 15000);
    return () => clearInterval(timer);
  }, []);

  const renderIcon = (type: FeedItem["type"]) => {
    switch (type) {
      case "cve":
        return (
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
            <line x1="9" y1="9" x2="15" y2="15" />
            <line x1="15" y1="9" x2="9" y2="15" />
          </svg>
        );
      case "domain":
        return (
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#818cf8" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <line x1="2" y1="12" x2="22" y2="12" />
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
          </svg>
        );
      case "breach":
        return (
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
        );
      case "activity":
        return (
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#a855f7" strokeWidth="2">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
          </svg>
        );
    }
  };

  return (
    <div className="threat-feed-card">
      {/* Header */}
      <div className="feed-header">
        <div className="feed-meta">
          <div className="feed-title">GLOBAL THREAT FEED</div>
          <div className="feed-status">
            <span className="live-dot"></span>
            <span className="live-label">Live Intelligence</span>
          </div>
        </div>

        {/* Sparkline wave visualization */}
        <div className="sparkline-wrapper">
          <svg className="sparkline-svg" viewBox="0 0 90 28" preserveAspectRatio="none">
            <defs>
              <linearGradient id="sparkGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
              </linearGradient>
            </defs>
            <path
              d="M0,20 Q15,5 30,16 T60,8 T78,14 T90,6 L90,28 L0,28 Z"
              fill="url(#sparkGrad)"
            />
            <path
              d="M0,20 Q15,5 30,16 T60,8 T78,14 T90,6"
              fill="none"
              stroke="#38bdf8"
              strokeWidth="2"
              strokeLinecap="round"
            />
          </svg>
        </div>
      </div>

      {/* Feed Items */}
      <div className="feed-list">
        {items.map((item) => (
          <div key={item.id} className="feed-row">
            <div className="feed-row-left">
              <span className="feed-icon">{renderIcon(item.type)}</span>
              <span className="feed-text">{item.title}</span>
            </div>
            <span className="feed-time">{item.time}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
