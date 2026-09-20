"use client";

import React from "react";

interface HeroHeaderProps {
  onExplore: () => void;
  onWatchDemo: () => void;
}

export default function HeroHeader({ onExplore, onWatchDemo }: HeroHeaderProps) {
  return (
    <div className="hero-header-content">
      {/* Top AI Badge */}
      <div className="hero-badge">
        <div className="badge-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <circle cx="12" cy="11" r="2" fill="currentColor" />
          </svg>
        </div>
        <span className="badge-text">AI-POWERED CYBER THREAT INTELLIGENCE</span>
      </div>

      {/* Main Large Title: SEEK in White, THREAT in Electric Purple */}
      <div className="hero-title-group">
        <h1 className="hero-main-brand">
          <span className="brand-seek">SEEK</span>
          <span className="brand-threat">THREAT</span>
        </h1>
        <div className="hero-tagline-text">
          See What <span className="text-gradient-purple">Others</span> Miss.
        </div>
      </div>

      {/* Subtitle description */}
      <p className="hero-description">
        From hidden vulnerabilities to complex attack paths, SeekThreat turns scattered data into clear, actionable intelligence — <span className="text-highlight-cyan">before the threat becomes a breach.</span>
      </p>

      {/* Action Buttons */}
      <div className="hero-actions">
        <button onClick={onExplore} className="btn-explore-platform">
          <span>Explore Platform</span>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="arrow-icon">
            <line x1="5" y1="12" x2="19" y2="12"></line>
            <polyline points="12 5 19 12 12 19"></polyline>
          </svg>
        </button>

        <button onClick={onWatchDemo} className="btn-watch-demo">
          <div className="play-icon-wrap">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor">
              <polygon points="5 3 19 12 5 21 5 3"></polygon>
            </svg>
          </div>
          <span>Watch Demo</span>
        </button>
      </div>
    </div>
  );
}
