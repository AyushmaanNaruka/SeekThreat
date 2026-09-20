"use client";

import React, { useState } from "react";

export default function Navbar({ onGetStarted }: { onGetStarted?: () => void }) {
  const [activeNav, setActiveNav] = useState("Home");

  const navLinks = ["Home", "Features", "Solutions", "Docs", "About"];

  return (
    <header className="navbar-container">
      <div className="navbar-inner">
        {/* Brand / Logo */}
        <a href="#home" className="navbar-brand">
          <div className="logo-badge">
            <svg
              className="logo-icon"
              viewBox="0 0 40 40"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <defs>
                <linearGradient id="hexGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#38bdf8" />
                  <stop offset="50%" stopColor="#818cf8" />
                  <stop offset="100%" stopColor="#c084fc" />
                </linearGradient>
                <linearGradient id="innerHexGrad" x1="100%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" stopColor="#00f0ff" />
                  <stop offset="100%" stopColor="#a855f7" />
                </linearGradient>
                <filter id="glowHex" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="2" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>
              {/* Outer Hexagon */}
              <polygon
                points="20,2 36,11 36,29 20,38 4,29 4,11"
                stroke="url(#hexGrad)"
                strokeWidth="2.4"
                fill="rgba(10, 15, 35, 0.6)"
                filter="url(#glowHex)"
              />
              {/* Nested Isometric Cube / Shield */}
              <polygon
                points="20,9 30,15 30,25 20,31 10,25 10,15"
                stroke="url(#innerHexGrad)"
                strokeWidth="1.8"
                fill="rgba(147, 51, 234, 0.15)"
              />
              {/* Inner Diamond / Core */}
              <polygon
                points="20,15 25,20 20,25 15,20"
                fill="url(#hexGrad)"
              />
            </svg>
          </div>
          <span className="brand-name">
            <span className="nav-seek">SEEK</span>
            <span className="nav-threat">THREAT</span>
          </span>
        </a>

        {/* Center Navigation Links */}
        <nav className="navbar-nav">
          {navLinks.map((item) => {
            const isActive = activeNav === item;
            return (
              <a
                key={item}
                href={`#${item.toLowerCase()}`}
                onClick={(e) => {
                  e.preventDefault();
                  setActiveNav(item);
                }}
                className={`nav-link ${isActive ? "active" : ""}`}
              >
                <span>{item}</span>
                {isActive && <div className="active-indicator"></div>}
              </a>
            );
          })}
        </nav>

        {/* Right Section: System Online + Get Started */}
        <div className="navbar-actions">
          {/* Status Indicator */}
          <div className="system-status">
            <span className="status-dot"></span>
            <span className="status-text">System Online</span>
          </div>

          {/* CTA Button */}
          <button
            onClick={onGetStarted}
            className="btn-get-started"
          >
            <span>Get Started</span>
          </button>
        </div>
      </div>
    </header>
  );
}
