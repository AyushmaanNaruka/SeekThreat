"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

type ApiStatus = "checking" | "online" | "offline";

const STATUS_STYLE: Record<ApiStatus, { label: string; color: string }> = {
  checking: { label: "Checking API…", color: "#94a3b8" },
  online: { label: "API online", color: "#22c55e" },
  offline: { label: "API offline", color: "#ef4444" },
};

// Section ids that exist on the landing page (app/page.tsx).
const NAV_LINKS = [
  { label: "Home", target: "home" },
  { label: "Features", target: "features" },
];

export default function Navbar() {
  const [activeNav, setActiveNav] = useState("Home");
  const [apiStatus, setApiStatus] = useState<ApiStatus>("checking");

  // One real health check against the API on mount. No polling.
  useEffect(() => {
    const controller = new AbortController();
    // A request that hangs for 5s counts as offline.
    const timeout = setTimeout(() => controller.abort(), 5000);
    let unmounted = false;

    fetch(`${API_BASE_URL}/health`, { signal: controller.signal, cache: "no-store" })
      .then((res) => {
        if (!unmounted) setApiStatus(res.ok ? "online" : "offline");
      })
      .catch(() => {
        if (!unmounted) setApiStatus("offline");
      })
      .finally(() => clearTimeout(timeout));

    return () => {
      unmounted = true;
      clearTimeout(timeout);
      controller.abort();
    };
  }, []);

  const scrollTo = (target: string) => {
    if (target === "home") {
      window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }
    document.getElementById(target)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const status = STATUS_STYLE[apiStatus];

  return (
    <header className="navbar-container">
      <div className="navbar-inner">
        {/* Brand / Logo */}
        <Link href="/" className="navbar-brand" aria-label="SeekThreat home">
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
        </Link>

        {/* Center Navigation Links: each scrolls to a real section */}
        <nav className="navbar-nav">
          {NAV_LINKS.map((item) => {
            const isActive = activeNav === item.label;
            return (
              <a
                key={item.label}
                href={`#${item.target}`}
                onClick={(e) => {
                  e.preventDefault();
                  setActiveNav(item.label);
                  scrollTo(item.target);
                }}
                className={`nav-link ${isActive ? "active" : ""}`}
              >
                <span>{item.label}</span>
                {isActive && <div className="active-indicator"></div>}
              </a>
            );
          })}
          <Link href="/dashboard" className="nav-link">
            <span>Dashboard</span>
          </Link>
        </nav>

        {/* Right Section: real API health + Get Started */}
        <div className="navbar-actions">
          <div
            className="system-status"
            title={`GET ${API_BASE_URL}/health`}
            role="status"
            aria-live="polite"
          >
            <span
              className="status-dot"
              style={{
                backgroundColor: status.color,
                boxShadow: `0 0 10px ${status.color}, 0 0 18px ${status.color}`,
                animation: apiStatus === "online" ? undefined : "none",
              }}
            ></span>
            <span className="status-text">{status.label}</span>
          </div>

          <Link href="/dashboard" className="btn-get-started">
            <span>Get Started</span>
          </Link>
        </div>
      </div>
    </header>
  );
}
