"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import DashboardGlobe from "../../components/DashboardGlobe";
import SidebarOrbit from "../../components/SidebarOrbit";
import {
  api,
  EngagementItem,
  ScanItem,
  ObservationItem,
  CreateEngagementPayload,
} from "../../lib/api";
import {
  hasActiveScans,
  DEFAULT_POLLING_CONFIG,
} from "../../lib/polling";
import "./dashboard.css";

function formatDuration(startedAt: string, completedAt?: string | null): string {
  const start = new Date(startedAt).getTime();
  const end = completedAt ? new Date(completedAt).getTime() : Date.now();
  const diffSec = Math.max(0, Math.floor((end - start) / 1000));
  if (diffSec < 60) return `${diffSec}s`;
  const m = Math.floor(diffSec / 60);
  const s = diffSec % 60;
  return `${m}m ${s}s`;
}

function formatDateStr(dateStr: string): string {
  try {
    const d = new Date(dateStr);
    return d.toLocaleDateString("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return dateStr;
  }
}

function computeEngagementStatus(
  grantedAt: string,
  expiresAt: string
): "active" | "not-yet-active" | "expired" {
  const now = Date.now();
  const granted = new Date(grantedAt).getTime();
  const expires = new Date(expiresAt).getTime();
  if (now < granted) return "not-yet-active";
  if (now > expires) return "expired";
  return "active";
}

function formatExpiresIn(expiresAt: string): string {
  const now = Date.now();
  const exp = new Date(expiresAt).getTime();
  const diffMs = exp - now;
  if (diffMs <= 0) return "Expired";
  const hours = Math.floor(diffMs / (1000 * 60 * 60));
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  if (days > 0) return `${days}d ${remHours}h`;
  const mins = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
  return `${hours}h ${mins}m`;
}

function formatScanTarget(scan: ScanItem): string {
  if (scan.options?.ports && !scan.target.includes(":")) {
    return `${scan.target}:${scan.options.ports}`;
  }
  return scan.target;
}

export default function DashboardPage() {
  const [activeNav, setActiveNav] = useState("Engagements");
  const [selectedScanner, setSelectedScanner] = useState<"nmap" | "nuclei">("nmap");
  const [targetInput, setTargetInput] = useState("");
  const [scopeWarning, setScopeWarning] = useState<string | null>(null);

  // Live Backend State
  const [engagements, setEngagements] = useState<EngagementItem[]>([]);
  const [selectedEngagementId, setSelectedEngagementId] = useState<string>("");
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);
  const [nowTick, setNowTick] = useState<number>(Date.now());
  const [pollGuardExceeded, setPollGuardExceeded] = useState(false);
  const pollAttemptsRef = React.useRef(0);

  // Modals
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createForm, setCreateForm] = useState({
    engagement_id: "",
    name: "",
    authorized_by: "",
    allowlist: "127.0.0.1, 127.0.0.1/32, localhost",
    granted_at: "",
    expires_at: "",
  });
  const [createError, setCreateError] = useState<string | null>(null);
  const [createSubmitting, setCreateSubmitting] = useState(false);

  // Observation inspection modal
  const [selectedScanObservations, setSelectedScanObservations] = useState<{
    scan: ScanItem;
    items: ObservationItem[];
  } | null>(null);
  const [obsLoading, setObsLoading] = useState(false);

  // Active Engagement derivation
  const activeEngagement =
    engagements.find((e) => e.engagement_id === selectedEngagementId) ||
    engagements[0] ||
    null;

  const authStatus = activeEngagement
    ? computeEngagementStatus(activeEngagement.granted_at, activeEngagement.expires_at)
    : "expired";

  // Data fetching
  const refreshData = useCallback(async () => {
    try {
      const [engList, scanList] = await Promise.all([
        api.getEngagements(),
        api.getScans(),
      ]);
      setEngagements(engList);
      setScans(scanList);
      if (engList.length > 0 && !selectedEngagementId) {
        setSelectedEngagementId(engList[0].engagement_id);
      }
      setApiError(null);
    } catch (err: any) {
      console.error("Failed to fetch dashboard data:", err);
      // Keep silent on background polling failure, only show if no data
      if (engagements.length === 0) {
        setApiError(err.message || "Failed to connect to SeekThreat API backend.");
      }
    } finally {
      setLoading(false);
    }
  }, [selectedEngagementId, engagements.length]);

  const handleManualRefresh = useCallback(() => {
    pollAttemptsRef.current = 0;
    setPollGuardExceeded(false);
    refreshData();
  }, [refreshData]);

  // Initial load
  useEffect(() => {
    refreshData();
  }, [refreshData]);

  const activeScansPresent = hasActiveScans(scans);

  // Live polling: Polls ONLY while scans are genuinely active (pending or running).
  // Automatically stops when all scans reach terminal states (completed, failed, cancelled).
  // Enforces a maximum polling guard (150 attempts @ 2000ms = 5 minutes) to prevent indefinite polling.
  useEffect(() => {
    if (!activeScansPresent) {
      pollAttemptsRef.current = 0;
      if (pollGuardExceeded) {
        setPollGuardExceeded(false);
      }
      return;
    }

    if (pollAttemptsRef.current >= DEFAULT_POLLING_CONFIG.maxAttempts) {
      setPollGuardExceeded(true);
      return;
    }

    const poller = setInterval(() => {
      pollAttemptsRef.current += 1;
      if (pollAttemptsRef.current >= DEFAULT_POLLING_CONFIG.maxAttempts) {
        setPollGuardExceeded(true);
        clearInterval(poller);
        return;
      }
      refreshData();
    }, DEFAULT_POLLING_CONFIG.activeIntervalMs);

    return () => {
      clearInterval(poller);
    };
  }, [activeScansPresent, pollGuardExceeded, refreshData]);

  // Live tick timer: Only updates elapsed seconds when active scans are in progress
  useEffect(() => {
    if (!activeScansPresent) return;
    const timer = setInterval(() => {
      setNowTick(Date.now());
    }, 1000);

    return () => {
      clearInterval(timer);
    };
  }, [activeScansPresent]);

  // Target input validation against active engagement allowlist
  const handleTargetChange = (val: string) => {
    setTargetInput(val);
    if (!val.trim()) {
      setScopeWarning(null);
      return;
    }
    if (!activeEngagement) {
      setScopeWarning("No active engagement selected.");
      return;
    }

    const trimmed = val.trim();
    let hostTarget = trimmed;
    if (hostTarget.includes("://")) {
      try {
        hostTarget = new URL(hostTarget).hostname;
      } catch {
        hostTarget = hostTarget.replace(/^[a-zA-Z]+:\/\//, "").split("/")[0].split(":")[0];
      }
    } else if (hostTarget.includes(":") && !hostTarget.includes("/")) {
      hostTarget = hostTarget.split(":")[0];
    }

    const allowlist = activeEngagement.allowlist;
    const isAllowed = allowlist.some((entry) => {
      const pattern = entry.trim();
      if (pattern === trimmed || pattern === hostTarget) return true;
      if (pattern.startsWith("*.") && (trimmed.endsWith(pattern.slice(1)) || hostTarget.endsWith(pattern.slice(1)))) return true;
      if (pattern.includes("/")) {
        // Simple CIDR prefix check for common lab subnets
        const base = pattern.split("/")[0].split(".").slice(0, 2).join(".");
        if (trimmed.startsWith(base) || hostTarget.startsWith(base)) return true;
      }
      if ((trimmed.startsWith("127.") || hostTarget.startsWith("127.")) && pattern.startsWith("127.")) return true;
      if ((trimmed.includes("localhost") || hostTarget.includes("localhost")) && pattern.includes("localhost")) return true;
      return false;
    });

    if (!isAllowed) {
      setScopeWarning(
        `Target "${trimmed}" is outside authorized scope (${allowlist.join(", ")}). Server authorization gate will reject this target.`
      );
    } else {
      setScopeWarning(null);
    }
  };

  const [isLaunching, setIsLaunching] = useState(false);

  // Launch scan handler
  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeEngagement) {
      setShowCreateModal(true);
      return;
    }
    let target =
      targetInput.trim() ||
      (activeEngagement.allowlist[0] || "127.0.0.1");

    setIsLaunching(true);
    try {
      setApiError(null);
      pollAttemptsRef.current = 0;
      setPollGuardExceeded(false);
      const options: Record<string, any> = {};
      if (selectedScanner === "nuclei") {
        options.template = "tests/fixtures/nuclei/test_http_detect.yaml";
        if (!target.startsWith("http://") && !target.startsWith("https://")) {
          target = `http://${target}`;
        }
      } else if (selectedScanner === "nmap") {
        options.no_ping = true;
        if (target.startsWith("http://") || target.startsWith("https://")) {
          try {
            const parsed = new URL(target);
            target = parsed.hostname;
            if (parsed.port) {
              options.ports = parsed.port;
            }
          } catch {
            target = target.replace(/^https?:\/\//, "").split("/")[0];
          }
        } else if (target.includes(":") && !target.includes("/")) {
          const parts = target.split(":");
          target = parts[0];
          if (parts[1] && /^\d+$/.test(parts[1])) {
            options.ports = parts[1];
          }
        }
      }
      await api.launchScan({
        engagement_id: activeEngagement.engagement_id,
        scanner: selectedScanner,
        target: target,
        options: options,
      });
      setTargetInput("");
      setScopeWarning(null);
      await refreshData();
    } catch (err: any) {
      console.error("Launch scan error:", err);
      setApiError(err.message || "Failed to dispatch scan.");
    } finally {
      setIsLaunching(false);
    }
  };

  // Create Engagement Form Submit
  const handleCreateEngagementSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateSubmitting(true);
    setCreateError(null);

    try {
      const granted = createForm.granted_at
        ? new Date(createForm.granted_at).toISOString()
        : new Date().toISOString();
      const expires = createForm.expires_at
        ? new Date(createForm.expires_at).toISOString()
        : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

      const allowlistArr = createForm.allowlist
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      if (allowlistArr.length === 0) {
        throw new Error("At least one allowlist target pattern is required.");
      }

      const payload: CreateEngagementPayload = {
        engagement_id:
          createForm.engagement_id.trim() ||
          `eng-${crypto.randomUUID().slice(0, 8)}`,
        name: createForm.name.trim(),
        authorized_by: createForm.authorized_by.trim(),
        allowlist: allowlistArr,
        granted_at: granted,
        expires_at: expires,
      };

      if (!payload.name) {
        throw new Error("Assessment name is required.");
      }
      if (!payload.authorized_by) {
        throw new Error(
          "Authorized By is required. Every engagement must name a real human authorizer."
        );
      }

      const created = await api.createEngagement(payload);
      setShowCreateModal(false);
      setSelectedEngagementId(created.engagement_id);
      setCreateForm({
        engagement_id: "",
        name: "",
        authorized_by: "",
        allowlist: "127.0.0.1, 127.0.0.1/32, localhost",
        granted_at: "",
        expires_at: "",
      });
      await refreshData();
    } catch (err: any) {
      setCreateError(err.message || "Failed to create engagement.");
    } finally {
      setCreateSubmitting(false);
    }
  };

  // Inspect Scan Observations
  const handleInspectScan = async (scan: ScanItem) => {
    setObsLoading(true);
    try {
      const res = await api.getScanObservations(scan.scan_id);
      setSelectedScanObservations({ scan, items: res.items });
    } catch (err: any) {
      setApiError(`Could not fetch observations: ${err.message}`);
    } finally {
      setObsLoading(false);
    }
  };

  return (
    <div className="dashboard-shell">
      {/* ----------------- SIDEBAR ----------------- */}
      <aside className="db-sidebar">
        <div className="db-sidebar-top-section">
          {/* Logo & Brand */}
          <div className="db-sidebar-logo-container">
            <Link href="/" className="db-sidebar-logo">
              <svg
                className="db-sidebar-logo-icon"
                viewBox="0 0 40 40"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <polygon
                  points="20,2 36,11 36,29 20,38 4,29 4,11"
                  stroke="#ffffff"
                  strokeWidth="2.5"
                  fill="rgba(8, 12, 24, 0.9)"
                />
                <polygon
                  points="20,9 30,15 30,25 20,31 10,25 10,15"
                  stroke="#ffffff"
                  strokeWidth="1.8"
                  fill="none"
                />
                <polygon points="20,15 25,20 20,25 15,20" fill="#ffffff" />
              </svg>
              <div className="db-sidebar-brand">SEEKTHREAT</div>
            </Link>
            <div className="db-sidebar-tagline">See What Others Miss.</div>
          </div>

          {/* Nav Items */}
          <nav className="db-nav">
            <div
              className={`db-nav-item ${activeNav === "Overview" ? "active" : ""}`}
              onClick={() => setActiveNav("Overview")}
            >
              <div className="db-nav-item-inner">
                <svg className="db-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
                  <polyline points="9 22 9 12 15 12 15 22" />
                </svg>
                <span>Overview</span>
              </div>
            </div>

            <div
              className={`db-nav-item ${activeNav === "Engagements" ? "active" : ""}`}
              onClick={() => setActiveNav("Engagements")}
            >
              <div className="db-nav-item-inner">
                <svg className="db-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <span>Engagements</span>
              </div>
            </div>

            <div
              className={`db-nav-item ${activeNav === "Scans" ? "active" : ""}`}
              onClick={() => setActiveNav("Scans")}
            >
              <div className="db-nav-item-inner">
                <svg className="db-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
                <span>Scans</span>
              </div>
            </div>

            <div className="db-nav-item">
              <div className="db-nav-item-inner">
                <svg className="db-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                <span>Observations</span>
              </div>
              <span className="db-coming-soon">Active</span>
            </div>

            <div className="db-nav-item">
              <div className="db-nav-item-inner">
                <svg className="db-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="3" />
                  <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                </svg>
                <span>Findings</span>
              </div>
              <span className="db-coming-soon">Coming Soon</span>
            </div>

            <div className="db-nav-item">
              <div className="db-nav-item-inner">
                <svg className="db-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="6" y1="3" x2="6" y2="15" />
                  <circle cx="18" cy="6" r="3" />
                  <circle cx="6" cy="18" r="3" />
                  <path d="M18 9a9 9 0 0 1-9 9" />
                </svg>
                <span>Attack Paths</span>
              </div>
              <span className="db-coming-soon">Coming Soon</span>
            </div>

            <div className="db-nav-item">
              <div className="db-nav-item-inner">
                <svg className="db-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76" />
                </svg>
                <span>Threat Intelligence</span>
              </div>
              <span className="db-coming-soon">Coming Soon</span>
            </div>

            <div className="db-nav-item">
              <div className="db-nav-item-inner">
                <svg className="db-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="2" />
                  <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
                </svg>
                <span>AI Assistant</span>
              </div>
              <span className="db-coming-soon">Coming Soon</span>
            </div>

            <div className="db-nav-item">
              <div className="db-nav-item-inner">
                <svg className="db-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                  <line x1="16" y1="13" x2="8" y2="13" />
                  <line x1="16" y1="17" x2="8" y2="17" />
                </svg>
                <span>Reports</span>
              </div>
              <span className="db-coming-soon">Coming Soon</span>
            </div>
          </nav>
        </div>

        {/* Lower Sidebar: 3D Orbit Graphic + Authorization Card + Footer */}
        <div className="db-sidebar-bottom-section">
          <SidebarOrbit />

          {/* Authorization Status Card */}
          <div className="db-auth-card">
            <div className="db-auth-card-top">
              <div className="db-auth-card-icon-box">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              </div>
              <div>
                <div className="db-auth-card-label">Authorization Status</div>
                <div className="db-auth-badge">
                  <span
                    className="db-auth-badge-dot"
                    style={{
                      background:
                        authStatus === "active"
                          ? "#20D6A3"
                          : authStatus === "not-yet-active"
                          ? "#D8AA45"
                          : "#E45D68",
                    }}
                  />
                  <span style={{ textTransform: "capitalize" }}>
                    {authStatus === "not-yet-active" ? "Not Yet Active" : authStatus}
                  </span>
                </div>
              </div>
            </div>
            <div className="db-auth-details">
              <div>
                Authorized by: <span>{activeEngagement ? activeEngagement.authorized_by : "—"}</span>
              </div>
              <div>
                Scope:{" "}
                <span>
                  {activeEngagement && activeEngagement.allowlist.length > 0
                    ? activeEngagement.allowlist.join(", ")
                    : "None"}
                </span>
              </div>
              <div>
                Expires:{" "}
                <span>
                  {activeEngagement ? formatDateStr(activeEngagement.expires_at) : "—"}
                </span>
              </div>
            </div>
          </div>

          {/* Sidebar Footer */}
          <div className="db-sidebar-footer">
            <span className="db-footer-crumb">SECURITY</span>
            <span className="db-footer-sep">•</span>
            <span className="db-footer-crumb">INTELLIGENCE</span>
            <span className="db-footer-sep">•</span>
            <span className="db-footer-crumb">ACTION</span>
          </div>
        </div>
      </aside>

      {/* ----------------- MAIN AREA ----------------- */}
      <main className="db-main">
        {/* TOP BAR */}
        <header className="db-topbar">
          <div className="db-topbar-left">
            <div className="db-topbar-shield">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div className="db-topbar-titles">
              <span className="db-topbar-title">Security Command Center</span>
              <span className="db-topbar-subtitle">Centralized Vulnerability Intelligence.</span>
            </div>
          </div>

          <div className="db-topbar-right">
            {/* Current Engagement Selector */}
            <div className="db-topbar-engagement">
              <div className="db-topbar-eng-icon">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              </div>
              <div className="db-topbar-eng-text">
                <span className="db-topbar-eng-label">Current Engagement</span>
                <span className="db-topbar-eng-val">
                  {activeEngagement ? activeEngagement.name : "No Engagement"}
                </span>
              </div>
              <span className={`db-status-pill ${authStatus}`}>
                <span className="db-pill-dot" />
                <span style={{ textTransform: "capitalize" }}>
                  {authStatus === "not-yet-active" ? "Pending" : authStatus}
                </span>
              </span>
            </div>

            {/* API Reachability Badge */}
            <div className="db-online-badge">
              <span
                className="db-pulse-dot"
                style={{
                  background: loading
                    ? "#D9B85C"
                    : apiError
                    ? "#E56B73"
                    : "#20D6A3",
                }}
              />
              <span>
                {loading
                  ? "Syncing..."
                  : apiError
                  ? "API unreachable"
                  : "API reachable"}
              </span>
            </div>

          </div>
        </header>

        {/* DASHBOARD CANVAS */}
        <div className="db-canvas">
          {/* Real Backend Error Alert Banner */}
          {apiError && (
            <div className="db-error-banner">
              <div className="db-error-banner-left">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>{apiError}</span>
              </div>
              <button className="db-error-close" onClick={() => setApiError(null)}>
                ✕
              </button>
            </div>
          )}

          {/* Maximum Polling Guard Notice */}
          {pollGuardExceeded && (
            <div className="db-scope-warning" style={{ marginBottom: "1rem", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>
                  Maximum polling duration reached (5 minutes). Background polling paused to conserve resources.
                </span>
              </div>
              <button
                type="button"
                className="db-suggestion-pill"
                style={{ cursor: "pointer", background: "rgba(255,255,255,0.1)", border: "1px solid rgba(255,255,255,0.2)", whiteSpace: "nowrap" }}
                onClick={handleManualRefresh}
              >
                Resume Polling
              </button>
            </div>
          )}

          {/* BANNER: ACTIVE ENGAGEMENT SCOPE */}
          <section className="db-banner">
            <div className="db-banner-left">
              <div className="db-banner-badge-row">
                <svg className="db-banner-shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <span className="db-banner-category">SECURITY ENGAGEMENT</span>
              </div>

              <div className="db-banner-title-group">
                <h1 className="db-banner-title">
                  {activeEngagement ? activeEngagement.name : "No Engagement Selected"}
                </h1>
              </div>

              <div className="db-banner-meta-grid">
                <div className="db-banner-meta-item">
                  <div className="db-banner-meta-icon-box">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                      <circle cx="12" cy="7" r="4" />
                    </svg>
                  </div>
                  <div className="db-banner-meta-text">
                    <span className="db-banner-meta-label">Authorized by</span>
                    <span className="db-banner-meta-value">
                      {activeEngagement ? activeEngagement.authorized_by : "—"}
                    </span>
                  </div>
                </div>

                <div className="db-banner-meta-item">
                  <div className="db-banner-meta-icon-box">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="22" y1="12" x2="18" y2="12" />
                      <line x1="6" y1="12" x2="2" y2="12" />
                      <line x1="12" y1="6" x2="12" y2="2" />
                      <line x1="12" y1="22" x2="12" y2="18" />
                    </svg>
                  </div>
                  <div className="db-banner-meta-text">
                    <span className="db-banner-meta-label">Target Scope</span>
                    <span className="db-banner-meta-value">
                      {activeEngagement && activeEngagement.allowlist.length > 0
                        ? activeEngagement.allowlist.join(", ")
                        : "—"}
                    </span>
                  </div>
                </div>

                <div className="db-banner-meta-item">
                  <div className="db-banner-meta-icon-box">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="4" width="18" height="18" rx="2" ry="2" />
                      <line x1="16" y1="2" x2="16" y2="6" />
                      <line x1="8" y1="2" x2="8" y2="6" />
                      <line x1="3" y1="10" x2="21" y2="10" />
                    </svg>
                  </div>
                  <div className="db-banner-meta-text">
                    <span className="db-banner-meta-label">Expires in</span>
                    <span className="db-banner-meta-value">
                      {activeEngagement ? formatExpiresIn(activeEngagement.expires_at) : "—"}
                    </span>
                  </div>
                </div>

                {/* Floating Status Badge */}
                <div className="db-banner-shield-col">
                  <span className={`db-status-pill ${authStatus}`}>
                    <span className="db-pill-dot" />
                    <span style={{ textTransform: "capitalize" }}>
                      {authStatus === "not-yet-active" ? "Not Yet Active" : authStatus}
                    </span>
                  </span>
                  <div className="db-banner-shield-badge">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#F4F7F8" strokeWidth="2">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                  </div>
                </div>
              </div>
            </div>

            {/* Banner Right: Globe & Scope Allowlist List */}
            <div className="db-banner-right">
              <DashboardGlobe />

              <div className="db-banner-scope-box">
                <div className="db-scope-box-header">AUTHORIZED SCOPE</div>
                {activeEngagement && activeEngagement.allowlist.length > 0 ? (
                  activeEngagement.allowlist.slice(0, 4).map((entry, idx) => (
                    <div key={idx} className="db-scope-row">
                      <span className="db-scope-ip">{entry}</span>
                      <span className="db-scope-tag">ALLOW</span>
                    </div>
                  ))
                ) : (
                  <div className="db-scope-row">
                    <span className="db-scope-ip">No Scope Defined</span>
                  </div>
                )}
              </div>
            </div>
          </section>

          {/* MIDDLE ROW: LAUNCH NEW SCAN & RECENT SCANS */}
          <div className="db-middle-row">
            {/* Launch New Scan Card */}
            <div className="db-card">
              <div className="db-card-header">
                <div className="db-card-title-wrap">
                  <div className="db-card-header-icon">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                  </div>
                  <div className="db-card-title-texts">
                    <h2 className="db-card-title">Launch New Scan</h2>
                    <span className="db-card-subtitle">Start an authorized scan verified by backend choke point.</span>
                  </div>
                </div>
              </div>

              <form className="db-card-body" onSubmit={handleLaunchScan}>
                {/* Engagement selector */}
                <div className="db-form-field">
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.4rem" }}>
                    <label className="db-form-label" style={{ margin: 0 }}>Engagement Scope</label>
                    <button
                      type="button"
                      onClick={() => setShowCreateModal(true)}
                      style={{
                        background: "none",
                        border: "none",
                        color: "#20D6A3",
                        fontSize: "0.75rem",
                        fontWeight: 600,
                        cursor: "pointer",
                        padding: 0,
                      }}
                    >
                      + New Scope
                    </button>
                  </div>
                  {engagements.length === 0 ? (
                    <div
                      onClick={() => setShowCreateModal(true)}
                      style={{
                        padding: "0.6rem 0.85rem",
                        background: "rgba(216, 170, 69, 0.08)",
                        border: "1px dashed rgba(216, 170, 69, 0.4)",
                        borderRadius: "8px",
                        cursor: "pointer",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                      }}
                    >
                      <span style={{ fontSize: "0.8rem", color: "#D8AA45", fontWeight: 500 }}>
                        No authorized scope registered. Click to create one.
                      </span>
                      <span style={{ fontSize: "0.75rem", color: "#F5F7F8", fontWeight: 600, textDecoration: "underline" }}>
                        Create Scope
                      </span>
                    </div>
                  ) : (
                    <div className="db-engagement-selector" style={{ position: "relative" }}>
                      <select
                        value={selectedEngagementId}
                        onChange={(e) => setSelectedEngagementId(e.target.value)}
                        style={{
                          width: "100%",
                          background: "transparent",
                          border: "none",
                          color: "#F5F7F8",
                          fontWeight: 600,
                          fontSize: "0.85rem",
                          outline: "none",
                          cursor: "pointer",
                          appearance: "none",
                        }}
                      >
                        {engagements.map((eng) => (
                          <option
                            key={eng.engagement_id}
                            value={eng.engagement_id}
                            style={{ background: "#0B1012", color: "#F5F7F8" }}
                          >
                            {eng.name} ({eng.engagement_id})
                          </option>
                        ))}
                      </select>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#7B8A8D" strokeWidth="2">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>
                  )}
                </div>

                {/* Scanner select: [ Nmap ] & [ Nuclei ] */}
                <div className="db-form-field">
                  <label className="db-form-label">Scanner</label>
                  <div className="db-scanner-switch">
                    <div
                      className={`db-scanner-opt ${selectedScanner === "nmap" ? "selected" : ""}`}
                      onClick={() => setSelectedScanner("nmap")}
                    >
                      <div className="db-scanner-opt-left">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                          <circle cx="12" cy="12" r="3" />
                        </svg>
                        <span>Nmap (Network & Ports)</span>
                      </div>
                      {selectedScanner === "nmap" && (
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                          <polyline points="9 18 15 12 9 6" />
                        </svg>
                      )}
                    </div>

                    <div
                      className={`db-scanner-opt ${selectedScanner === "nuclei" ? "selected" : ""}`}
                      onClick={() => setSelectedScanner("nuclei")}
                    >
                      <div className="db-scanner-opt-left">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        </svg>
                        <span>Nuclei (Vulnerabilities)</span>
                      </div>
                      {selectedScanner === "nuclei" && (
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                          <polyline points="9 18 15 12 9 6" />
                        </svg>
                      )}
                    </div>
                  </div>
                </div>

                {/* Target input */}
                <div className="db-form-field">
                  <label className="db-form-label">Target (IP, hostname, or URL)</label>
                  <div className="db-input-wrapper">
                    <input
                      type="text"
                      className="db-input"
                      placeholder={
                        activeEngagement && activeEngagement.allowlist.length > 0
                          ? `e.g. ${activeEngagement.allowlist[0]}`
                          : "Enter IP, hostname, or URL"
                      }
                      value={targetInput}
                      onChange={(e) => handleTargetChange(e.target.value)}
                    />
                    <svg className="db-input-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="6 9 12 15 18 9" />
                    </svg>
                  </div>
                </div>

                {/* Scope Warning Alert if outside allowlist */}
                {scopeWarning && (
                  <div className="db-scope-warning">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="12" y1="8" x2="12" y2="12" />
                      <line x1="12" y1="16" x2="12.01" y2="16" />
                    </svg>
                    <span>{scopeWarning}</span>
                  </div>
                )}

                {/* Authorized Scope Suggestions from Active Engagement */}
                {activeEngagement && activeEngagement.allowlist.length > 0 && (
                  <div className="db-form-field">
                    <span className="db-suggestions-title">Authorized Scope Shortcuts</span>
                    <div className="db-suggestions-grid">
                      {activeEngagement.allowlist.map((pattern) => (
                        <button
                          type="button"
                          key={pattern}
                          className="db-suggestion-pill"
                          onClick={() => handleTargetChange(pattern)}
                        >
                          {pattern}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Launch Scan Button */}
                <button
                  type={activeEngagement ? "submit" : "button"}
                  className="db-btn-launch"
                  disabled={isLaunching || !!scopeWarning}
                  onClick={(e) => {
                    if (!activeEngagement) {
                      e.preventDefault();
                      setShowCreateModal(true);
                    }
                  }}
                >
                  <span>
                    {isLaunching
                      ? "Launching Scan..."
                      : !activeEngagement
                      ? "Register Engagement First"
                      : "Launch Scan"}
                  </span>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <line x1="5" y1="12" x2="19" y2="12" />
                    <polyline points="12 5 19 12 12 19" />
                  </svg>
                </button>
              </form>
            </div>

            {/* Recent Scans Card */}
            <div className="db-card">
              <div className="db-card-header">
                <div className="db-card-title-wrap">
                  <div className="db-card-header-icon">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                      <polyline points="23 4 23 10 17 10" />
                      <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
                    </svg>
                  </div>
                  <div className="db-card-title-texts">
                    <h2 className="db-card-title">Recent Scans</h2>
                  </div>
                </div>
                <button className="db-card-action-btn" onClick={handleManualRefresh}>
                  <span>Refresh</span>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="23 4 23 10 17 10" />
                    <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
                  </svg>
                </button>
              </div>

              <div className="db-card-body" style={{ padding: "0.5rem 0 0 0" }}>
                {scans.length === 0 ? (
                  <div className="db-empty-state">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#667276" strokeWidth="1.5">
                      <circle cx="11" cy="11" r="8" />
                      <line x1="21" y1="21" x2="16.65" y2="16.65" />
                    </svg>
                    <div className="db-empty-state-title">No scans executed yet</div>
                    <div className="db-empty-state-desc">
                      Launch your first Nmap or Nuclei scan against an authorized scope.
                    </div>
                  </div>
                ) : (
                  <div className="db-table-container">
                    <table className="db-table">
                      <thead>
                        <tr>
                          <th>Scanner</th>
                          <th>Target</th>
                          <th>Status</th>
                          <th>Started</th>
                          <th>Findings</th>
                          <th style={{ width: "30px" }}></th>
                        </tr>
                      </thead>
                      <tbody>
                        {scans.map((scan) => {
                          const durationStr =
                            scan.status === "running" || scan.status === "pending"
                              ? formatDuration(scan.created_at, null)
                              : scan.completed_at
                              ? formatDuration(scan.created_at, scan.completed_at)
                              : "—";

                          return (
                            <tr key={scan.scan_id}>
                              <td>
                                <div className="db-scanner-badge">
                                  {scan.scanner === "nuclei" ? (
                                    <svg className="db-scanner-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                    </svg>
                                  ) : (
                                    <svg className="db-scanner-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                                      <circle cx="12" cy="12" r="3" />
                                    </svg>
                                  )}
                                  <span style={{ textTransform: "capitalize" }}>{scan.scanner}</span>
                                </div>
                              </td>
                              <td>
                                <span className="db-table-ip">{formatScanTarget(scan)}</span>
                              </td>
                              <td>
                                <span className={`db-status-pill ${scan.status}`} title={scan.error_message || undefined}>
                                  <span className="db-pill-dot" />
                                  <span style={{ textTransform: "capitalize" }}>{scan.status}</span>
                                </span>
                                {scan.status === "failed" && scan.error_message && (
                                  <div
                                    className="db-table-error-detail"
                                    style={{
                                      fontSize: "0.72rem",
                                      color: "#E56B73",
                                      marginTop: "0.25rem",
                                      maxWidth: "200px",
                                      overflow: "hidden",
                                      textOverflow: "ellipsis",
                                      whiteSpace: "nowrap",
                                    }}
                                    title={scan.error_message}
                                  >
                                    {scan.error_message}
                                  </div>
                                )}
                              </td>
                              <td>
                                <div className="db-table-time">
                                  <span className="db-table-date-str">{formatDateStr(scan.created_at)}</span>
                                  <span className="db-table-duration">
                                    {scan.status === "running" ? `Elapsed: ${durationStr}` : durationStr}
                                  </span>
                                </div>
                              </td>
                              <td>
                                <span style={{ fontSize: "0.75rem", color: scan.observation_count > 0 ? "#20D6A3" : "#A7B2B5" }}>
                                  {scan.observation_count} obs
                                </span>
                              </td>
                              <td>
                                <button
                                  className="db-more-btn"
                                  onClick={() => handleInspectScan(scan)}
                                  title="View observations & details"
                                >
                                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <circle cx="12" cy="12" r="1.5" />
                                    <circle cx="12" cy="5" r="1.5" />
                                    <circle cx="12" cy="19" r="1.5" />
                                  </svg>
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* BOTTOM ROW: ENGAGEMENTS & SCAN ACTIVITY */}
          <div className="db-bottom-row">
            {/* Engagements List */}
            <div className="db-card">
              <div className="db-card-header">
                <div className="db-card-title-wrap">
                  <div className="db-card-header-icon">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                      <circle cx="9" cy="7" r="4" />
                      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                    </svg>
                  </div>
                  <div className="db-card-title-texts">
                    <h2 className="db-card-title">Engagements</h2>
                    <span className="db-card-subtitle">Active security authorizations scoping scan boundaries.</span>
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "0.85rem" }}>
                  <button className="db-btn-create-eng" onClick={() => setShowCreateModal(true)}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                      <line x1="12" y1="5" x2="12" y2="19" />
                      <line x1="5" y1="12" x2="19" y2="12" />
                    </svg>
                    <span>Create Engagement</span>
                  </button>
                </div>
              </div>

              <div className="db-card-body" style={{ padding: "0.5rem 0 0 0" }}>
                {engagements.length === 0 ? (
                  <div className="db-empty-state">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#667276" strokeWidth="1.5">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                    <div className="db-empty-state-title">No engagements registered</div>
                    <div className="db-empty-state-desc">
                      Create an engagement with an authorized target scope to start scanning.
                    </div>
                  </div>
                ) : (
                  <div className="db-table-container">
                    <table className="db-table">
                      <thead>
                        <tr>
                          <th>Name</th>
                          <th>ID</th>
                          <th>Authorized By</th>
                          <th>Target Scope</th>
                          <th>Status</th>
                          <th>Expires</th>
                        </tr>
                      </thead>
                      <tbody>
                        {engagements.map((eng) => {
                          const status = computeEngagementStatus(eng.granted_at, eng.expires_at);
                          const isSelected = eng.engagement_id === selectedEngagementId;

                          return (
                            <tr
                              key={eng.engagement_id}
                              onClick={() => setSelectedEngagementId(eng.engagement_id)}
                              style={{
                                cursor: "pointer",
                                background: isSelected ? "rgba(255, 255, 255, 0.04)" : "transparent",
                              }}
                            >
                              <td>
                                <div style={{ display: "flex", alignItems: "center", gap: "0.55rem" }}>
                                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#7B8A8D" strokeWidth="2">
                                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                                    <circle cx="12" cy="7" r="4" />
                                  </svg>
                                  <span style={{ fontWeight: 600, color: "#F4F7F7" }}>{eng.name}</span>
                                </div>
                              </td>
                              <td>
                                <span className="db-eng-id">{eng.engagement_id}</span>
                              </td>
                              <td>
                                <span style={{ color: "#9BA6A8" }}>{eng.authorized_by}</span>
                              </td>
                              <td>
                                <span className="db-table-ip">{eng.allowlist.join(", ")}</span>
                              </td>
                              <td>
                                <span className={`db-status-pill ${status}`}>
                                  <span className="db-pill-dot" />
                                  <span style={{ textTransform: "capitalize" }}>
                                    {status === "not-yet-active" ? "Not Yet Active" : status}
                                  </span>
                                </span>
                              </td>
                              <td>
                                <span style={{ color: "#9BA6A8", fontSize: "0.75rem" }}>
                                  {formatExpiresIn(eng.expires_at)}
                                </span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>

            {/* Live Scan Activity Feed */}
            <div className="db-card">
              <div className="db-card-header">
                <div className="db-card-title-wrap">
                  <div className="db-card-header-icon">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                    </svg>
                  </div>
                  <div className="db-card-title-texts">
                    <h2 className="db-card-title">Scan Activity</h2>
                    <span className="db-card-subtitle">Real-time status across all active jobs</span>
                  </div>
                </div>
              </div>

              <div className="db-card-body">
                {scans.length === 0 ? (
                  <div className="db-empty-state">
                    <div className="db-empty-state-title">No scan activity yet</div>
                  </div>
                ) : (
                  <div className="db-activity-list">
                    {scans.slice(0, 5).map((scan) => {
                      const dotColor =
                        scan.status === "completed"
                          ? "#20D6A3"
                          : scan.status === "running"
                          ? "#6DB8FF"
                          : scan.status === "failed"
                          ? "#E56B73"
                          : "#D9B85C";

                      const durationStr =
                        scan.status === "running" || scan.status === "pending"
                          ? formatDuration(scan.created_at, null)
                          : scan.completed_at
                          ? formatDuration(scan.created_at, scan.completed_at)
                          : "—";

                      return (
                        <div key={`act-${scan.scan_id}`} className="db-activity-row">
                          <div className="db-activity-left">
                            <div className="db-activity-dot-wrap">
                              <span
                                className="db-activity-dot"
                                style={{
                                  background: dotColor,
                                  boxShadow: `0 0 6px ${dotColor}`,
                                }}
                              />
                            </div>
                            <div className="db-activity-info">
                              <span className="db-activity-title">
                                {scan.scanner === "nuclei" ? "Nuclei Vulnerability Scan" : "Nmap Network Scan"}
                              </span>
                              <span className="db-activity-target">{formatScanTarget(scan)}</span>
                            </div>
                          </div>

                          <div className="db-activity-right">
                            <div className="db-activity-time-group">
                              <span className={`db-status-pill ${scan.status}`}>
                                <span className="db-pill-dot" />
                                <span style={{ textTransform: "capitalize" }}>{scan.status}</span>
                              </span>
                              <span className="db-activity-time">{formatDateStr(scan.created_at)}</span>
                            </div>
                            <span className="db-activity-duration">{durationStr}</span>
                            {scan.status === "failed" && scan.error_message && (
                              <span
                                style={{
                                  fontSize: "0.68rem",
                                  color: "#E56B73",
                                  marginTop: "0.15rem",
                                  display: "block",
                                  textAlign: "right",
                                  maxWidth: "180px",
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                }}
                                title={scan.error_message}
                              >
                                {scan.error_message}
                              </span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* ----------------- CREATE ENGAGEMENT MODAL ----------------- */}
      {showCreateModal && (
        <div className="db-modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="db-modal-box" onClick={(e) => e.stopPropagation()}>
            <div className="db-modal-header">
              <div className="db-modal-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <span>Register Authorized Engagement</span>
              </div>
              <button className="db-modal-close-btn" onClick={() => setShowCreateModal(false)}>
                ✕
              </button>
            </div>

            {createError && (
              <div className="db-scope-warning" style={{ margin: 0 }}>
                <span>{createError}</span>
              </div>
            )}

            <form className="db-modal-form" onSubmit={handleCreateEngagementSubmit}>
              <div className="db-form-field">
                <label className="db-form-label">Engagement ID</label>
                <div className="db-input-wrapper">
                  <input
                    type="text"
                    className="db-input"
                    placeholder="e.g. eng-lab-01"
                    value={createForm.engagement_id}
                    onChange={(e) => setCreateForm({ ...createForm, engagement_id: e.target.value })}
                  />
                </div>
              </div>

              <div className="db-form-field">
                <label className="db-form-label">Assessment Name</label>
                <div className="db-input-wrapper">
                  <input
                    type="text"
                    className="db-input"
                    placeholder="e.g. Local Lab Assessment"
                    value={createForm.name}
                    onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div className="db-form-field">
                <label className="db-form-label">Authorized By (Named Human)</label>
                <div className="db-input-wrapper">
                  <input
                    type="text"
                    className="db-input"
                    placeholder="e.g. Lead Security Officer"
                    value={createForm.authorized_by}
                    onChange={(e) => setCreateForm({ ...createForm, authorized_by: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div className="db-form-field">
                <label className="db-form-label">Target Scope / Allowlist (comma-separated)</label>
                <div className="db-input-wrapper">
                  <input
                    type="text"
                    className="db-input"
                    placeholder="e.g. 127.0.0.1, 127.0.0.1/32, localhost, 172.20.0.0/16"
                    value={createForm.allowlist}
                    onChange={(e) => setCreateForm({ ...createForm, allowlist: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div className="db-modal-actions">
                <button
                  type="button"
                  className="db-btn-secondary"
                  onClick={() => setShowCreateModal(false)}
                >
                  Cancel
                </button>
                <button type="submit" className="db-btn-launch" disabled={createSubmitting}>
                  <span>{createSubmitting ? "Registering..." : "Create & Authorize"}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ----------------- SCAN DETAILS & OBSERVATIONS MODAL ----------------- */}
      {selectedScanObservations && (
        <div className="db-modal-overlay" onClick={() => setSelectedScanObservations(null)}>
          <div className="db-modal-box" style={{ maxWidth: "680px" }} onClick={(e) => e.stopPropagation()}>
            <div className="db-modal-header">
              <div className="db-modal-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
                <span>Scan Details — {selectedScanObservations.scan.scan_id}</span>
              </div>
              <button className="db-modal-close-btn" onClick={() => setSelectedScanObservations(null)}>
                ✕
              </button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", fontSize: "0.8rem" }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
                <div>
                  <span style={{ color: "#7B8A8D" }}>Scanner: </span>
                  <span style={{ fontWeight: 600, color: "#F4F7F8", textTransform: "capitalize" }}>
                    {selectedScanObservations.scan.scanner}
                  </span>
                </div>
                <div>
                  <span style={{ color: "#7B8A8D" }}>Target: </span>
                  <span style={{ fontFamily: "monospace", color: "#F4F7F8" }}>
                    {formatScanTarget(selectedScanObservations.scan)}
                  </span>
                </div>
                <div>
                  <span style={{ color: "#7B8A8D" }}>Status: </span>
                  <span className={`db-status-pill ${selectedScanObservations.scan.status}`}>
                    <span className="db-pill-dot" />
                    <span style={{ textTransform: "capitalize" }}>{selectedScanObservations.scan.status}</span>
                  </span>
                </div>
                <div>
                  <span style={{ color: "#7B8A8D" }}>Artifact ID: </span>
                  <span style={{ fontFamily: "monospace", fontSize: "0.7rem", color: "#A7B2B5" }}>
                    {selectedScanObservations.scan.artifact_id || "None"}
                  </span>
                </div>
              </div>

              {selectedScanObservations.scan.error_message && (
                <div className="db-scope-warning" style={{ margin: "0.5rem 0" }}>
                  <span>Error: {selectedScanObservations.scan.error_message}</span>
                </div>
              )}

              <div style={{ borderTop: "1px solid rgba(217, 226, 229, 0.1)", paddingTop: "0.75rem" }}>
                <div style={{ fontWeight: 600, marginBottom: "0.5rem", color: "#F4F7F8" }}>
                  Observations ({selectedScanObservations.items.length})
                </div>

                {obsLoading ? (
                  <div style={{ color: "#7B8A8D", padding: "1rem" }}>Loading observations...</div>
                ) : selectedScanObservations.items.length === 0 ? (
                  <div style={{ color: "#7B8A8D", padding: "0.5rem 0" }}>
                    No observations found for this scan.
                  </div>
                ) : (
                  <div style={{ maxHeight: "250px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                    {selectedScanObservations.items.map((obs) => (
                      <div
                        key={obs.observation_id}
                        style={{
                          background: "rgba(255, 255, 255, 0.03)",
                          border: "1px solid rgba(217, 226, 229, 0.1)",
                          borderRadius: "6px",
                          padding: "0.5rem 0.75rem",
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "flex-start",
                        }}
                      >
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontWeight: 600, color: "#20D6A3", fontSize: "0.76rem" }}>
                            {obs.kind.toUpperCase()} — {obs.subject}
                          </div>
                          <div style={{ fontSize: "0.7rem", color: "#7B8A8D", fontFamily: "monospace", marginTop: "0.2rem" }}>
                            {JSON.stringify(obs.attributes)}
                          </div>
                          {obs.provenance && (
                            <div style={{ fontSize: "0.68rem", color: "#9BA6A8", marginTop: "0.25rem", display: "flex", gap: "0.75rem" }}>
                              <span>
                                Source:{" "}
                                <span style={{ color: "#C5D0D3", fontWeight: 500 }}>
                                  {obs.provenance.source}
                                </span>
                              </span>
                              <span>
                                Confidence:{" "}
                                <span style={{ color: "#C5D0D3", fontWeight: 500 }}>
                                  {obs.provenance.confidence}
                                </span>
                              </span>
                            </div>
                          )}
                        </div>
                        <span style={{ fontSize: "0.68rem", color: "#7B8A8D", marginLeft: "0.75rem", whiteSpace: "nowrap" }}>
                          {formatDateStr(obs.observed_at)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="db-modal-actions">
              <button className="db-btn-secondary" onClick={() => setSelectedScanObservations(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
