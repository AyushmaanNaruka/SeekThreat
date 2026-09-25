"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import Navbar from "../components/Navbar";
import HeroHeader from "../components/HeroHeader";
import LiveThreatFeed from "../components/LiveThreatFeed";
import ThreatStats from "../components/ThreatStats";
import ThreatGlobe from "../components/ThreatGlobe";
import FeatureDock from "../components/FeatureDock";
import ServerRacksBackground from "../components/ServerRacksBackground";
import DemoModal from "../components/DemoModal";

export default function HomePage() {
  const router = useRouter();
  const [modalMode, setModalMode] = useState<"demo" | "explore" | "auth" | null>(null);

  const handleOpenDemo = () => setModalMode("demo");
  const handleOpenExplore = () => router.push("/dashboard");
  const handleOpenAuth = () => setModalMode("auth");
  const handleCloseModal = () => setModalMode(null);

  return (
    <div className="page-container">
      {/* Background Cyber Infrastructure & Server Racks */}
      <ServerRacksBackground />

      {/* Top Navigation */}
      <Navbar onGetStarted={handleOpenAuth} />

      {/* Main Hero & Cyber Threat Intelligence Centerpiece */}
      <main className="hero-section">
        {/* Left Column: Heading, Subtitle, CTAs, Live Feed, and Stats */}
        <section className="hero-left-column">
          <HeroHeader
            onExplore={handleOpenExplore}
            onWatchDemo={handleOpenDemo}
          />

          <div className="hero-bottom-metrics">
            <LiveThreatFeed />
            <ThreatStats />
          </div>
        </section>

        {/* Right Column: 3D Rotating Cyber Threat Globe with Interactive Pinned Nodes */}
        <section className="hero-right-column">
          <ThreatGlobe />
        </section>
      </main>

      {/* Bottom Floating Feature Dock: Comprehensive Security Pillars */}
      <section className="w-full">
        <FeatureDock />
      </section>

      {/* Interactive Modal (Demo / Platform Explore / Authorization) */}
      <DemoModal
        isOpen={modalMode !== null}
        onClose={handleCloseModal}
        mode={modalMode || "demo"}
      />
    </div>
  );
}
