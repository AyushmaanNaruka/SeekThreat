"use client";

import React from "react";
import { useRouter } from "next/navigation";
import Navbar from "../components/Navbar";
import HeroHeader from "../components/HeroHeader";
import ThreatStats from "../components/ThreatStats";
import ThreatGlobe from "../components/ThreatGlobe";
import FeatureDock from "../components/FeatureDock";
import ServerRacksBackground from "../components/ServerRacksBackground";

export default function HomePage() {
  const router = useRouter();

  const handleOpenExplore = () => router.push("/dashboard");

  return (
    <div id="home" className="page-container">
      {/* Background Cyber Infrastructure & Server Racks (decorative) */}
      <ServerRacksBackground />

      {/* Top Navigation */}
      <Navbar />

      {/* Main Hero */}
      <main className="hero-section">
        {/* Left Column: Heading, Subtitle, CTA and structural guarantees */}
        <section className="hero-left-column">
          <HeroHeader onExplore={handleOpenExplore} />

          <div
            className="hero-bottom-metrics"
            style={{ gridTemplateColumns: "1fr", maxWidth: "420px" }}
          >
            <ThreatStats />
          </div>
        </section>

        {/* Right Column: decorative animated globe */}
        <section className="hero-right-column">
          <ThreatGlobe />
        </section>
      </main>

      {/* Bottom Feature Dock: what the platform does today */}
      <section id="features" className="w-full">
        <FeatureDock />
      </section>
    </div>
  );
}
