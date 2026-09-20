"use client";

import React from "react";

export default function ServerRacksBackground() {
  return (
    <div className="server-racks-atmosphere pointer-events-none select-none">
      {/* 1. Cinematic Datacenter Backdrop Layer Masked at Borders */}
      <div className="datacenter-photo-border-layer"></div>

      {/* 2. Cybernetic Wave Mesh / Digital Frequency Terrain in Background */}
      <div className="cyber-wave-terrain">
        <svg className="cyber-wave-svg" viewBox="0 0 1440 280" preserveAspectRatio="none">
          <defs>
            <linearGradient id="waveCyanGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.45" />
              <stop offset="35%" stopColor="#3b82f6" stopOpacity="0.3" />
              <stop offset="70%" stopColor="#8b5cf6" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#ec4899" stopOpacity="0.25" />
            </linearGradient>
            <linearGradient id="wavePurpleGrad" x1="100%" y1="0%" x2="0%" y2="0%">
              <stop offset="0%" stopColor="#a855f7" stopOpacity="0.35" />
              <stop offset="50%" stopColor="#38bdf8" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#0284c7" stopOpacity="0.1" />
            </linearGradient>
            <filter id="waveGlow" x="-10%" y="-10%" width="120%" height="120%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Flowing cyber waves */}
          <path
            d="M0,180 C240,110 420,240 720,160 C1020,80 1200,210 1440,130"
            fill="none"
            stroke="url(#waveCyanGrad)"
            strokeWidth="2.5"
            filter="url(#waveGlow)"
          />
          <path
            d="M0,210 C200,160 480,270 780,180 C1080,100 1280,220 1440,170"
            fill="none"
            stroke="url(#wavePurpleGrad)"
            strokeWidth="1.8"
          />
          <path
            d="M0,230 C260,190 520,280 840,200 C1140,130 1340,240 1440,195"
            fill="none"
            stroke="rgba(56, 189, 248, 0.2)"
            strokeWidth="1.2"
            strokeDasharray="6 4"
          />
        </svg>
      </div>

      {/* 3. Left Border: Data Breach Server Towers */}
      <div className="rack-cluster rack-left">
        {/* Glowing Red Warning Placard */}
        <div className="rack-hazard-card">
          <div className="hazard-triangle-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="#ef4444">
              <path d="M12 2L1 21h22L12 2zm0 3.8L19.5 19h-15L12 5.8zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z" />
            </svg>
          </div>
        </div>

        {/* Glowing Red THREAT Badge */}
        <div className="rack-badge rack-threat-badge">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="#ef4444">
            <path d="M12 2L1 21h22L12 2zm0 3.8L19.5 19h-15L12 5.8zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z" />
          </svg>
          <span>THREAT</span>
        </div>

        {/* Server unit chassis */}
        <div className="rack-chassis">
          {Array.from({ length: 12 }).map((_, i) => (
            <div key={i} className="rack-slot">
              <div className="rack-leds">
                <span className={`led ${i % 3 === 0 ? "led-red" : i % 2 === 0 ? "led-cyan" : "led-purple"}`}></span>
                <span className="led led-blue"></span>
                <span className="led led-green"></span>
              </div>
              <div className="rack-vent"></div>
            </div>
          ))}
        </div>
      </div>

      {/* 4. Right Border: Tall Server Towers with Multiple DATA BREACH Signs */}
      <div className="rack-cluster rack-right">
        {/* Top Glowing Red Danger Triangle Placard */}
        <div className="rack-hazard-card">
          <div className="hazard-triangle-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="#ef4444">
              <path d="M12 2L1 21h22L12 2zm0 3.8L19.5 19h-15L12 5.8zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z" />
            </svg>
          </div>
        </div>

        {/* Upper DATA BREACH Glowing Banner */}
        <div className="rack-alert-banner">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="#ef4444">
            <path d="M12 2L1 21h22L12 2zm0 3.8L19.5 19h-15L12 5.8zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z" />
          </svg>
          <span>DATA BREACH</span>
        </div>

        {/* Middle Warning Placard */}
        <div className="rack-hazard-mini-box">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="#ef4444">
            <path d="M12 2L1 21h22L12 2zm0 3.8L19.5 19h-15L12 5.8zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z" />
          </svg>
        </div>

        {/* Lower DATA BREACH Glowing Banner */}
        <div className="rack-alert-banner banner-lower">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="#ef4444">
            <path d="M12 2L1 21h22L12 2zm0 3.8L19.5 19h-15L12 5.8zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z" />
          </svg>
          <span>DATA BREACH</span>
        </div>

        {/* Server unit chassis */}
        <div className="rack-chassis chassis-tall">
          {Array.from({ length: 16 }).map((_, i) => (
            <div key={i} className="rack-slot">
              <div className="rack-leds">
                <span className={`led ${i % 2 === 0 ? "led-red" : "led-purple"}`}></span>
                <span className="led led-cyan"></span>
                <span className="led led-blue"></span>
              </div>
              <div className="rack-vent"></div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
