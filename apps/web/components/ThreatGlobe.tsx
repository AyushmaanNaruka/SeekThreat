"use client";

import React, { useEffect, useRef, useMemo } from "react";

// Decorative anchor point for the animated arcs. Purely visual: these are not
// observed hosts, threats or locations, so they carry no labels or numbers.
interface ArcAnchor {
  id: string;
  lat: number;
  lon: number;
  color: string;
}

// Realistic Earth continent clusters
const CONTINENT_CENTERS = [
  // North America
  { lat: 45, lon: -100, count: 280, spreadLat: 16, spreadLon: 28 },
  { lat: 55, lon: -115, count: 160, spreadLat: 14, spreadLon: 32 },
  { lat: 34, lon: -85, count: 180, spreadLat: 12, spreadLon: 22 },
  { lat: 20, lon: -102, count: 90, spreadLat: 8, spreadLon: 14 },
  // South America
  { lat: -8, lon: -55, count: 260, spreadLat: 18, spreadLon: 16 },
  { lat: -28, lon: -62, count: 160, spreadLat: 14, spreadLon: 14 },
  // Europe
  { lat: 50, lon: 15, count: 320, spreadLat: 12, spreadLon: 20 },
  { lat: 60, lon: 20, count: 160, spreadLat: 10, spreadLon: 22 },
  { lat: 40, lon: -4, count: 140, spreadLat: 8, spreadLon: 12 },
  // Africa
  { lat: 8, lon: 22, count: 300, spreadLat: 22, spreadLon: 18 },
  { lat: -22, lon: 25, count: 160, spreadLat: 14, spreadLon: 14 },
  // Asia & India
  { lat: 24, lon: 78, count: 260, spreadLat: 14, spreadLon: 18 },
  { lat: 38, lon: 105, count: 360, spreadLat: 18, spreadLon: 30 },
  { lat: 56, lon: 85, count: 220, spreadLat: 14, spreadLon: 40 },
  { lat: 15, lon: 102, count: 160, spreadLat: 10, spreadLon: 16 },
  // Japan & Archipelagos
  { lat: 36, lon: 138, count: 140, spreadLat: 8, spreadLon: 8 },
  { lat: 2, lon: 115, count: 160, spreadLat: 10, spreadLon: 22 },
  // Australia
  { lat: -24, lon: 134, count: 200, spreadLat: 14, spreadLon: 20 },
];

export default function ThreatGlobe() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Rotation angles
  const rotYRef = useRef(1.4);
  const rotXRef = useRef(0.2);
  const isDraggingRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });

  const PINS: ArcAnchor[] = useMemo(() => [
    { id: "a", lat: 44, lon: -78, color: "#ef4444" },
    { id: "b", lat: 58, lon: 50, color: "#38bdf8" },
    { id: "c", lat: 28, lon: 82, color: "#ef4444" },
    { id: "d", lat: 18, lon: -30, color: "#00f0ff" },
    { id: "e", lat: -8, lon: 110, color: "#38bdf8" },
  ], []);

  // Prominent Glowing Danger Triangles on continents
  const DANGER_TRIANGLES = useMemo(() => [
    { id: "dt1", lat: 46, lon: -76 },     // North America
    { id: "dt2", lat: 50, lon: 12 },      // Europe
    { id: "dt3", lat: 26, lon: 80 },      // South Asia
    { id: "dt4", lat: 36, lon: 112 },     // East Asia
    { id: "dt5", lat: -12, lon: -52 },    // South America
    { id: "dt6", lat: 6, lon: 24 },       // Africa
  ], []);

  const ATTACK_ARCS = useMemo(() => [
    { from: "b", to: "c", color: "#ec4899" },
    { from: "c", to: "d", color: "#a855f7" },
    { from: "d", to: "a", color: "#ef4444" },
    { from: "c", to: "e", color: "#00f0ff" },
    { from: "a", to: "b", color: "#6366f1" },
    { from: "b", to: "d", color: "#38bdf8" },
  ], []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;

    interface Particle {
      lat: number;
      lon: number;
      size: number;
      alpha: number;
      isLand: boolean;
      color: string;
    }

    const particles: Particle[] = [];

    // 1. Continental land particles
    CONTINENT_CENTERS.forEach((c) => {
      for (let i = 0; i < c.count; i++) {
        const u = (Math.random() - 0.5) * 2;
        const v = (Math.random() - 0.5) * 2;
        const lat = c.lat + u * c.spreadLat * (0.6 + Math.random() * 0.4);
        const lon = c.lon + v * c.spreadLon * (0.6 + Math.random() * 0.4);
        const isCyan = Math.random() > 0.4;
        particles.push({
          lat,
          lon,
          size: 1.2 + Math.random() * 1.8,
          alpha: 0.65 + Math.random() * 0.35,
          isLand: true,
          color: isCyan ? "#38bdf8" : "#818cf8",
        });
      }
    });

    // 2. Uniform ocean & sphere mesh particles
    const numOcean = 1100;
    const phi = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < numOcean; i++) {
      const y = 1 - (i / (numOcean - 1)) * 2;
      const theta = phi * i;
      const lon = (theta * 180) / Math.PI;
      const lat = Math.asin(y) * (180 / Math.PI);
      particles.push({
        lat,
        lon,
        size: 0.9 + Math.random() * 0.9,
        alpha: 0.2 + Math.random() * 0.3,
        isLand: false,
        color: "#1e3a8a",
      });
    }

    let lastTime = performance.now();
    let packetT = 0;

    const render = (time: number) => {
      const dt = (time - lastTime) / 1000;
      lastTime = time;

      if (!isDraggingRef.current) {
        rotYRef.current += 0.14 * dt;
      }
      packetT = (packetT + dt * 0.35) % 1;

      const width = canvas.clientWidth || 680;
      const height = canvas.clientHeight || 680;
      const dpr = window.devicePixelRatio || 1;

      if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
        canvas.width = width * dpr;
        canvas.height = height * dpr;
      }

      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, width, height);

      const cx = width * 0.52;
      const cy = height * 0.50;
      const R = Math.min(width, height) * 0.38;

      const project = (latDeg: number, lonDeg: number, radius: number = R) => {
        const phi = (90 - latDeg) * (Math.PI / 180);
        const theta = (lonDeg * Math.PI) / 180 + rotYRef.current;
        const tilt = rotXRef.current;

        const x0 = radius * Math.sin(phi) * Math.cos(theta);
        const y0 = radius * Math.cos(phi);
        const z0 = radius * Math.sin(phi) * Math.sin(theta);

        const cosX = Math.cos(tilt);
        const sinX = Math.sin(tilt);
        const x = x0;
        const y = y0 * cosX - z0 * sinX;
        const z = y0 * sinX + z0 * cosX;

        return {
          px: cx + x,
          py: cy - y,
          z,
          visible: z > -radius * 0.2,
        };
      };

      // 1. Cosmic Atmosphere & Nebula Glow
      const bgGlow = ctx.createRadialGradient(cx, cy, R * 0.2, cx, cy, R * 1.4);
      bgGlow.addColorStop(0, "rgba(25, 40, 110, 0.55)");
      bgGlow.addColorStop(0.55, "rgba(56, 189, 248, 0.16)");
      bgGlow.addColorStop(0.8, "rgba(168, 85, 247, 0.12)");
      bgGlow.addColorStop(1, "rgba(3, 7, 18, 0)");
      ctx.fillStyle = bgGlow;
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.4, 0, Math.PI * 2);
      ctx.fill();

      // Deep Dark Inner Core
      const innerCore = ctx.createRadialGradient(cx - R * 0.2, cy - R * 0.25, R * 0.1, cx, cy, R);
      innerCore.addColorStop(0, "rgba(10, 18, 45, 0.96)");
      innerCore.addColorStop(0.8, "rgba(4, 9, 26, 0.98)");
      innerCore.addColorStop(1, "rgba(2, 6, 23, 0.99)");
      ctx.fillStyle = innerCore;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.fill();

      // Outer Atmosphere Rim Rings
      ctx.strokeStyle = "rgba(56, 189, 248, 0.45)";
      ctx.lineWidth = 1.8;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.stroke();

      ctx.strokeStyle = "rgba(139, 92, 246, 0.35)";
      ctx.lineWidth = 3.5;
      ctx.beginPath();
      ctx.arc(cx, cy, R + 1.5, 0, Math.PI * 2);
      ctx.stroke();

      // 2. Latitude / Longitude Mesh Lines
      const latRings = [-60, -30, 0, 30, 60];
      latRings.forEach((lat) => {
        ctx.beginPath();
        let first = true;
        for (let l = -180; l <= 180; l += 8) {
          const pt = project(lat, l);
          if (pt.z > 0) {
            if (first) {
              ctx.moveTo(pt.px, pt.py);
              first = false;
            } else {
              ctx.lineTo(pt.px, pt.py);
            }
          } else {
            first = true;
          }
        }
        ctx.strokeStyle = lat === 0 ? "rgba(56, 189, 248, 0.3)" : "rgba(30, 58, 138, 0.18)";
        ctx.lineWidth = lat === 0 ? 1.4 : 0.8;
        ctx.stroke();
      });

      // 3. Render Globe Particles with Depth Culling
      particles.forEach((p) => {
        const pt = project(p.lat, p.lon);
        if (pt.z > -R * 0.2) {
          const depth = (pt.z + R) / (2 * R);
          const alpha = p.alpha * Math.max(0.12, depth);
          const size = p.size * (0.85 + depth * 0.75);

          ctx.fillStyle = p.isLand
            ? (depth > 0.65 ? "#ffffff" : p.color)
            : p.color;
          ctx.globalAlpha = Math.min(1, alpha * 1.3);
          ctx.beginPath();
          ctx.arc(pt.px, pt.py, size, 0, Math.PI * 2);
          ctx.fill();

          if (p.isLand && depth > 0.8 && Math.random() < 0.06) {
            ctx.fillStyle = "rgba(56, 189, 248, 0.7)";
            ctx.beginPath();
            ctx.arc(pt.px, pt.py, size * 2.5, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      });
      ctx.globalAlpha = 1;

      // 4. Attack Arcs & Great Circle Projectiles
      ATTACK_ARCS.forEach((arc) => {
        const pinA = PINS.find((p) => p.id === arc.from);
        const pinB = PINS.find((p) => p.id === arc.to);
        if (!pinA || !pinB) return;

        const pA = project(pinA.lat, pinA.lon);
        const pB = project(pinB.lat, pinB.lon);

        if (pA.z > -R * 0.1 || pB.z > -R * 0.1) {
          const steps = 32;
          ctx.beginPath();
          let started = false;
          let packetPos: { px: number; py: number } | null = null;

          for (let s = 0; s <= steps; s++) {
            const frac = s / steps;
            const lat = pinA.lat + (pinB.lat - pinA.lat) * frac;
            const lon = pinA.lon + (pinB.lon - pinA.lon) * frac;
            const elev = Math.sin(frac * Math.PI) * (R * 0.32);
            const pt = project(lat, lon, R + elev);

            if (pt.z > -R * 0.2) {
              if (!started) {
                ctx.moveTo(pt.px, pt.py);
                started = true;
              } else {
                ctx.lineTo(pt.px, pt.py);
              }
            } else {
              started = false;
            }

            if (Math.abs(frac - packetT) < 1 / steps) {
              packetPos = pt;
            }
          }

          ctx.strokeStyle = arc.color;
          ctx.lineWidth = 1.6;
          ctx.shadowColor = arc.color;
          ctx.shadowBlur = 10;
          ctx.stroke();
          ctx.shadowBlur = 0;

          if (packetPos) {
            ctx.fillStyle = "#ffffff";
            ctx.shadowColor = arc.color;
            ctx.shadowBlur = 14;
            ctx.beginPath();
            ctx.arc(packetPos.px, packetPos.py, 3.5, 0, Math.PI * 2);
            ctx.fill();
            ctx.shadowBlur = 0;
          }
        }
      });

      // 5. Render Glowing Red DANGER WARNING TRIANGLES on the Globe!
      DANGER_TRIANGLES.forEach((dt, idx) => {
        const pt = project(dt.lat, dt.lon, R * 1.02);
        if (pt.z > -R * 0.15) {
          const pulse = (Math.sin(time * 0.005 + idx * 1.3) + 1) * 0.5;

          ctx.save();
          ctx.translate(pt.px, pt.py);

          // Pulsing outer warning halo ring
          ctx.beginPath();
          ctx.arc(0, 0, 11 + pulse * 9, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(239, 68, 68, ${0.85 - pulse * 0.55})`;
          ctx.lineWidth = 1.4;
          ctx.shadowColor = "#ef4444";
          ctx.shadowBlur = 12;
          ctx.stroke();

          // Second inner ring
          ctx.beginPath();
          ctx.arc(0, 0, 7, 0, Math.PI * 2);
          ctx.strokeStyle = "rgba(239, 68, 68, 0.9)";
          ctx.lineWidth = 1.2;
          ctx.stroke();

          // Glowing Red Danger Triangle
          const s = 10 + pulse * 1.2;
          ctx.beginPath();
          ctx.moveTo(0, -s);
          ctx.lineTo(s * 0.866, s * 0.5);
          ctx.lineTo(-s * 0.866, s * 0.5);
          ctx.closePath();
          ctx.fillStyle = "#ef4444";
          ctx.shadowColor = "#ff2247";
          ctx.shadowBlur = 16;
          ctx.fill();

          // Crisp white border
          ctx.strokeStyle = "#ffffff";
          ctx.lineWidth = 1.3;
          ctx.stroke();

          // Exclamation Mark inside triangle
          ctx.fillStyle = "#ffffff";
          ctx.shadowBlur = 0;
          ctx.fillRect(-0.85, -s * 0.45, 1.7, s * 0.48);
          ctx.beginPath();
          ctx.arc(0, s * 0.22, 1.0, 0, Math.PI * 2);
          ctx.fill();

          ctx.restore();
        }
      });

      // 6. Decorative beacons at arc anchors
      PINS.forEach((pin) => {
        const pt = project(pin.lat, pin.lon, R * 1.015);
        if (pt.z > -R * 0.15) {
          const pulse = (Math.sin(time * 0.005 + (pin.lat + pin.lon)) + 1) * 0.5;
          const nodeColor = pin.color;

          ctx.strokeStyle = nodeColor;
          ctx.lineWidth = 1.6;
          ctx.shadowColor = nodeColor;
          ctx.shadowBlur = 10;
          ctx.beginPath();
          ctx.arc(pt.px, pt.py, 5 + pulse * 7, 0, Math.PI * 2);
          ctx.stroke();

          ctx.fillStyle = "#ffffff";
          ctx.beginPath();
          ctx.arc(pt.px, pt.py, 2.5, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      });

      ctx.restore();
      animId = requestAnimationFrame(render);
    };

    animId = requestAnimationFrame(render);

    const handleMouseDown = (e: MouseEvent) => {
      isDraggingRef.current = true;
      lastMouseRef.current = { x: e.clientX, y: e.clientY };
    };

    const handleMouseMove = (e: MouseEvent) => {
      if (!isDraggingRef.current) return;
      const dx = e.clientX - lastMouseRef.current.x;
      const dy = e.clientY - lastMouseRef.current.y;
      lastMouseRef.current = { x: e.clientX, y: e.clientY };

      rotYRef.current += dx * 0.005;
      rotXRef.current = Math.max(-0.6, Math.min(0.8, rotXRef.current + dy * 0.005));
    };

    const handleMouseUp = () => {
      isDraggingRef.current = false;
    };

    const c = canvasRef.current;
    if (c) {
      c.addEventListener("mousedown", handleMouseDown);
      window.addEventListener("mousemove", handleMouseMove);
      window.addEventListener("mouseup", handleMouseUp);
    }

    return () => {
      cancelAnimationFrame(animId);
      if (c) {
        c.removeEventListener("mousedown", handleMouseDown);
      }
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [PINS, DANGER_TRIANGLES, ATTACK_ARCS]);

  return (
    <div
      ref={containerRef}
      className="threat-globe-container"
    >
      {/* Background Cyber Glowing Nebulas */}
      <div className="globe-ambient-glow">
        <div className="globe-glow-circle"></div>
      </div>

      {/* HTML5 Canvas with decorative 3D globe (no data is plotted) */}
      <canvas
        ref={canvasRef}
        className="threat-globe-canvas"
        aria-hidden="true"
      />
    </div>
  );
}
