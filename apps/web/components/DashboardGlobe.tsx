"use client";

import React, { useEffect, useRef } from "react";

// Dense realistic continent cluster coordinates for high-definition white/silver digital globe
const CONTINENT_POINTS = [
  // North America
  { lat: 48, lon: -100, count: 180, spreadLat: 14, spreadLon: 24 },
  { lat: 58, lon: -115, count: 130, spreadLat: 10, spreadLon: 26 },
  { lat: 36, lon: -85, count: 150, spreadLat: 10, spreadLon: 18 },
  { lat: 24, lon: -102, count: 80, spreadLat: 8, spreadLon: 12 },
  { lat: 64, lon: -150, count: 70, spreadLat: 7, spreadLon: 18 },
  // Greenland
  { lat: 72, lon: -40, count: 80, spreadLat: 8, spreadLon: 16 },
  // South America
  { lat: -6, lon: -55, count: 160, spreadLat: 15, spreadLon: 15 },
  { lat: -25, lon: -60, count: 120, spreadLat: 12, spreadLon: 14 },
  { lat: -45, lon: -68, count: 60, spreadLat: 10, spreadLon: 8 },
  // Europe
  { lat: 52, lon: 15, count: 160, spreadLat: 9, spreadLon: 18 },
  { lat: 60, lon: 18, count: 95, spreadLat: 8, spreadLon: 14 },
  { lat: 40, lon: 0, count: 110, spreadLat: 7, spreadLon: 14 },
  { lat: 54, lon: -3, count: 65, spreadLat: 5, spreadLon: 6 },
  // Africa
  { lat: 24, lon: 15, count: 150, spreadLat: 12, spreadLon: 22 },
  { lat: 5, lon: 22, count: 180, spreadLat: 16, spreadLon: 18 },
  { lat: -22, lon: 25, count: 130, spreadLat: 14, spreadLon: 14 },
  // Asia & Middle East
  { lat: 28, lon: 45, count: 110, spreadLat: 9, spreadLon: 15 },
  { lat: 22, lon: 78, count: 180, spreadLat: 13, spreadLon: 16 },
  { lat: 36, lon: 105, count: 220, spreadLat: 15, spreadLon: 25 },
  { lat: 58, lon: 95, count: 180, spreadLat: 14, spreadLon: 34 },
  { lat: 14, lon: 102, count: 130, spreadLat: 9, spreadLon: 15 },
  { lat: 36, lon: 138, count: 95, spreadLat: 7, spreadLon: 8 },
  // Australia & New Zealand
  { lat: -25, lon: 135, count: 140, spreadLat: 13, spreadLon: 18 },
  { lat: -42, lon: 172, count: 50, spreadLat: 6, spreadLon: 6 },
];

export default function DashboardGlobe() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let rotation = 0.6;
    let orbitAngle = 0;

    // Generate point cloud on the sphere
    const points: { lat: number; lon: number; r: number; isCity: boolean }[] = [];
    CONTINENT_POINTS.forEach((c) => {
      for (let i = 0; i < c.count; i++) {
        const u = Math.random() + Math.random() - 1;
        const v = Math.random() + Math.random() - 1;
        const isCity = Math.random() > 0.8;
        points.push({
          lat: ((c.lat + u * c.spreadLat) * Math.PI) / 180,
          lon: ((c.lon + v * c.spreadLon) * Math.PI) / 180,
          r: isCity ? 1.7 : 0.95,
          isCity,
        });
      }
    });

    // Technical grid dots on sphere
    for (let lat = -75; lat <= 75; lat += 15) {
      for (let lon = -180; lon < 180; lon += 12) {
        if (Math.random() > 0.3) {
          points.push({
            lat: (lat * Math.PI) / 180,
            lon: (lon * Math.PI) / 180,
            r: 0.65,
            isCity: false,
          });
        }
      }
    }

    // 6 prominent orbital tracks with varying radii, tilts, and speeds
    const orbits = [
      { rx: 220, ry: 64, deg: -18, color: "rgba(255, 255, 255, 0.8)", backAlpha: 0.28, width: 1.25, dashed: false, speed: 0.007, nodes: [0, Math.PI * 0.85] },
      { rx: 195, ry: 75, deg: 26, color: "rgba(220, 235, 240, 0.7)", backAlpha: 0.22, width: 1.1, dashed: true, speed: -0.005, nodes: [Math.PI * 0.4, Math.PI * 1.4] },
      { rx: 165, ry: 50, deg: -46, color: "rgba(244, 247, 248, 0.65)", backAlpha: 0.2, width: 1.0, dashed: false, speed: 0.009, nodes: [Math.PI * 0.2] },
      { rx: 245, ry: 85, deg: 10, color: "rgba(210, 225, 230, 0.55)", backAlpha: 0.18, width: 0.95, dashed: true, speed: -0.0035, nodes: [Math.PI * 0.9] },
      { rx: 145, ry: 42, deg: 58, color: "rgba(255, 255, 255, 0.65)", backAlpha: 0.22, width: 1.1, dashed: false, speed: 0.011, nodes: [Math.PI * 0.6] },
      { rx: 205, ry: 38, deg: -6, color: "rgba(200, 220, 225, 0.5)", backAlpha: 0.16, width: 0.85, dashed: true, speed: 0.006, nodes: [Math.PI * 1.2] },
    ];

    const render = () => {
      const width = canvas.width;
      const height = canvas.height;
      const cx = width * 0.5;
      const cy = height * 0.5;
      const radius = 96; // ~192px sphere, ~490px total orbital diameter

      ctx.clearRect(0, 0, width, height);

      rotation += 0.0022;
      orbitAngle += 1;

      // 1. Outer ambient atmosphere radial glow behind globe
      const glowGrad = ctx.createRadialGradient(cx, cy, radius * 0.6, cx, cy, radius * 1.7);
      glowGrad.addColorStop(0, "rgba(220, 235, 245, 0.16)");
      glowGrad.addColorStop(0.45, "rgba(220, 235, 245, 0.05)");
      glowGrad.addColorStop(1, "rgba(0, 0, 0, 0)");
      ctx.fillStyle = glowGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.7, 0, Math.PI * 2);
      ctx.fill();

      // 2. Render Back-half of orbital rings (behind sphere)
      orbits.forEach((orb) => {
        ctx.save();
        ctx.translate(cx, cy);
        ctx.rotate((orb.deg * Math.PI) / 180);

        ctx.beginPath();
        // Back half: from PI to 2*PI
        ctx.ellipse(0, 0, orb.rx, orb.ry, 0, Math.PI, Math.PI * 2);
        ctx.strokeStyle = `rgba(220, 229, 232, ${orb.backAlpha})`;
        ctx.lineWidth = orb.width * 0.85;
        if (orb.dashed) {
          ctx.setLineDash([4, 6]);
        }
        ctx.stroke();
        ctx.restore();
      });

      // 3. Globe Base Sphere & Shading
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);

      // Dark translucent interior gradient
      const sphereGrad = ctx.createRadialGradient(
        cx - radius * 0.35,
        cy - radius * 0.35,
        radius * 0.1,
        cx,
        cy,
        radius
      );
      sphereGrad.addColorStop(0, "#0e1518");
      sphereGrad.addColorStop(0.65, "#06090a");
      sphereGrad.addColorStop(1, "#020405");
      ctx.fillStyle = sphereGrad;
      ctx.fill();

      // Crisp luminous silver sphere edge rim
      ctx.strokeStyle = "rgba(244, 247, 248, 0.55)";
      ctx.lineWidth = 1.2;
      ctx.stroke();

      // Clip content inside the globe sphere
      ctx.clip();

      // 4. Rotating Latitude/Longitude Wireframe Lines
      ctx.lineWidth = 0.65;
      // Latitudes
      [-50, -25, 0, 25, 50].forEach((latDeg) => {
        const latRad = (latDeg * Math.PI) / 180;
        const yOffset = -Math.sin(latRad) * radius;
        const sliceRadius = Math.cos(latRad) * radius;
        ctx.beginPath();
        ctx.ellipse(cx, cy + yOffset, sliceRadius, sliceRadius * 0.28, 0, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(220, 229, 232, 0.14)";
        ctx.stroke();
      });

      // 5. Render Rotating Continents Point Cloud
      points.forEach((p) => {
        const currentLon = p.lon + rotation;
        const x3d = Math.cos(p.lat) * Math.sin(currentLon);
        const y3d = -Math.sin(p.lat);
        const z3d = Math.cos(p.lat) * Math.cos(currentLon);

        if (z3d > -0.05) {
          const px = cx + x3d * radius;
          const py = cy + y3d * radius;
          const alpha = Math.max(0.15, (z3d + 0.05) / 1.05);

          if (p.isCity) {
            // Bright white glowing city node
            ctx.fillStyle = `rgba(255, 255, 255, ${alpha * 0.95})`;
            ctx.shadowColor = "rgba(255, 255, 255, 0.9)";
            ctx.shadowBlur = 4;
          } else {
            // Crisp silver land dot
            ctx.fillStyle = `rgba(225, 235, 238, ${alpha * 0.85})`;
            ctx.shadowBlur = 0;
          }

          ctx.beginPath();
          ctx.arc(px, py, p.r * (0.8 + 0.35 * z3d), 0, Math.PI * 2);
          ctx.fill();
        }
      });
      ctx.shadowBlur = 0;

      // Soft rim highlight on top-left
      const specular = ctx.createLinearGradient(cx - radius, cy - radius, cx + radius, cy + radius);
      specular.addColorStop(0, "rgba(255, 255, 255, 0.12)");
      specular.addColorStop(0.4, "transparent");
      specular.addColorStop(1, "rgba(0, 0, 0, 0.8)");
      ctx.fillStyle = specular;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fill();

      ctx.restore();

      // 6. Render Front-half of Orbital Rings & Luminous Nodes (In Front of Sphere)
      orbits.forEach((orb) => {
        ctx.save();
        ctx.translate(cx, cy);
        ctx.rotate((orb.deg * Math.PI) / 180);

        // Entire ring with bright white/silver stroke
        ctx.beginPath();
        ctx.ellipse(0, 0, orb.rx, orb.ry, 0, 0, Math.PI * 2);
        ctx.strokeStyle = orb.color;
        ctx.lineWidth = orb.width;
        if (orb.dashed) {
          ctx.setLineDash([4, 6]);
        } else {
          ctx.setLineDash([]);
        }
        ctx.stroke();

        // Traveling glowing nodes on the orbits
        orb.nodes.forEach((initialOffset) => {
          const currentAngle = initialOffset + orbitAngle * orb.speed;
          const nx = Math.cos(currentAngle) * orb.rx;
          const ny = Math.sin(currentAngle) * orb.ry;

          // Luminous node outer halo
          ctx.fillStyle = "rgba(255, 255, 255, 0.4)";
          ctx.beginPath();
          ctx.arc(nx, ny, 5, 0, Math.PI * 2);
          ctx.fill();

          // Bright solid white node core
          ctx.fillStyle = "#FFFFFF";
          ctx.shadowColor = "rgba(255, 255, 255, 1)";
          ctx.shadowBlur = 6;
          ctx.beginPath();
          ctx.arc(nx, ny, 2.2, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        });

        ctx.restore();
      });

      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animId);
    };
  }, []);

  return (
    <div className="db-globe-wrapper">
      <canvas
        ref={canvasRef}
        width={580}
        height={260}
        className="db-globe-canvas"
      />
    </div>
  );
}

