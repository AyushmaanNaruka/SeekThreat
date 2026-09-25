"use client";

import React, { useEffect, useRef } from "react";

export default function SidebarOrbit() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let angle = 0;

    // 4 elliptical orbital tracks tilted diagonally to match reference image
    const orbits = [
      { rx: 110, ry: 38, deg: -22, speed: 0.008, alpha: 0.55, width: 1.0, nodes: [0, Math.PI * 0.75] },
      { rx: 140, ry: 48, deg: -18, speed: -0.006, alpha: 0.45, width: 0.9, nodes: [Math.PI * 0.4, Math.PI * 1.3] },
      { rx: 85, ry: 28, deg: -26, speed: 0.012, alpha: 0.65, width: 1.1, nodes: [Math.PI * 0.2] },
      { rx: 165, ry: 58, deg: -15, speed: -0.004, alpha: 0.35, width: 0.8, nodes: [Math.PI * 0.9, Math.PI * 1.8] },
    ];

    const render = () => {
      const w = canvas.width;
      const h = canvas.height;
      const cx = 30; // Anchored near bottom-left corner like reference
      const cy = h * 0.55;

      ctx.clearRect(0, 0, w, h);
      angle += 1;

      orbits.forEach((orb) => {
        ctx.save();
        ctx.translate(cx, cy);
        ctx.rotate((orb.deg * Math.PI) / 180);

        // Orbit ring path
        ctx.beginPath();
        ctx.ellipse(0, 0, orb.rx, orb.ry, 0, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(220, 229, 232, ${orb.alpha})`;
        ctx.lineWidth = orb.width;
        ctx.stroke();

        // Traveling glowing nodes on the orbit
        orb.nodes.forEach((initialOffset, nIdx) => {
          const nodeAngle = initialOffset + angle * orb.speed;
          const nx = Math.cos(nodeAngle) * orb.rx;
          const ny = Math.sin(nodeAngle) * orb.ry;

          // Soft white bloom
          ctx.fillStyle = "rgba(255, 255, 255, 0.45)";
          ctx.beginPath();
          ctx.arc(nx, ny, 3.5, 0, Math.PI * 2);
          ctx.fill();

          // Bright crisp white core
          ctx.fillStyle = "#FFFFFF";
          ctx.shadowColor = "rgba(255, 255, 255, 0.95)";
          ctx.shadowBlur = 5;
          ctx.beginPath();
          ctx.arc(nx, ny, 1.8, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        });

        ctx.restore();
      });

      animId = requestAnimationFrame(render);
    };

    render();

    return () => cancelAnimationFrame(animId);
  }, []);

  return (
    <div className="db-sidebar-orbit-wrap">
      <canvas ref={canvasRef} width={285} height={110} className="db-sidebar-orbit-canvas" />
    </div>
  );
}

