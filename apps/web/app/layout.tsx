import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SEEKTHREAT — See What Others Miss | Vulnerability Detection & Enrichment Platform",
  description:
    "SeekThreat runs authorized scans with Nmap, Nuclei, Nikto and ssh-audit, then enriches findings with CVSS, EPSS, CISA KEV and exploit data. Every field carries its source, and every risk score shows its components.",
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
