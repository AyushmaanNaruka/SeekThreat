import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SEEKTHREAT — See What Others Miss | AI-Powered Cyber Threat Intelligence",
  description:
    "From hidden vulnerabilities to complex attack paths, SeekThreat turns scattered data into clear, actionable intelligence before the threat becomes a breach.",
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
      </head>
      <body>{children}</body>
    </html>
  );
}
