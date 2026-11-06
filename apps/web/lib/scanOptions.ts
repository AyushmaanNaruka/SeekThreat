/**
 * Scanner labels for the dashboard launcher.
 *
 * Target parsing, range expansion, per-target port/scheme and scope checking
 * all happen on the server (POST /scans/plan, POST /scans/batch). The browser
 * deliberately does not reimplement them: if the two disagreed about where a
 * host ended, an allowlist check could pass for one host while the scan hit
 * another. See DECISIONS.md D-025.
 */

export type ScannerName = "nmap" | "nuclei" | "nikto" | "ssh-audit";

/** Human label for a scan's scanner, used in the activity feed. */
export function scannerTitle(scanner: string): string {
  switch (scanner) {
    case "nuclei":
      return "Nuclei Vulnerability Scan";
    case "nikto":
      return "Nikto Web Server Scan";
    case "ssh-audit":
      return "SSH Audit";
    default:
      return "Nmap Network Scan";
  }
}
