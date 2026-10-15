/**
 * Scan request building for the dashboard launcher.
 *
 * Pure functions (no React, no fetch) so the host/port/scheme splitting can be
 * unit tested with `node --test`.
 */

export type ScannerName = "nmap" | "nuclei" | "nikto" | "ssh-audit";

export interface BuiltScanRequest {
  /** Bare IP/hostname as the API's authorization gate expects it. */
  target: string;
  options: Record<string, unknown>;
}

export interface SplitTarget {
  host: string;
  scheme: "http" | "https";
  port: string | null;
}

/**
 * Split user input into a bare host, a scheme and an optional port.
 *
 * Send the BARE HOST, never a URL. The API's authorization gate compares
 * `target` as an exact string and deliberately refuses to parse a URL down
 * to a host (packages/schema/models/engagement.py): if the browser and the
 * server disagreed about where the host ended, an allowlist check could
 * pass for one host while the scan hit another. The adapter rebuilds the
 * URL from the validated `scheme` and `port` options instead. See
 * DECISIONS.md D-025. Sending "http://localhost" here is what produced
 * "Target 'http://localhost' is not authorized" against an allowlist that
 * plainly contained "localhost".
 */
export function splitHostPortScheme(input: string): SplitTarget {
  let target = input;
  let scheme: "http" | "https" = "http";
  let port: string | null = null;
  if (target.includes("://")) {
    try {
      const parsed = new URL(target);
      scheme = parsed.protocol === "https:" ? "https" : "http";
      target = parsed.hostname;
      if (parsed.port) port = parsed.port;
    } catch {
      ({ host: target, port } = splitHostPort(target.replace(/^[a-zA-Z]+:\/\//, "").split("/")[0]));
    }
  } else if (target.includes(":") && !target.includes("/")) {
    ({ host: target, port } = splitHostPort(target));
  }
  // new URL() brackets an IPv6 literal; the gate matches on the bare address
  // and the adapters re-bracket it where a tool needs it.
  if (target.startsWith("[") && target.endsWith("]")) {
    target = target.slice(1, -1);
  }
  return { host: target, scheme, port };
}

/**
 * Split "host", "host:port", "[v6]" or "[v6]:port". An unbracketed string with
 * two or more colons is a bare IPv6 address with no port. A port that is not
 * all digits is kept as typed so the API rejects it, rather than being dropped
 * and the default port scanned instead.
 */
function splitHostPort(s: string): { host: string; port: string | null } {
  const bracketed = /^\[([^\]]+)\](?::(.*))?$/.exec(s);
  if (bracketed) return { host: `[${bracketed[1]}]`, port: bracketed[2] || null };
  const colons = s.split(":").length - 1;
  if (colons !== 1) return { host: s, port: null };
  const [host, port] = s.split(":");
  return { host, port: port || null };
}

function withTimeout(
  options: Record<string, unknown>,
  timeoutSeconds?: number | null,
): void {
  if (typeof timeoutSeconds === "number" && Number.isFinite(timeoutSeconds) && timeoutSeconds > 0) {
    options.timeout = Math.floor(timeoutSeconds);
  }
}

export const NUCLEI_TEMPLATE = "tests/fixtures/nuclei/test_http_detect.yaml";

/** Nuclei: bare host + `scheme` (+ `port` when given) + the fixture template. */
export function buildNucleiRequest(input: string): BuiltScanRequest {
  const { host, scheme, port } = splitHostPortScheme(input);
  const options: Record<string, unknown> = { template: NUCLEI_TEMPLATE, scheme };
  if (port) options.port = port;
  return { target: host, options };
}

/**
 * Nikto: bare host + `port` + `scheme` (+ optional `timeout`). Never sends
 * nuclei's `template`. Port defaults to the scheme's well-known port (80 for
 * http, 443 for https) when the user gave none.
 */
export function buildNiktoRequest(
  input: string,
  timeoutSeconds?: number | null,
): BuiltScanRequest {
  const { host, scheme, port } = splitHostPortScheme(input);
  const options: Record<string, unknown> = {
    port: port ?? (scheme === "https" ? "443" : "80"),
    scheme,
  };
  withTimeout(options, timeoutSeconds);
  return { target: host, options };
}

/** ssh-audit: bare host + `port` (default 22) (+ optional `timeout`). No scheme. */
export function buildSshAuditRequest(
  input: string,
  timeoutSeconds?: number | null,
): BuiltScanRequest {
  const { host, port } = splitHostPortScheme(input);
  const options: Record<string, unknown> = { port: port ?? "22" };
  withTimeout(options, timeoutSeconds);
  return { target: host, options };
}

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
