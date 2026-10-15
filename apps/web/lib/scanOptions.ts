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

function ipv4ToInt(s: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1);
  // Python's ipaddress rejects leading zeros ("010"); so must we.
  if (parts.some((p) => p.length > 1 && p.startsWith("0"))) return null;
  const octets = parts.map(Number);
  if (octets.some((o) => o > 255)) return null;
  return ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
}

/**
 * Client-side preview of the API's allowlist gate (packages/schema/models/
 * engagement.py `target_matches`): exact host, `*.domain` (subdomains, not the
 * apex) and IPv4 CIDR. It checks the bare host, which is what gets sent.
 * Returns `null` when the browser cannot decide (IPv6 ranges, non-canonical
 * IPv6, netmask-style prefixes), so the UI defers to the server instead of
 * guessing. The server is always the authority; this only spares the operator
 * a 403 round trip.
 */
export function isTargetInScope(input: string, allowlist: string[]): boolean | null {
  const host = splitHostPortScheme(input.trim()).host.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host || host.includes("%")) return false;
  // The gate only accepts a single host: a range target (172.20.1.0/24) never
  // matches, even inside an allowed range, so one scan always means one host.
  if (host.includes("/")) return false;
  const hostInt = ipv4ToInt(host);
  let undecided = false;
  for (const entry of allowlist) {
    const pattern = entry.trim().toLowerCase();
    if (!pattern) continue;
    if (pattern === host) return true;
    if (pattern.startsWith("*.")) {
      if (hostInt === null && host.endsWith(pattern.slice(1))) return true;
      continue;
    }
    if (pattern.includes(":") && host.includes(":")) {
      // IPv6 exact or range: string compare can't see "fd00::1" == "fd00:0:...:1".
      undecided = true;
      continue;
    }
    if (pattern.includes("/")) {
      const [base, bitsStr] = pattern.split("/");
      const baseInt = ipv4ToInt(base);
      if (baseInt === null || hostInt === null) continue;
      if (!/^\d{1,2}$/.test(bitsStr)) {
        // "10.0.0.0/255.0.0.0" is valid to Python; "10.0.0.0/" and "/8.0" are not.
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bitsStr)) undecided = true;
        continue;
      }
      const bits = Number(bitsStr);
      if (bits > 32) continue;
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      if (((hostInt & mask) >>> 0) === ((baseInt & mask) >>> 0)) return true;
    }
  }
  return undecided ? null : false;
}

function withTimeout(
  options: Record<string, unknown>,
  timeoutSeconds?: number | null,
): void {
  if (typeof timeoutSeconds === "number" && Number.isFinite(timeoutSeconds) && timeoutSeconds > 0) {
    options.timeout = Math.floor(timeoutSeconds);
  }
}

/**
 * Nuclei: bare host + `scheme` (+ `port` when given). No template is sent, so
 * the worker runs its pinned template set with intrusive, DoS, fuzz, RCE,
 * brute-force and default-login templates excluded (nuclei_adapter.py).
 */
export function buildNucleiRequest(input: string): BuiltScanRequest {
  const { host, scheme, port } = splitHostPortScheme(input);
  const options: Record<string, unknown> = { scheme };
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
