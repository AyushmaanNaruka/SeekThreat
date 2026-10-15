# Nikto fixtures

Real capture, `httpd_2449.json` / `unreachable.json`:

- Tool: Nikto 2.5.0 (LW 2.5), image `ghcr.io/sullo/nikto` (digest
  `sha256:0bb37022ebfadc38d6a9a2755c03bfd1f9e079e01e8946fe548153d9ba0c2012`).
- Target: a throwaway `httpd:2.4.49` container on an `--internal` docker network, so nothing
  could leave the host. No public host was scanned.
- Argv (the adapter's, minus the binary): `-ask no -nointeractive -nolookup -Format json -o -
  -host <ip> -port 80 -maxtime 60s -Tuning 123abde -Plugins "<SAFE_PLUGINS>"`.
- The container IP (172.20.0.2) was rewritten to the lab address 172.20.1.10 with sed; nothing
  else was edited. `unreachable.json` is the same run against closed port 81.
- Nikto 2.5.0 JSON has no timestamps and an empty `banner` even though the text report prints
  `Server: Apache/2.4.49 (Unix)`.

Hand-written (not Nikto output; shaped after it plus the older 2.1.x format):

- `empty_vulnerabilities.json` — a host with no findings.
- `malformed.json` — truncated mid-string.
- `multi_host_cve.json` — two hosts, banners, CVE ids in msg/references, near-miss CVE strings.
- `legacy_trailing_commas.json` — single host object, `OSVDB` keys, trailing commas.
