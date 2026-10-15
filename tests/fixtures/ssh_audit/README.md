# ssh-audit fixtures

Inputs for `tests/unit/test_ssh_audit_json.py` and `test_ssh_audit_adapter.py`.

## Real captures

| File | Tool | How it was produced |
|---|---|---|
| `openssh_8.3_ssh-audit-3.9.0.json` | ssh-audit 3.9.0 (`positronsecurity/ssh-audit` image) | exact adapter argv, `-j --skip-rate-test -n -t 10 -p 2222 -- <ip>` |
| `openssh_8.3_ssh-audit-2.9.0.json` | ssh-audit 2.9.0 (`pip install ssh-audit==2.9.0` in a throwaway `python:3.12-slim` container) | `-j -t 10 -p 2222 -- <ip>` |
| `connection_refused.txt` | ssh-audit 3.9.0 | same argv, against a closed port (2223). Exit code 1, plain text on stdout, no JSON |

Both JSON files audit the same server. The server was
`linuxserver/openssh-server:version-8.3_p1-r0` (OpenSSH 8.3p1 on Alpine, banner
`SSH-2.0-OpenSSH_8.3`; `sshd -V` reports `OpenSSH_8.3p1, OpenSSL 1.1.1g`), started with
`PASSWORD_ACCESS=true` on an isolated `docker network create --internal` network, with the
ssh-audit container on the same network. No public host was scanned. The lab's pinned
`linuxserver/openssh-server:8.2p1` tag does not exist on Docker Hub, and no tag carries
OpenSSH 8.2p1, so 8.3p1 (the nearest published version) was used.

The container IP and port were rewritten with `sed` to the lab bastion's address
(`172.20.2.50:2222`) in the `target` field. Nothing else was edited.

The two ssh-audit versions differ in ways the parser must handle:

- v3.9.0 always reports `cves: []` (its source: "Historically, CVE information was
  returned") but attaches `notes` (`fail` / `warn` / `info`) to every algorithm and has
  `banner.protocol` as the string `"2.0"`.
- v2.9.0 still reports `cves` (three CVEs for OpenSSH 8.3, from the banner alone) but
  attaches no per-algorithm `notes`, so weak algorithms appear only in `recommendations`,
  and `banner.protocol` is the list `[2, 0]`.

Both files are single-line JSON exactly as `-j` emits it; use `python -m json.tool` to read.

## Hand-written edge cases

| File | Purpose |
|---|---|
| `hardened_ipv6_dropbear.json` | IPv6 target (`fd00::5:22`, which ssh-audit emits unbracketed), Dropbear banner, nothing weak, no CVEs |
| `distro_banner_comments.json` | Ubuntu banner comment, duplicate and malformed CVE entries, an algorithm with both `fail` and `warn` notes carrying a CVE id, a `chg` recommendation, and recommendations naming an algorithm the server never advertised |
| `malicious_attributes.json` | control characters and ANSI escapes in banner / notes / algorithm names, and a 5000-character note |
| `truncated.json` | JSON cut off mid-document |
