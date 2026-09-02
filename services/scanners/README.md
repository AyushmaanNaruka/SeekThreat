# services/scanners

One adapter per tool. Invoke as subprocess or container, parse output, emit `Finding` objects.

## Adding a scanner

1. Subclass `ScannerAdapter` in `base.py`
2. Implement `_execute`, `_parse`, `is_available`
3. Preserve raw output in `Finding.raw`
4. **Do not assign severity** — that belongs to `services/enrichment`
5. Add tests using fixture output, not live scans

## Planned

Nmap, Nuclei, Nikto, Greenbone/OpenVAS, ZAP, subfinder/httpx/naabu. Stretch: Tsunami,
testssl.sh, WhatWeb, Wapiti, sslyze.

## Rules

- **Authorization is enforced in `ScannerAdapter.scan()`.** Don't bypass it.
- Invoke binaries, don't vendor source. Nmap's licence makes this mandatory; treat it as the
  pattern for everything.
- DefectDojo's parser directory is a good reference for output parsing and appears to be
  BSD-licensed — verify before copying, and register anything you take.
