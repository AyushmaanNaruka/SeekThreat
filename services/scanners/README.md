# services/scanners

One adapter per tool. Invoke as subprocess or container, parse output, emit `Observation`
objects. `Finding` is downstream — `services/normalize` builds it by merging observations
across scanners. A scanner adapter never constructs one.

## Adding a scanner

1. Subclass `ScannerAdapter` in `base.py`
2. Set `name`, `version_command`, `content_type` (e.g. `"application/xml"`)
3. Implement `_execute` (invoke the tool, return its raw output), `_parse` (a pure function
   of `(artifact, request) -> tuple[Observation, ...]` — see the abstract method's docstring
   in `base.py` for the determinism contract), and `is_available`
4. Override `_captured_at` if the tool's own output carries a timestamp — see `nmap_adapter.py`.
   Without an override, the base class uses the wall clock, which is fine for a tool that
   doesn't embed one, but breaks purity for one that does.
5. Raw output is preserved automatically: `scan()` builds a content-addressed `RawArtifact`
   and hands it to `_parse`. Don't build your own.
6. **Do not assign severity** — that belongs to `services/enrichment`
7. Add tests using fixture output, not live scans. See `services/scanners/nmap_xml.py` and
   `tests/fixtures/nmap/` for the reference shape.

## Planned

Nmap, Nuclei, Nikto, Greenbone/OpenVAS, ZAP, subfinder/httpx/naabu. Stretch: Tsunami,
testssl.sh, WhatWeb, Wapiti, sslyze.

## Rules

- **Authorization is enforced in `ScannerAdapter.scan()`.** Don't bypass it.
- Invoke binaries, don't vendor source. Nmap's licence makes this mandatory; treat it as the
  pattern for everything.
- DefectDojo's parser directory is a good reference for output parsing and appears to be
  BSD-licensed — verify before copying, and register anything you take.
