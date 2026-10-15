# Track D Implementation: Licences & Third-Party Terms Verification

**Branch:** `mayank_level2_working`  
**Base Commit:** `a82986f` (PR #19 merged), following review fix `48d5f2b`  
**Owner:** Mayank (Layer 2 Owner)  
**Status:** Completed  
**Compliance Standard:** CLAUDE.md Hard Rule 3 ("Licence discipline") & THIRD_PARTY.md  

---

## 1. Executive Summary & Verification Objective

During the PR #19 review, several data feed entries in `THIRD_PARTY.md` carried provisional annotations ("no terms page cited", "client-rendered page: not retrieved", or "TO VERIFY"). Track D resolves these gaps through direct verification of official terms pages (rendered via headless browser subagent and HTTP probe) to uphold academic and legal rigor for the final project viva defense.

---

## 2. Progress Tracker

| Task | Feed / Target | Status | Verification Method | Primary Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **D-1** | NVD API 2.0 Terms of Use | ✅ Verified | Headless Browser Rendering (`https://nvd.nist.gov/developers/terms-of-use`) | Confirmed public domain/U.S. Gov work; extracted exact required attribution notice. |
| **D-2** | CVE.org Terms of Use | ✅ Verified | Headless Browser Rendering (`https://www.cve.org/Legal/TermsOfUse`) | Confirmed perpetual royalty-free license grant from MITRE; documented disclaimer terms. |
| **D-3** | ENISA EUVD Legal Notice | ✅ Verified | Direct HTTP Fetch & Web Legal Notice Verification | General ENISA legal notice confirmed (reuse with attribution); retained *TO VERIFY* for separate data license. |
| **D-4** | EUVD `/api/vulnerability` vs `/api/search` Endpoint Probe | ✅ Verified | Live HTTP probe via `httpx` against `euvdservices.enisa.europa.eu` | Confirmed `403 Forbidden` on `/api/vulnerability`; confirmed `200 OK` on `/api/search`. Documented in `sync.py`. |

---

## 3. Task D-1: NVD Terms of Use Verification

- **Official URL:** `https://nvd.nist.gov/developers/terms-of-use`
- **Verification Method:** Rendered via Angular SPA headless browser subagent on 2026-10-15.
- **Copyright & License Status:** Created by NIST as a public service (work of the U.S. Federal Government, public domain under 17 U.S.C. § 105). No commercial use restrictions.
- **Permitted Use:** Developing services to search, display, analyze, retrieve, and view NVD data.
- **Mandatory Attribution & Non-Endorsement Notice:**
  > *"This product uses the NVD API but is not endorsed or certified by the NVD."*
- **Modification Rule:** If NVD data is modified or adapted, the modified source must not be attributed as official NVD output.
- **Rate Limits & API Keys:**
  - Public unauthenticated rate limit: ~5 requests per rolling 30-second window.
  - Registered API key limit: ~50 requests per rolling 30-second window.
  - API keys must not be shared or embedded in client-side code.

---

## 4. Task D-2: CVE.org Terms of Use Verification

- **Official URL:** `https://www.cve.org/Legal/TermsOfUse`
- **Verification Method:** Rendered via Vue/Vite SPA headless browser subagent on 2026-10-15.
- **License Grant Type:** Perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license.
- **Permitted Scope:** Permission to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE™).
- **Condition:** Any copy made for such purposes must reproduce MITRE's copyright designation and license.
- **Warranty Disclaimer:** Provided on an `"AS IS"` basis without warranties of title, non-infringement, merchantability, or fitness for a particular purpose.

---

## 5. Task D-3: ENISA EUVD Legal Notice Verification

- **Official URLs:**
  - `https://www.enisa.europa.eu/about-enisa/legal-notice`
  - `https://euvd.enisa.europa.eu`
- **Verification Date:** 2026-10-15
- **Legal Notice Terms:**
  > *"Reproduction is authorised provided the source is acknowledged, unless otherwise stated. Where prior permission must be obtained for the reproduction or use of textual and multimedia information (sound, images, software, etc.), such permission shall cancel the above-mentioned general permission and shall clearly indicate any restrictions on use."*
- **Dedicated Data License Status:** Retained as `*TO VERIFY*` in `THIRD_PARTY.md`. While general ENISA content reuse with attribution is authorized, ENISA has not published a separate formal open data license (e.g., CC BY 4.0 or EU Open Data Directive Decision 2011/833/EU) on the EUVD portal.

---

## 6. Task D-4: EUVD API Endpoint Verification

Empirical probe conducted on 2026-10-15 via `httpx` to verify endpoint routing behavior against `euvdservices.enisa.europa.eu`:

```python
GET https://euvdservices.enisa.europa.eu/api/vulnerability?id=CVE-2021-44228
--> HTTP 403 Forbidden
Headers: {'Server': 'Apache', 'Content-Length': '0', 'X-Frame-Options': 'DENY'}
Body: (empty)

GET https://euvdservices.enisa.europa.eu/api/search?text=CVE-2021-44228
--> HTTP 200 OK
Headers: {'Content-Type': 'application/json', 'Content-Length': '5453'}
Body: {"items":[{"id":"EUVD-2021-34768","enisaUuid":"4d72f2b4-...","aliases":"CVE-2021-44228\nGHSA-j2ge-4vd3-q558", ...}]}
```

### Architectural Confirmation:
- The `/api/vulnerability` endpoint is restricted or internal (returns `403 Forbidden` on public gateway).
- The public search endpoint `/api/search?text={cve}` is operational and returns structured JSON `items`.
- As documented in `services/enrichment/sources/sync.py` (lines 89–93), SeekThreat uses `/api/search` with exact alias matching across the returned items.

---

## 7. Artifact Updates Summary

1. **`THIRD_PARTY.md`:**
   - Updated register rows for NVD, CVE.org, and ENISA EUVD to `Verified by: Mayank Narang` on `2026-10-15`.
   - Updated Notes `[N]`, `[C]`, and `[U]` with exact verified wording and date of retrieval.
2. **`services/enrichment/sources/sync.py`:**
   - Documented the rationale for `DEFAULT_EUVD_URL = "https://euvdservices.enisa.europa.eu/api/search"` with reference to Task D-4 test results.
3. **`docs/mayank_implementation/working_level2_tasks.md`:**
   - Track D tasks marked complete.

---
*Generated: 2026-10-15*
