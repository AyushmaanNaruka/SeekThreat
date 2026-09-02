# Open source policy

How we use other people's code without damaging the project.

## Four modes

| Mode | What it is | Licence impact | Verdict |
|---|---|---|---|
| **Run as a service** | Deploy their container, call their API. Their code never enters our repo | None — separate programs over a network | **Preferred** |
| **Study and reimplement** | Read their design, write our own | None — ideas aren't copyrightable | **Preferred** |
| **Vendor / copy** | Their files in our `vendor/` | Their licence attaches to us | Permissive licences only |
| **Fork wholesale** | Build inside their repo | High, plus we inherit their architecture | **Never** |

Forking feels like a head start and isn't. We'd spend six months bending someone else's data
model around our differentiator. Our attack path engine needs asset topology and reachability
facts none of these platforms carry.

## Licence tiers

**Permissive — MIT, BSD-3, Apache-2.0.** Copy freely with attribution. Our project stays ours.

**Copyleft — GPL-3.0, AGPL-3.0.** Copying makes our project GPL/AGPL. With AGPL, exposing the
platform over a network obliges us to offer source to every user. Survivable academically, but
it closes off a closed deployment and any commercial path later. **Running an AGPL tool as a
service does not trigger this.** Only copying its code does.

**Source-available — BSL, custom.** Looks open, isn't. OpenCVE is here.

**Nmap is special.** The NPSL interprets "derivative work" broadly and restricts inclusion in
proprietary products, including inside containers. Invoke the binary as a subprocess and parse
XML. Never vendor or link the source.

## Rules

1. All third-party code in `vendor/`. Nowhere else in the tree.
2. Never copy from AGPL or GPL. Study and reimplement.
3. Every vendored item gets a `THIRD_PARTY.md` row in the same PR. CI enforces this.
4. Verify licences by opening the actual `LICENSE` file. Never guess. Licences change —
   OpenCVE's did.
5. **The 3-day rule.** If integrating takes more than three days, it must save more than three
   days. Otherwise drop it.

## Don't outsource the differentiators

Some projects do much of what our Layer 2 does. Adopting them wholesale would save weeks and
hollow out the project — the honest answer to "what did you build?" becomes "a UI and some
adapters."

**Take commodity infrastructure. Build the differentiators.**

Ours, non-negotiably:
1. Multi-source enrichment fusion — provenance, confidence, fallback chains
2. Deterministic attack path engine with per-edge provenance
3. Composite Exposure Risk Score with explanation
4. Chokepoint analysis
5. ML gap-filler classifier
6. Authorization and scope model
7. Evaluation harness and golden dataset

If we can't state in one sentence what we uniquely contributed, we've over-adopted.
