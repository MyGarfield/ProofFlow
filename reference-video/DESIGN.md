# Reference Runtime Evidence — visual system

## Overview

This auxiliary evidence film inherits the captured ProofFlow console: a stark white field, black hairline grid, oversized Chinese grotesk type, and a four-color boundary signal. The source page is a local-only proof console rather than a product marketing page, so the visual language keeps UI state and evidence legible at 1920×1080. Motion is restrained: state changes, cursor-like highlights, and hash rails carry the rhythm.

## Colors

- **Surface**: `#FFFFFF` — full-frame console background.
- **Ink**: `#000000` — typography, grid, and trace.
- **Boundary blue**: `#0000FF` — public-synthetic and benchmark evidence.
- **Fail-closed red**: `#FF0000` — 409 gate and stopped/blocked truth.
- **Approval gold**: `#FFD700` — explicit local approval and attention marker.

## Typography

- **Primary**: `-apple-system`, with 400/700/800/900 weights from the captured page.
- **Mono**: `ui-monospace`, `SF Mono`, Menlo, Consolas for hashes, action ledgers, and labels.
- **Hierarchy**: 92–120px stage titles, 28–44px state labels, 18–24px body text, 16–18px metadata.

## Elevation

The page uses borders and solid color blocks instead of shadows. Evidence cards are flat, with 1–2px black rules and localized blue/red/gold signals. No external imagery or decorative gradients are introduced.

## Components

- Loopback capture frame with source URL and request policy.
- Boundary ribbon: PUBLIC SYNTHETIC / REFERENCE RUNTIME / NO LLM / Workers Stopped.
- Five-step state rail: PREPARE → HUMAN GATE → APPROVE → PACKAGE → VERIFY.
- Evidence ledger with HTTP code, stage, and expected outcome.
- Runtime truth card with `readyWorkers=0`, `LLM=OFF`, and `127.0.0.1`.
- Benchmark card showing `11/11` beside explicit “NOT ACCURACY”.
- Caption safe zone pinned above the lower trace band.

## Do's and Don'ts

### Do's

- Keep every public-boundary label visible at least once per state.
- Make `409`, `60000`, `11/11`, `UNKNOWN`, and `null` visually unambiguous.
- Preserve the captured page’s hard grid and monospace evidence notation.
- Keep captions within the 10% safe margins.

### Don'ts

- Do not use a remote font, image, CDN, URL, API, Worker, LLM, or external side effect.
- Do not turn `11/11` into an accuracy, legal, or production claim.
- Do not show PF-A1…PF-A6 as running workers.
- Do not remove the `PUBLIC SYNTHETIC / REFERENCE RUNTIME` boundary.
