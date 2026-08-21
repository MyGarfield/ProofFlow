# Storyboard — 92s evidence-only capture

**Format:** 1920×1080, H.264 yuv420p, 30fps, faststart
**Audio:** manual Chinese SRT + 92s AAC placeholder silence (local TTS unavailable)
**VO direction:** no voiceover claim; subtitles are the authoritative narration layer
**Style basis:** captured ProofFlow console tokens (`#FFFFFF`, `#000000`, `#0000FF`, `#FF0000`, `#FFD700`)

## Global safety frame

The top ribbon and bottom caption-safe zone remain legible in every state. A small upper-right source chip reads `http://127.0.0.1:8765` and `CAPTURE CLIENT · NON-LOOPBACK SENT: 0`. Every state card repeats `REFERENCE RUNTIME / NO LLM` to prevent accidental over-claiming. This is a capture-client ledger claim, not a host-wide browser or network observation.

## Beats

### 1 — captured page + boundary (0–10s)

Show the actual HyperFrames capture screenshot of the loopback page, with a thin blue source bar and a red annotation: `PAGE-LEVEL CAPTURE / NO EXTERNAL REQUESTS`. The boundary ribbon remains dominant. A deterministic scanline moves once across the screenshot.

### 2 — PREPARE (10–26s)

Render the captured console as a structured state card. The PREPARE rail is gold and `AWAITING_APPROVAL` is large. Show 13 Evidence, 4 Rules, 60000 CNY REF., and 0 package files. The runtime truth card says Workers Stopped, readyWorkers 0, LLM OFF, network 127.0.0.1. Hash rails scroll only through fixed characters.

### 3 — 409 fail-closed (26–41s)

Cut to red gate treatment. The state rail freezes on HUMAN GATE; a single large `HTTP 409` and `HUMAN_GATE_REQUIRED` stamp enters. The package counter remains 0 and stage remains AWAITING_APPROVAL. A red ledger row says `EXPECTED / BLOCKED`.

### 4 — LOCAL_DEMO (41–58s)

Gold approval treatment. The reason field is outlined but explicitly labeled synthetic/local. Show `approval_method=LOCAL_DEMO`, `approver_role=legal-reviewer`, and “subject hash bound”. Keep the top boundary labels and stopped-worker card visible.

### 5 — PACKAGE (58–66s)

Black package panel slides into the rail: `PACKAGED`, `review-draft.md`, `review-manifest.json`, `external_side_effects_enabled=false`. The visual motion is a short horizontal seal sweep.

### 6 — VERIFY (66–75s)

Blue verification panel. Show `VALID`, `checked_artifacts=25`, `checked_package_files=2`, and `errors=[]`. Add a quiet hash checkmark; do not use a “correctness” badge.

### 7 — 11/11 + limitations (75–92s)

Benchmark card resolves to `11/11`. Beside it, a black limitation block states `NOT ACCURACY`, `60000 NOT LEGAL CONCLUSION`, `Worker/LLM eval UNKNOWN`, `scores=null`. End on the full boundary ribbon and a final “reference runtime only” lockup.

## Capture artifacts and ledger

The source page capture is in `capture/`. The sequence is replayed against `http://127.0.0.1:8765` by `evidence/capture_sequence.py`; `action-ledger.json`, `network-ledger.json`, and `dom-states.json` are retained without tokens or secrets.
