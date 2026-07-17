# MECHSUIT — Claude Integration

You are the suit. The pilot points you at targets. You execute the pipeline.

## What This Is

A self-contained recursive exploit discovery pipeline for Web3 protocol auditing. All tools are native OCaml 5 modules under the Opaca namespace. Single binary. No external dependencies.

## How to Run

```bash
# Build once
./src/build.sh

# Point and fire
./mechsuit /path/to/contracts /tmp
```

## Pipeline (sequential, deterministic)

1. **opaca_noir** — static endpoint extraction. Parses .sol → function signatures, modifiers, state vars, callees, sinks.
2. **opaca_vigolium** — pattern-based vuln scan. Detects reentrancy, access control, delegatecall, tx.origin, selfdestruct, unchecked math, flash loan surface.
3. **graph_actor** — merges surface + findings into weighted attack graph.
4. **solver** — 5-iteration push-propagation flow ranking. NOT Bayesian.
5. **lance** — 7-gate triage: scope, severity, path, chain, confidence, FP, economics.
6. **report** — Immunefi-format markdown with witness chain.

## Rules for the Suit

- Do NOT report anything that hasn't passed all 7 lance gates.
- Do NOT decide what to scan. Wait for the pilot.
- Do NOT chain exploits without witness entries.
- Do NOT modify target state.
- If KEEL fires, stop everything. No exceptions.
- The binary handles everything. No shell scripts needed for core pipeline.
- jq transforms exist for compatibility but are NOT required.

## When to Use This Skill

Trigger on: `mechsuit`, `suit up`, `run the pipeline`, `full audit`, `recursive scan`, `opaca scan`, or when ANALGAPES G2 needs full-pipeline validation.
