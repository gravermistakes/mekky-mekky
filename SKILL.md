---
name: mechsuit
version: 2.0.0
ecosystem: [evm, monero]
pending_ecosystems: [solana, move, bitcoin, cosmos]
triggers: [audit, security, vulnerability, smart contract, crypto, exploit, bounty, suit up, get in the robot, full audit, recursive scan, opaca scan]
toolchain: ocaml-4.14
dependencies: []
author: KAIROS-0
architect: gravermistakes
license: copyleft
---

# MECHSUIT — Opaca-Integrated Exploit Discovery Pipeline

Self-contained recursive exploit discovery for Web3 protocol auditing. All tools reimplemented as native OCaml 5 modules under the **Opaca** namespace. Single binary. Zero external dependencies.

## Architecture

```
Target Dir ──┐
             ├── opaca_noir (surface map) ──┐
             │                               ├── graph_actor ── solver ── lance ── report
             └── opaca_vigolium (vuln scan) ─┘
                                                                              │
                                                              witness chain (SHA256)
                                                                              │
                                                                    KEEL (kill switch)
```

## Pipeline Phases

| Phase | Module | Function |
|-------|--------|----------|
| 1a | `opaca_noir.ml` | Parse .sol files → endpoints, modifiers, state, callees, sinks |
| 1b | `opaca_vigolium.ml` | Pattern-based vuln detection → findings with severity/confidence |
| 2 | `graph_actor.ml` | Merge endpoints + findings into weighted attack graph |
| 3 | `solver_actor.ml` | 5-iteration push-propagation flow ranking |
| 4 | `lance_actor.ml` | 7-gate triage: scope, severity, path, chain, confidence, FP, economics |
| 5 | `report_actor.ml` | Immunefi-format markdown report with witness chain |

## Usage

```bash
# Build (once)
./src/build.sh

# Run
./mechsuit /path/to/contracts /tmp

# Or via harness
MECHSUIT_TARGET=/path/to/contracts ./harness/run.sh
```

## Outputs

| File | Content |
|------|---------|
| `mechsuit_noir.json` | Endpoint surface map |
| `mechsuit_vigolium.json` | Raw vulnerability findings |
| `mechsuit_graph.json` | Attack graph (nodes + edges) |
| `mechsuit_ranked.json` | Flow-ranked graph |
| `mechsuit_report.md` | Immunefi-format report |
| `mechsuit_witness.log` | SHA256 witness chain |

## Governance

- **KEEL**: Hard-stop kill switch. Fires on out-of-scope targets or unrecoverable errors.
- **Witness Chain**: Every phase records `epoch|phase|sha256` — append-only, hash-linked.
- **ANALGAPES Layer Mapping**:
  - L0 Perception: opaca_noir + opaca_vigolium
  - L1 Cognition: solver flow ranking
  - L2 Action: lance 7-gate triage
  - L3 Metacognition: witness chain audit
  - L4 Governance: KEEL

## Triggers

`mechsuit`, `suit up`, `get in the robot`, `full audit`, `recursive scan`, `opaca scan`, `scan this`

## File Layout

```
mechsuit/
├── SKILL.md
├── CLAUDE.md
├── AGENTS.md
├── plugin.json
├── marketplace.json
├── src/
│   ├── build.sh
│   ├── shell.ml
│   ├── msg.ml
│   ├── keel.ml
│   ├── witness_actor.ml
│   ├── opaca_noir.ml        ← replaces noir (75MB Crystal repo)
│   ├── opaca_vigolium.ml    ← replaces vigolium (66MB Go repo)
│   ├── graph_actor.ml
│   ├── solver_actor.ml      ← replaces sublinear-time-solver (96MB)
│   ├── lance_actor.ml
│   ├── report_actor.ml
│   └── mechsuit.ml          (supervisor)
├── harness/
│   ├── run.sh
│   ├── transforms/
│   │   ├── to_graph.sh      (jq compat layer)
│   │   └── to_lance.sh      (jq compat layer)
│   └── config/
│       └── sky.env
└── lance/
    ├── scripts/              (Python report gen)
    ├── assets/templates/     (Immunefi/Bugcrowd templates)
    └── references/           (vulnerability playbooks)
```

## What Was Removed

| Removed | Size | Replaced By |
|---------|------|-------------|
| `noir/` (Crystal repo) | 75MB | `opaca_noir.ml` (150 lines) |
| `vigolium/` (Go repo) | 66MB | `opaca_vigolium.ml` (180 lines) |
| `sublinear-time-solver/` (Rust/Node) | 96MB | `solver_actor.ml` (30 lines, already native) |
| `Archon/` (TypeScript) | 11MB | `harness/run.sh` (30 lines) |
| `local-logic/` | 2MB | removed (unused) |
| **Total removed** | **250MB** | **~400 lines OCaml** |
