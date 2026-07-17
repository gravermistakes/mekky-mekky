# MECHSUIT — Agent Integration

## Build

```bash
./src/build.sh
# Requires: ocamlopt >= 5.1
# Produces: ./mechsuit (~4MB static binary)
```

## Run

```bash
./mechsuit <target_dir> [output_dir]
```

## Agent Tool Interface

### Inputs

| Var | Required | Description |
|-----|----------|-------------|
| `$1` (argv) | yes | Path to target contract directory |
| `$2` (argv) | no | Output directory (default: `.`) |
| `MECHSUIT_TARGET` | alt | Same as $1, used by harness |
| `MECHSUIT_OUTDIR` | no | Same as $2, used by harness |

### Outputs

| File | Format | Description |
|------|--------|-------------|
| `mechsuit_noir.json` | JSON array | Endpoint surface map |
| `mechsuit_vigolium.json` | JSON object | `{findings: [...]}` |
| `mechsuit_graph.json` | JSON object | `{nodes: [...], edges: [...]}` |
| `mechsuit_ranked.json` | JSON object | Flow-ranked graph |
| `mechsuit_report.md` | Markdown | Immunefi-format report |
| `mechsuit_witness.log` | Text | SHA256 witness chain |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Pipeline complete |
| 1 | Missing target or usage error |
| 2 | KEEL halt (governance stop) |

## Governance

ANALGAPES layer mapping:
- L0 Perception: opaca_noir + opaca_vigolium
- L1 Cognition: solver flow ranking
- L2 Action: lance triage
- L3 Metacognition: witness chain
- L4 Governance: KEEL

Witness chain at `mechsuit_witness.log`. Every phase records `epoch|phase|sha256`.

## Dependencies

**Runtime**: OCaml 5.1+ (for compilation only — binary is static)
**Optional**: jq (for legacy transform scripts), python3 (for lance report scripts)
**External tools**: NONE. Everything is native.
