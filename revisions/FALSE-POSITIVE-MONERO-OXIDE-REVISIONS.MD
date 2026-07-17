# MECHSUIT hardening — false-positive elimination

Cause of the Monero-Oxide "Confirmed Medium DoS" false positive, and the fix.
Verified by building the pipeline (ocaml 4.14) and running it against
monero-oxide @ 32e6b5fe before and after.

## Root cause (two layers)

1. Scanner self-certified confidence from lexical presence.
   `toolchain_monero.detect_panic_paths` stamped `Confirmed` /
   "guaranteed DoS path" on any `panic!` inside a `pub fn`. No build, no
   reachability, no taint from an untrusted entry point, no awareness of a
   preceding `validate()`. It cannot tell the wallet send path from the
   verify path because it never builds a call graph.

2. The 7 gates did not gate.
   `graph_actor` dropped the file path, so `lance` G0 (scope) tested the
   synthetic node id `vuln_0_...` instead of `wallet/src/send/tx.rs` and
   could not exclude tests or send paths. G2/G3 were near-tautologies, G5 a
   4-word denylist. Result: 381 in, 381 out. Nothing rejected.

The polished report (prose threat model + a non-compiling PoC + $5K) was then
written by the agent layer on top of a lead the tool labeled "Needs Evidence".

## Fix

- `toolchain_monero.ml`: panic!/unwrap/expect -> Theoretical (leads, not DoS).
  Lexical constant-time "Confirmed" -> Probable. Central clamp in `scan_file`:
  a pattern scanner can never emit Confirmed.
- `msg.ml`: carry real `file` + `pattern` into `graph_node`; add `file` to `finding`.
- `graph_actor.ml`: set file/pattern on every node.
- `lance_actor.ml`: gates read the real path. G0 rejects test/bench/example/fuzz/mock.
  G5 rejects panic/overflow DoS claims on send/construction paths (self-inflicted,
  not broadcast-reachable). G6: Confirmed requires an evidence artifact. G0/G4/G5/G6
  are hard (all must hold).
- `report_actor.ml`: cite the real source path; stamp every report UNVALIDATED
  LEADS with an explicit "compile a PoC + trace reachability before submit" banner.

## Before / after (monero-oxide @ 32e6b5fe, `-t monero`)

| metric                              | before | after |
|-------------------------------------|--------|-------|
| raw findings                        | 381    | 381   |
| passed triage                       | 381    | 150   |
| Confirmed in report                 | 7+     | 0     |
| "Reachable Panic (DoS)" surviving   | 3x send/tx.rs + more | 0 |
| scanner self-certified Confirmed    | 9      | 0     |
| passing findings' confidence        | mixed  | all Probable |

The exact finding that became the uploaded report (send/tx.rs:51,220,292) is now
rejected at G4 (Theoretical) and G5 (send path).

## Still open (not fixed here — design calls for the pilot)

- 150 Probable leads is still noisy; crypto-invariant detector is name-substring
  based (222 raw). Real reachability needs a call graph from untrusted entry
  points (deserialize/verify), which a lexical pass cannot provide.
- `opaca_vigolium.ml` (EVM) was not re-read; its scanner may still emit Confirmed.
  Lance G6 catches it downstream, but the same clamp belongs in that scanner too.
- No evidence-attachment mechanism exists, so nothing can legitimately reach
  Confirmed via the pipeline. That is correct: Confirmed is a human/PoC verdict.