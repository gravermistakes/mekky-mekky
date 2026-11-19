# MECHSUIT behavioral acceptance contracts — v1 (RED)

**Purpose:** establish what must be demonstrated before the suit can claim it has found a vulnerability. The tests are intentionally independent of existing implementation decisions and deliberately fail where the implementation does not satisfy the contract.

**Scope:** static, read-only tests against self-contained synthetic programs. No live networks, wallets, third-party targets, exploit transactions, or production secrets.

## Evidence levels (required semantics)

1. **Surface:** a parsed endpoint, state variable, callee, or risk-sensitive operation. Not a vulnerability.
2. **Lead:** a lexical/static indicator with a source location and explicit uncertainty. Not an exploit.
3. **Candidate:** a lead tied to the relevant callable entry point, preconditions, and plausible attacker-controlled path.
4. **Verified:** a reproducible exploit or proof with a compiling, isolated PoC, observed impact, source location, reachability trace, and scope authorization.

The suite must NEVER promote a lexical match straight to **Verified**, even if a detector uses a name such as \`Confirmed\`. 'No findings' must be communicated as **no findings in supported checked coverage**, not as a security guarantee. Use **incomplete** or **unsupported** for unanalysed input rather than green-checkmark success.

## Minimum behavioral requirements

| Requirement | Observable acceptance criterion | Gate |
|---|---|---|
| A01: EVM support | Correctly map contract/function identity, visibility, state changes, calls and sinks | Parser |
| A02: Comment/string isolation | Code-like text in comments and string literals creates no endpoint or vulnerability | Scanner |
| A03: True positive | A synthetic call-before-state-update withdrawal generates a reentrancy lead | Scanner |
| A04: True negative | A safe pure arithmetic calculator generates zero vulnerability findings | Scanner |
| A05: Confidence integrity | Static matches never claim exploit confirmation without evidence | Scanner |
| A06: Graph provenance | Connect a lead only to source-matched functions and plausible call chains, not all functions in its file | Graph |
| A07: Ranking | Identical inputs produce deterministic, stable rankings; ranking does not manufacture reachability | Solver |
| A08: Scope | Unlisted targets fail closed, including an explicit empty allowlist | KEEL |
| A09: Toolchain support | Unsupported/unknown ecosystems produce a nonzero exit and cannot emit a completed 'clean' report | Supervisor |
| A10: Evidence gating | Unconfirmed leads remain needs-evidence, fixtures are excluded from production candidates, unsupported confidence is rejected | Lance |
| A11: Provenance | Witness output supports independent verification of ordering, integrity, and binding to scan inputs | Witness |
| A12: Report quality | Reports identify unvalidated leads and provide accurate counts and missing-evidence requirements | Reporter |
| A13: Read-only operation | A scan neither mutates the target nor adds files within it | Integration |
| A14: Path handling | Whitespace in output paths does not invoke shell interpolation errors or unintended commands | Integration |
| A15: Unknown syntax | A parser failure is distinguishable from a clean scan; no swallowed exceptions produce false assurance | Scanner |
| A16: Capability boundaries | EVM / Monero support claims must be verified separately; Solana, Move, Cosmos, Bitcoin remain explicitly unsupported until conformance suites pass | Product |

## Running

\`\`\`sh
bash tests/run.sh
\`\`\`

Requires OCaml 5.1+ (\`ocamlopt\`), \`jq\`, \`sha256sum\`, and a local POSIX shell. The production tool does **not** require Java or Python. CI uses OCaml 5.2 and disposable synthetic fixtures.

The runner prints PASS/FAIL per check, returns nonzero when any assertion fails, and does not mask failures. This is the **RED phase**: a failed build or test is actionable evidence. Do not relabel the tests as passing by omitting failing assertions.

## Immediate expected failures in current main

- Empty allowlist is treated as allow-all.
- Unsupported toolchains silently fall back to Monero.
- Vulnerability graph links a file-level finding to every endpoint in that file.
- Scanner can match comment/string text as executable patterns.
- Some lexical detectors set \`Confirmed\` without an exploit proof.
- Output directories containing whitespace may break the shell utility.
- Witness digest chain cannot currently be independently replayed from the emitted log.

## Follow-up suites (not yet implemented)

- Malformed Solidity, nested comments, multi-contract fixtures, inheritance, library links, assembly and generated code.
- Differential comparison with compiler ASTs and reputable reference analyzers; measure both precision and recall on labeled fixtures.
- Known-fix and known-vulnerable twins differing by one relevant operation.
- Monero-specific crypto constant-time, public-input panic, parser invariant and consensus-divergence fixtures.
- Proof replay and independently verified witness-chain integrity.
- Path symlinks, traversal, output collision, shell metacharacters, and resource-exhaustion cases.
- Property and mutation tests, performance caps, deterministic seeded fuzzing.
- Responsible-disclosure report quality and authorization gates.

**Do not use this suite as evidence of production vulnerability detection until the synthetic test failures are resolved, and then calibrated against an independent labeled corpus.**
