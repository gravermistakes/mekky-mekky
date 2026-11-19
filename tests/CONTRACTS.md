# MECHSUIT contract tests (RED baseline)

These are **black-box acceptance contracts** for the executable, not a declaration
that the current scanner is correct. They intentionally include known failures.
Do not weaken a test just to turn the build green: fix the relevant implementation
or document and explicitly renegotiate the contract.

## Run locally

Requirements: JDK 17+ and a built native OCaml MECHSUIT executable. No DNS,
third-party Java dependencies, target networks, RPC endpoints, or real wallets.

```sh
bash tests/run.sh
# Or test an existing binary:
MECHSUIT_BIN=/absolute/path/to/mechsuit bash tests/run.sh
```

The runner generates toy Solidity, Rust/Monero, and unsupported-language
fixtures in temporary directories. Inputs are local-only. Each contract is
independently scored. Nonzero exit means at least one failed contract.
Temporary files are intentionally retained for debugging.

## Executable contracts

| ID | Behavior | Observable pass criterion |
|---|---|---|
| C01 | Missing target | Nonzero exit; no report |
| C02 | Unknown ecosystem | Fail closed; no successful scan report |
| C03 | Move auto-detection | Unsupported Move is rejected, never analyzed as Monero |
| C04 | Forced Solana | Explicit unsupported toolchain is rejected |
| C05 | EVM surface and pipeline | Finds `ReadOnly.read`; emits all six artifacts |
| C06 | Non-executable text | Comments and string literals produce no vulnerability findings |
| C07 | EVM reentrancy lead | External call before state update emits a raw reentrancy lead |
| C08 | EVM lexical confidence | Detects `tx.origin` but does not self-certify `Confirmed` |
| C09 | Evidence policy | Leads are labeled unvalidated; none promoted to Accepted without proof |
| C10 | Monero false-positive guard | Wallet-side transaction-construction panic is not reported as remote DoS |
| C11 | Read-only execution | Source SHA-256 unchanged after audit |
| C12 | Deterministic analysis | Same target produces byte-identical surface, findings, graph and ranking |
| C13 | KEEL scope | `MECHSUIT_ALLOWED_ROOT` rejects targets outside an authorized root |

### Contract interpretation

- **Detection != exploitation != validation.** A lexical match is a lead,
  not a confirmed vulnerability or a justified monetary claim.
- **No substitution by fallback.** A missing scanner is an error; running the
  wrong ecosystem's scanner can yield dangerously misleading results.
- **Non-destructive operation.** Scanning an authorized source tree should
  not alter it or transmit it to another service.
- **No claim of full security from a clean report.** False negatives remain
  possible; negative fixtures only exercise known cases.
- **Scope contract C13 defines a proposed interface.** The current KEEL module
  has a scope helper, but CLI enforcement of this environment variable has
  not yet been implemented.
- **No dependency on the internet.** Java is the external test driver,
  not a replacement for OCaml scanner modules.

## Known initial RED targets

At the time these contracts were authored, inspection of the code indicated:

- Unsupported and unknown toolchains fall back to Monero in `src/mechsuit.ml`.
- `src/opaca_vigolium.ml` scans raw Solidity text, including comments/strings,
  and can self-label pattern hits `Confirmed`.
- KEEL's target allowlist is not connected to the executable CLI.
- The existing Monero false-positive hardening and unvalidated-lead banner
  should survive future changes.

These are **source inspection observations**, not a measured failure count of
the OCaml binary in this environment. An actual native binary must be compiled
and run to establish the real RED baseline.

## Phase-two contracts (specification only; not executable yet)

1. Strict JSON parse/schema checks for all machine-readable artifacts.
2. Witness-chain recomputation and detection of tampering, omission, or reordering.
3. Canonicalized scope checks (symlinks, parent traversal, nested repositories).
4. Accurate Solidity source locations; distinct contracts sharing function names.
5. A valid compiling PoC plus untrusted-input reachability before `Accepted`.
6. Explicit CPU, memory, file-count and execution-time budgets for hostile inputs.
7. Mutation and differential testing against established analysis tools.
8. Precision/recall measurement over a versioned labeled fixture corpus.

Do not use MECHSUIT output as conclusive evidence for a bounty submission
until the evidence workflow is itself proven.
