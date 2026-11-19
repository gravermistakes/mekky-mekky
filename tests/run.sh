#!/usr/bin/env bash
# End-to-end behavioral contracts. Deliberately RED while known defects exist.
# No network, real target exploits, signing keys, or chain transactions.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failures=0
tests=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }
check() {
  tests=$((tests + 1))
  label="$1"; shift
  if "$@"; then pass "$label"; else fail "$label"; fi
}
expect_failure() {
  label="$1"; log="$2"; shift 2
  tests=$((tests + 1))
  if "$@" >"$log" 2>&1; then fail "$label"; else pass "$label"; fi
}

command -v ocamlopt >/dev/null || { echo "ocamlopt required (>= 5.1)" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq required for JSON schema assertions" >&2; exit 2; }

printf '%s\n' '=== Build ==='
sh "$ROOT/src/build.sh" "$TMP/mechsuit"

printf '%s\n' '=== OCaml unit contracts ==='
ocamlopt -I "$ROOT/src" -I +str -I +unix str.cmxa unix.cmxa \
  "$ROOT/src/shell.cmx" "$ROOT/src/msg.cmx" "$ROOT/src/keel.cmx" \
  "$ROOT/src/witness_actor.cmx" "$ROOT/src/opaca_noir.cmx" \
  "$ROOT/src/opaca_vigolium.cmx" "$ROOT/src/toolchain_monero.cmx" \
  "$ROOT/src/toolchain.cmx" "$ROOT/src/graph_actor.cmx" \
  "$ROOT/src/solver_actor.cmx" "$ROOT/src/lance_actor.cmx" \
  "$ROOT/src/report_actor.cmx" \
  "$ROOT/tests/contract_tests.ml" -o "$TMP/unit_contracts"
tests=$((tests + 1))
if "$TMP/unit_contracts"; then pass "OCaml unit contracts"; else fail "OCaml unit contracts"; fi

printf '%s\n' '=== Isolated synthetic targets ==='
mkdir -p "$TMP/safe" "$TMP/vulnerable" "$TMP/solana" "$TMP/unknown"

cat >"$TMP/safe/Calculator.sol" <<'SOL'
pragma solidity ^0.8.20;
contract Calculator {
    function sum(uint256 a, uint256 b) external pure returns(uint256) {
        return a + b;
    }
}
SOL
cat >"$TMP/vulnerable/Vault.sol" <<'SOL'
pragma solidity ^0.8.20;
contract Vault {
    uint256 public balance;
    function withdraw() external {
        (bool ok,) = msg.sender.call{value: 1}("");
        require(ok);
        balance = 0;
    }
}
SOL
cat >"$TMP/solana/Cargo.toml" <<'TOML'
[package]
name = "example"
version = "0.1.0"
[dependencies]
solana-program = "2.0"
TOML
cat >"$TMP/solana/lib.rs" <<'RUST'
pub fn example() { }
RUST

printf '%s\n' '=== Supported EVM execution ==='
before="$(sha256sum "$TMP/safe/Calculator.sol" | cut -d' ' -f1)"
if "$TMP/mechsuit" "$TMP/safe" "$TMP/out_safe" >"$TMP/safe.log" 2>&1; then
  pass "EVM fixture runs to completion"
else
  fail "EVM fixture runs to completion"
fi
tests=$((tests + 1))
check "Noir writes a parseable endpoint array" \
  jq -e 'type=="array" and length>=1' "$TMP/out_safe/mechsuit_noir.json"
check "Vigolium writes a parseable findings document" \
  jq -e '.findings | type=="array"' "$TMP/out_safe/mechsuit_vigolium.json"
check "Graph output contains nodes and edges arrays" \
  jq -e '(.nodes|type=="array") and (.edges|type=="array")' "$TMP/out_safe/mechsuit_graph.json"
check "Ranked graph output remains valid JSON" \
  jq -e '(.nodes|type=="array") and (.edges|type=="array")' "$TMP/out_safe/mechsuit_ranked.json"
check "Safe calculator has zero scanner findings" \
  jq -e '.findings|length==0' "$TMP/out_safe/mechsuit_vigolium.json"
after="$(sha256sum "$TMP/safe/Calculator.sol" | cut -d' ' -f1)"
tests=$((tests + 1))
if [ "$before" = "$after" ] && [ "$(find "$TMP/safe" -type f | wc -l)" -eq 1 ]; then
  pass "Scanning does not modify target files or add files to target"
else
  fail "Scanning does not modify target files or add files to target"
fi
check "Witness log exists and records the report phase" \
  grep -Eq '^[0-9]+\|report\|[a-f0-9]{64}$' "$TMP/out_safe/mechsuit_witness.log"
check "Report includes explicit unvalidated-lead warning" \
  grep -q 'UNVALIDATED SCANNER LEADS' "$TMP/out_safe/mechsuit_report.md"

printf '%s\n' '=== Vulnerable synthetic EVM fixture ==='
if "$TMP/mechsuit" "$TMP/vulnerable" "$TMP/out_vulnerable" >"$TMP/vulnerable.log" 2>&1; then
  pass "Vulnerable EVM fixture runs to completion"
else
  fail "Vulnerable EVM fixture runs to completion"
fi
tests=$((tests + 1))
check "Raw scanner recognizes call-before-update reentrancy" \
  jq -e 'any(.findings[]; .pattern == "reentrancy")' "$TMP/out_vulnerable/mechsuit_vigolium.json"
check "Raw lexical scan never claims confirmed exploit" \
  jq -e 'all(.findings[]; .confidence != "confirmed")' "$TMP/out_vulnerable/mechsuit_vigolium.json"
check "Vulnerability report retains uncertainty and evidence requirement" \
  grep -q 'Needs Evidence' "$TMP/out_vulnerable/mechsuit_report.md"

printf '%s\n' '=== Fail-closed boundaries ==='
expect_failure "Missing target is rejected" "$TMP/missing.log" \
  "$TMP/mechsuit" "$TMP/not_a_directory" "$TMP/missing_out"
expect_failure "Unknown ecosystem is rejected instead of treated as Monero" "$TMP/unknown.log" \
  "$TMP/mechsuit" "$TMP/unknown" "$TMP/out_unknown"
tests=$((tests + 1))
if [ ! -e "$TMP/out_unknown/mechsuit_report.md" ]; then
  pass "Unknown ecosystem produces no misleading completed report"
else
  fail "Unknown ecosystem produces no misleading completed report"
fi
expect_failure "Explicit unsupported Solana toolchain is rejected" "$TMP/solana.log" \
  "$TMP/mechsuit" "$TMP/solana" "$TMP/out_solana" --toolchain solana
tests=$((tests + 1))
if [ ! -e "$TMP/out_solana/mechsuit_report.md" ]; then
  pass "Unsupported toolchain produces no misleading completed report"
else
  fail "Unsupported toolchain produces no misleading completed report"
fi
check "Ecosystem rejection never advertises silent Monero fallback" \
  sh -c '! grep -qi "falling back to monero" "$1" "$2"' _ "$TMP/unknown.log" "$TMP/solana.log"

printf '%s\n' '=== Path safety ==='
tests=$((tests + 1))
if "$TMP/mechsuit" "$TMP/safe" "$TMP/output with spaces" >"$TMP/spaces.log" 2>&1 &&
   [ -f "$TMP/output with spaces/mechsuit_report.md" ]; then
  pass "Output directory with whitespace is handled safely"
else
  fail "Output directory with whitespace is handled safely"
fi

printf '\nE2E contracts: %s assertions; %s failed.\n' "$tests" "$failures"
[ "$failures" -eq 0 ]
