#!/usr/bin/env bash
# Run black-box MECHSUIT contracts with an OCaml-built binary and JDK 17+.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/mechsuit"
if [ -n "$(printenv MECHSUIT_BIN || true)" ]; then
  BIN="$(printenv MECHSUIT_BIN)"
fi
if [[ ! -x "$BIN" ]]; then
  "$ROOT/src/build.sh" "$BIN"
fi
exec java "$ROOT/tests/MechsuitContractTest.java" "$BIN"
