#!/bin/sh
set -e
OCAMLOPT=${OCAMLOPT:-ocamlopt}
SRC=$(dirname "$0")
OUT=${1:-$SRC/../mechsuit}

echo "[BUILD] mechsuit (multi-ecosystem toolchain)"
$OCAMLOPT -version

cd "$SRC"

# Compile order matters — dependencies first
MODULES="shell msg keel witness_actor opaca_noir opaca_vigolium toolchain_monero toolchain graph_actor solver_actor lance_actor report_actor mechsuit"

for f in $MODULES; do
  $OCAMLOPT -I +str -I +unix -c ${f}.ml && echo "  ok $f" || { echo "  FAIL $f"; exit 1; }
done

$OCAMLOPT -I +str -I +unix str.cmxa unix.cmxa \
  $(echo $MODULES | tr ' ' '\n' | sed 's/$/.cmx/' | tr '\n' ' ') \
  -o "$OUT"

echo "[BUILD] $OUT ($(du -h "$OUT" | cut -f1))"
echo "[BUILD] ecosystems: evm, monero (solana/move/bitcoin/cosmos: pending)"
