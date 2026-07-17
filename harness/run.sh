#!/bin/bash  
# run.sh — mechsuit pipeline runner. fully self-contained.  
# Well thats the target anyway, but for some reason Opus 4.8 hates me?
# --CulpabilityAnchor: Anja Evermoor

set -euo pipefail  
  
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"  
MECHSUIT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"  
MECHSUIT_BIN="$MECHSUIT_ROOT/mechsuit"  
TARGET="${MECHSUIT_TARGET:-${1:-}}"  
OUTDIR="${MECHSUIT_OUTDIR:-/tmp}"  
  
if [ -z "$TARGET" ]; then  
  echo "usage: MECHSUIT_TARGET=/path/to/contracts ./harness/run.sh" >&2  
  echo "   or: ./harness/run.sh /path/to/contracts" >&2  
  exit 1  
fi  
  
if [ ! -d "$TARGET" ]; then  
  echo "[KEEL] target does not exist: $TARGET" >&2  
  exit 1  
fi  
  
# ── Build if needed ──  
if [ ! -x "$MECHSUIT_BIN" ]; then  
  echo "[HARNESS] building mechsuit binary..." >&2  
  "$MECHSUIT_ROOT/src/build.sh" "$MECHSUIT_BIN"  
fi  
  
# ── Execute ──  
echo "[HARNESS] target: $TARGET" >&2  
echo "[HARNESS] output: $OUTDIR" >&2  
exec "$MECHSUIT_BIN" "$TARGET" "$OUTDIR"  
  
