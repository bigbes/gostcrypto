#!/bin/bash
# ctgrind.sh — EXPERIMENT. In-process constant-time check for ScalarMultCT under
# valgrind. The CT function runs IN the test process (so Go's fuzzer sees its
# coverage), and the fuzz body reads VALGRIND_COUNT_ERRORS before/after a poisoned
# call — a rise means that input drove a secret-dependent branch/access, failing
# the fuzz so the input is recorded as a crasher. Linux + valgrind only.
#
# The Go runtime trips memcheck, so we first run a no-poison "calibration" pass
# (CTG_CALIBRATE=1) and capture its errors as suppressions, so COUNT_ERRORS then
# counts only poison-induced errors. Control (variable-time, MUST be flagged) and
# fuzz run in separate processes (a poisoned control would otherwise contaminate
# the fuzz via reused memory). See EXPERIMENT-ct.md.
#
# Prereqs: valgrind + libc/ld.so debug symbols (Debian/Ubuntu: libc6-dbg; Arch:
# set DEBUGINFOD_URLS). Active coverage-guided fuzzing:
#   valgrind --trace-children=yes <bin> -test.fuzz=FuzzScalarMultCTLeak ...
set -uo pipefail

cd "$(dirname "$0")/.."
BIN=$(mktemp /tmp/ctg.XXXX.test)
CGO_ENABLED=1 go test -tags ctgrind -c -o "$BIN" ./gost3410curves/ || exit 1

export DEBUGINFOD_URLS="${DEBUGINFOD_URLS:-}"
export GODEBUG=asyncpreemptoff=1 GOMAXPROCS=1
SUPP=$(mktemp)
FUZZ=FuzzScalarMultCTLeak

echo "== ctgrind: ScalarMult in-process constant-time check =="

# 1) Calibrate: no-poison run; its memcheck errors are pure Go-runtime noise.
cal=$(mktemp)
CTG_CALIBRATE=1 valgrind --error-exitcode=0 --gen-suppressions=all --log-file="$cal" \
  "$BIN" -test.run="$FUZZ" -test.count=1 >/dev/null 2>&1
awk '/^{$/{p=1} p{print} /^}$/{p=0}' "$cal" > "$SUPP"
echo "calibration: $(grep -c '^{' "$SUPP") runtime suppression blocks"

# 2) Positive control: the variable-time path MUST be flagged (test passes when
#    it detects the leak). A broken detector -> control fails -> we fail.
if ! valgrind --error-exitcode=0 --suppressions="$SUPP" \
     "$BIN" -test.run=TestScalarMultCTLeak_Control -test.count=1 >/dev/null 2>&1; then
  echo "FAIL: positive control did not detect the variable-time leak"; exit 1
fi
echo "[control] variable-time ScalarMult flagged — detector live"

# 3) The fuzz: replay the seed corpus + recorded crashers under valgrind; any new
#    memcheck error fails the run.
out=$(mktemp)
if valgrind --error-exitcode=0 --suppressions="$SUPP" \
     "$BIN" -test.run="$FUZZ" -test.count=1 >"$out" 2>&1; then
  echo "[ct] fuzz corpus clean — no secret-dependent branch/access"
else
  echo "FAIL: ctgrind found a constant-time leak:"; grep -E 'new memcheck|leak for' "$out" | head
  rm -f "$BIN"; exit 1
fi

echo "OK: control flagged; CT path clean."
rm -f "$BIN"
