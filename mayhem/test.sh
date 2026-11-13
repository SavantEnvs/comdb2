#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the pre-built comdb2 library tests (built by mayhem/build.sh with normal flags):
# upstream's tests/tools/{crle,cson_test}.c plus a known-answer probe (kat.c) diffed against kat.expected.
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# EDIT-free below: nothing is compiled here.
TB="$SRC/build-tests/bin"
for b in kat crle cson_test; do
  [ -x "$TB/$b" ] || { echo "missing $TB/$b — mayhem/build.sh did not build it" >&2; emit_ctrf "comdb2-libs" 0 1 0; exit 1; }
done

passed=0; failed=0
ok()   { passed=$((passed + 1)); }
bad()  { failed=$((failed + 1)); echo "FAIL: $1" >&2; }

# 1) known-answer probe: every expected line (comdb2rle bytes, cson tree, decQuad arithmetic, csc2 layout)
#    must appear in the probe's stdout, in order, and nothing else may.
kat_out="$("$TB/kat" 2>/dev/null)"
n=0
while IFS= read -r line; do
  n=$((n + 1))
  if printf '%s\n' "$kat_out" | grep -qxF -- "$line"; then ok; else bad "kat line $n: $line"; fi
done < "$SRC/mayhem/kat.expected"
if [ "$kat_out" = "$(cat "$SRC/mayhem/kat.expected")" ]; then ok; else bad "kat output differs from mayhem/kat.expected"; fi

# 2) upstream comdb2rle unit test: asserts internally and prints a summary line.
crle_out="$("$TB/crle" 2>&1)"; crle_rc=$?
if [ "$crle_rc" -eq 0 ] && printf '%s\n' "$crle_out" | grep -qx 'PASSED ALL TESTS' \
   && [ "$(printf '%s\n' "$crle_out" | grep -c '^passed test_')" -ge 10 ]; then ok; else bad "tests/tools/crle.c (rc=$crle_rc)"; fi

# 3) upstream cson unit test: asserts internally; check the 16 sections ran and a known serialization.
cson_out="$("$TB/cson_test" 2>&1)"; cson_rc=$?
if [ "$cson_rc" -eq 0 ] && [ "$(printf '%s\n' "$cson_out" | grep -c '^test_[a-p]$')" -eq 16 ] \
   && printf '%s\n' "$cson_out" | grep -qxF '{"obj0":{"myArray":[0,1,{}],"myInt":42,"myDouble":42.24,"myString":"hi"}}'; then
  ok; else bad "tests/tools/cson_test.c (rc=$cson_rc)"; fi

emit_ctrf "comdb2-libs" "$passed" "$failed" 0
