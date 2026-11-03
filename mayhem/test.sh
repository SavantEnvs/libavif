#!/usr/bin/env bash
#
# mayhem/test.sh — RUN libavif's OWN gtest suite (already built by mayhem/build.sh into build-tests/).
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

TESTS=(avifbasictest avifdecodetest avifencodetest avifrgbtest avifrgbtoyuvtest avifcolrtest
       avifclaptest avifutilstest avifstreamtest avifpropinternaltest avifimagetest avifgridapitest
       avifincrtest avifreadimagetest avifanimationtest avif16bittest avifmetadatatest aviftilingtest
       avifopaquetest avifpixitest avifalphapremtest avifcicptest avifchangesettingtest)
# Tests that take the tests/data directory as argv[1] (add_avif_gtest_with_data in tests/CMakeLists.txt).
WITH_DATA=" avif16bittest avifdecodetest avifencodetest avifincrtest avifreadimagetest avifanimationtest avifmetadatatest avifpixitest avifchangesettingtest "

# Each gtest binary is run directly (not through ctest) and its own "[==========] N tests ... ran" /
# "[  PASSED  ] P" report is parsed, so a binary that exits 0 without running anything counts as a failure.
passed=0; failed=0; skipped=0
for t in "${TESTS[@]}"; do
  exe="build-tests/tests/$t"
  if [ ! -x "$exe" ]; then echo "MISSING test binary $exe (mayhem/build.sh did not build it)" >&2; failed=$((failed+1)); continue; fi
  args=()
  case "$WITH_DATA" in *" $t "*) args=("$SRC/tests/data/") ;; esac
  out=$(timeout 1200 "$exe" "${args[@]}" 2>&1); rc=$?
  printf '%s\n' "$out" | tail -n 5
  ran=$(printf '%s\n' "$out" | sed -n 's/^\[==========\] \([0-9][0-9]*\) tests\? from .* ran\..*/\1/p' | tail -n1)
  ok=$(printf '%s\n' "$out" | sed -n 's/^\[  PASSED  \] \([0-9][0-9]*\) tests\?\..*/\1/p' | tail -n1)
  sk=$(printf '%s\n' "$out" | sed -n 's/^\[  SKIPPED \] \([0-9][0-9]*\) tests\?, listed below.*/\1/p' | tail -n1)
  if [ -z "$ran" ] || [ -z "$ok" ] || [ "$rc" -ne 0 ]; then
    echo "FAIL $t (rc=$rc, ran='${ran:-}', passed='${ok:-}')" >&2
    nf=$(printf '%s\n' "$out" | sed -n 's/^\[  FAILED  \] \([0-9][0-9]*\) tests\?, listed below.*/\1/p' | tail -n1)
    failed=$((failed + ${nf:-1})); passed=$((passed + ${ok:-0}))
  else
    passed=$((passed + ok)); skipped=$((skipped + ${sk:-0}))
  fi
done
emit_ctrf "gtest" "$passed" "$failed" "$skipped"
