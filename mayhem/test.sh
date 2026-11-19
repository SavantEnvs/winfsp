#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
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

# Upstream's own unit tests for the code the harnesses fuzz (tst/winfsp-tests, run by ext/tlib),
# built by mayhem/build.sh. The rest of upstream's suite needs a Windows kernel with the WinFsp
# driver loaded (it mounts memfs volumes), and posix-test.c's SID/ACL cases need the Win32
# security APIs, so only these cases run:
WINFSP_TESTS=(path_prefix_test path_suffix_test
              dirbuf_empty_test dirbuf_dots_test dirbuf_fill_test dirbuf_presort_fill_test
              dirbuf_boundary_test posix_map_path_test)
FUSE_TESTS=(fuse_opt_parse_test)

passed=0 failed=0
# run_tlib <runner> <test names...>: tlib's TAP output is "ok N name" / "not ok N name" per case
# and a final "1..N" plan; any named case that does not report "ok" counts as failed.
run_tlib() {
  local runner="$1"; shift
  if [ ! -x "$runner" ]; then
    echo "test.sh: $runner missing -- mayhem/build.sh must build it" >&2
    failed=$((failed + $#)); return
  fi
  local out t
  out=$("$runner" --tap --no-abort "$@" 2>&1); echo "$out"
  for t in "$@"; do
    if grep -Eq "^ok [0-9]+ $t\$" <<<"$out"; then passed=$((passed + 1)); else failed=$((failed + 1)); fi
  done
}
run_tlib mayhem/build/winfsp-tests "${WINFSP_TESTS[@]}"
run_tlib mayhem/build/fuse-tests "${FUSE_TESTS[@]}"

emit_ctrf "tlib" "$passed" "$failed" 0
