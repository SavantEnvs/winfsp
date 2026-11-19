#!/usr/bin/env bash
#
# mayhem/build.sh -- build WinFsp's fuzz harnesses and its Linux-runnable unit tests.
#
# WinFsp only builds with Visual Studio + the WDK (build/VStudio/winfsp.sln); there is no POSIX
# build. The parsers worth fuzzing live in a few user-mode DLL sources that are almost plain C, so
# this compiles those upstream files UNMODIFIED with clang on Linux, against a minimal stand-in for
# the Windows SDK headers (mayhem/shim/include) and a handful of Win32 functions (mayhem/shim):
#   src/dll/fuse/fuse_opt.c   FUSE argv / -o option parser
#   src/dll/fsop.c            reparse point resolution, EA lists, dir info packing
#   src/dll/dirbuf.c          directory buffers
#   src/dll/path.c            path prefix/suffix
#   src/shared/ku/posix.c     POSIX <-> Windows path mapping
# -fshort-wchar gives WCHAR its Windows width (16 bits); LONG/ULONG/DWORD are 32-bit (LLP64).
#
# Outputs: /mayhem/fuzz_<name> (libFuzzer) and /mayhem/fuzz_<name>-standalone (run-once
# reproducer) for each mayhem/harnesses/fuzz_<name>.c, and mayhem/build/{winfsp,fuse}-tests,
# which run upstream's own tst/winfsp-tests suites for that code (mayhem/test.sh).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Windows-on-Linux compile flags shared by every object.
WINFLAGS=(-fms-extensions -fdeclspec -fshort-wchar -DNDEBUG -D__CYGWIN__
          -Imayhem/shim/include -Iinc -Isrc -Iext)
# Two Windows data models. The DLL ships for x64 (LLP64) and x86 (ILP32); Linux x86_64 is LP64,
# so `long` is 8 bytes here but 4 on Windows. The shim types (LONG, ULONG, DWORD) are 32-bit either
# way, which is all fsop.c, dirbuf.c, path.c and posix.c use, so they build as x64. fuse_opt.c uses
# C `long` itself (`-1L == opt->offset` recognizes FUSE_OPT_KEY entries; the "%l" conversions), so
# on LP64 it would mis-parse every FUSE_OPT_KEY; it builds as x86 (-m32, ILP32), where `long` has
# its Windows width and the code runs exactly as in the x86 DLL.
X64=(-D_AMD64_ -D_M_X64)
# -malign-double: MSVC x86 aligns 64-bit struct members to 8 (i386 Linux: 4); fsctl.h asserts it.
X86=(-m32 -malign-double -D_X86_ -D_M_IX86)
# The upstream sources are MSVC code: silence clang's warnings about MSVC-isms (pragmas, declspec)
# rather than drown the build log. MSVC also accepts passing a prototyped function where winfsp.h
# declares an unprototyped `NTSTATUS (*CreateFunc)()` (FspDeleteSecurityDescriptor), which clang
# rejects by default; and the Windows SDK headers declare the CRT (memcpy, malloc) and MSVC
# intrinsics (_BitScanReverse) that the shim cannot (minimal.h defines its own static memcpy), so
# those calls are implicit declarations of clang LIBRARY BUILTINS, which keep their builtin
# signatures. Both diagnostics are downgraded; every non-builtin function the sources call is
# declared in mayhem/shim/include/windows.h. Code generation is unaffected.
QUIET=(-w -Wno-error=incompatible-function-pointer-types -Wno-error=implicit-function-declaration)
HFLAGS=(-Wno-ignored-attributes)

WINFSP_SRCS=(src/dll/fsop.c src/dll/dirbuf.c src/dll/path.c src/shared/ku/posix.c)
FUSE_SRCS=(src/dll/fuse/fuse_opt.c)
SHIM=(mayhem/shim/win32.c mayhem/shim/unreachable.c)

# build_lib <out.a> <compile flags...> -- <sources...>
build_lib() {
  local lib="$1"; shift
  local flags=() objs=() f o
  while [ "$1" != "--" ]; do flags+=("$1"); shift; done; shift
  local dir="${lib%.a}.objs"
  rm -rf "$dir" "$lib"; mkdir -p "$dir"
  for f in "$@"; do
    o="$dir/$(echo "$f" | tr '/' '_').o"
    $CC "${WINFLAGS[@]}" "${QUIET[@]}" "${flags[@]}" -c "$f" -o "$o" &
    objs+=("$o")
  done
  wait
  for o in "${objs[@]}"; do [ -f "$o" ] || { echo "build.sh: failed to compile $o" >&2; exit 1; }; done
  ar rcs "$lib" "${objs[@]}"
}

B=mayhem/build
rm -rf "$B"; mkdir -p "$B"

# 1) The project, instrumented: sanitizers + DWARF 3, plus SanitizerCoverage for the libFuzzer
#    builds (fuzzer-no-link) so the fuzzer sees edges inside WinFsp, not only in the harness.
#    The standalone reproducers link a copy without coverage instrumentation (no libFuzzer runtime).
#    UBSan's pointer-overflow check is relaxed for the WinFsp objects only: the DLL routinely forms
#    `NULL + 0` (an empty argv in fuse_opt.c fsp_fuse_opt_insert_arg, an empty directory buffer in
#    dirbuf.c FspFileSystemReleaseDirectoryBuffer/ReadDirectoryBuffer), which the check reports on
#    the first input, every run. ASan and every other UBSan check stay on and halting.
RELAX=(-fno-sanitize=pointer-overflow)
for arch in x64 x86; do
  if [ $arch = x64 ]; then A=("${X64[@]}"); S=("${WINFSP_SRCS[@]}"); else A=("${X86[@]}"); S=("${FUSE_SRCS[@]}"); fi
  build_lib "$B/fuzz-$arch.a" "${A[@]}" -O1 $SANITIZER_FLAGS "${RELAX[@]}" $DEBUG_FLAGS -fsanitize=fuzzer-no-link \
      -- "${S[@]}" "${SHIM[@]}"
  build_lib "$B/standalone-$arch.a" "${A[@]}" -O1 $SANITIZER_FLAGS "${RELAX[@]}" $DEBUG_FLAGS \
      -- "${S[@]}" "${SHIM[@]}" "$STANDALONE_FUZZ_MAIN"
  build_lib "$B/lsan_off-$arch.a" "${A[@]}" $SANITIZER_FLAGS $DEBUG_FLAGS -- mayhem/lsan_off.c
done

# 2) Harnesses: libFuzzer binary + standalone reproducer each, built for the data model of the
#    code they call (fuzz_fuse_opt: x86; the rest: x64).
for h in mayhem/harnesses/fuzz_*.c; do
  name=$(basename "$h" .c)
  if [ "$name" = fuzz_fuse_opt ]; then arch=x86; A=("${X86[@]}"); else arch=x64; A=("${X64[@]}"); fi
  $CC "${WINFLAGS[@]}" "${HFLAGS[@]}" "${A[@]}" -O1 $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
      "$h" -Wl,--whole-archive "$B/lsan_off-$arch.a" -Wl,--no-whole-archive \
      "$B/fuzz-$arch.a" -o "$SRC/$name"
  # the run-once driver's main() comes from the archive, so pull it in explicitly
  $CC "${WINFLAGS[@]}" "${HFLAGS[@]}" "${A[@]}" -O1 $SANITIZER_FLAGS $DEBUG_FLAGS \
      "$h" -Wl,--whole-archive "$B/lsan_off-$arch.a" -Wl,--no-whole-archive \
      "$B/standalone-$arch.objs/$(echo "$STANDALONE_FUZZ_MAIN" | tr '/' '_').o" \
      "$B/standalone-$arch.a" -o "$SRC/$name-standalone"
done

# 3) Upstream's own unit tests for this code (tst/winfsp-tests + ext/tlib), with NORMAL flags (no
#    sanitizers): tst/winfsp-tests/{path,dirbuf,posix}-test.c (x64) and fuse-opt-test.c (x86).
build_lib "$B/test-x64.a" "${X64[@]}" -O2 $COVERAGE_FLAGS -- "${WINFSP_SRCS[@]}" "${SHIM[@]}"
build_lib "$B/test-x86.a" "${X86[@]}" -O2 $COVERAGE_FLAGS -- "${FUSE_SRCS[@]}" "${SHIM[@]}"
$CC "${WINFLAGS[@]}" "${QUIET[@]}" "${X64[@]}" -O2 $COVERAGE_FLAGS -DSUITES_WINFSP \
    mayhem/tests/winfsp_tests_main.c ext/tlib/testsuite.c \
    tst/winfsp-tests/path-test.c tst/winfsp-tests/dirbuf-test.c tst/winfsp-tests/posix-test.c \
    "$B/test-x64.a" -o "$B/winfsp-tests"
$CC "${WINFLAGS[@]}" "${QUIET[@]}" "${X86[@]}" -O2 $COVERAGE_FLAGS -DSUITES_FUSE \
    mayhem/tests/winfsp_tests_main.c ext/tlib/testsuite.c \
    tst/winfsp-tests/fuse-opt-test.c \
    "$B/test-x86.a" -o "$B/fuse-tests"

echo "build.sh: done"
ls -l "$SRC"/fuzz_* "$B/winfsp-tests" "$B/fuse-tests"
