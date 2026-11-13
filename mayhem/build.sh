#!/usr/bin/env bash
#
# mayhem/build.sh — build the comdb2 fuzz harnesses (csc2 / cson / comdb2rle / decNumber), their
# standalone reproducers, and the clean (unsanitized) test binaries mayhem/test.sh runs.
#
# comdb2 is a database server; the targets are its self-contained parsing/codec libraries, built from the
# project's own CMake tree. Runs inside the commit image as `mayhem` in /mayhem.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Relaxed UBSan checks, all benign on every input (see the PR notes): `function` (lemon's actioncmp is
# called through a differently-typed pointer), `array-bounds` (csc2/maccwrite2.c:84 reads un_start[-1]
# on a sentinel), `alignment` (comdb2rle.c:251 loads a packed header through an aligned type).
RELAX="-fno-sanitize=function,array-bounds,alignment"
LIBS_TARGETS="csc2 util mem dlmalloc comdb2rle cson dfpal"

# COMDB2_PER_THREAD_MALLOC=OFF is upstream's own valgrind/sanitizer switch: it routes comdb2_malloc to
# the system allocator so ASan sees the allocations.
# CMake takes the compiler from the exported $CC/$CXX; extra args (the fuzz tree's) follow.
configure_and_build() {
    local dir="$1" flags="$2"
    shift 2
    cmake -S . -B "$dir" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_FLAGS="$flags" -DCMAKE_CXX_FLAGS="$flags" \
        -DCOMDB2_PER_THREAD_MALLOC=OFF -DCOMDB2_TEST=OFF "$@" >"$dir.cmake.log" 2>&1 \
        || { tail -30 "$dir.cmake.log"; exit 1; }
    # shellcheck disable=SC2086
    ninja -C "$dir" -j"$MAYHEM_JOBS" $LIBS_TARGETS
}

DEFS="-DCDB2API_SERVER -DUSE_SYS_ALLOC -D_GNU_SOURCE -D_LINUX_SOURCE -D_FILE_OFFSET_BITS=64"
inc_flags() {
    local b="$1"
    echo "-I $SRC/csc2 -I $SRC/bbinc -I $b/bbinc -I $SRC/util -I $SRC/db -I $SRC/mem -I $SRC/cdb2api" \
         "-I $SRC/dfp/dfpal -I $SRC/dfp/decNumber -I $SRC/sqlite/src -I $SRC/datetime -I $b/datetime" \
         "-I $SRC/cson -I $SRC/comdb2rle"
}

# 1) The project (csc2, cson, comdb2rle, decNumber and their support libs) with the sanitizers + SanCov
#    (-fsanitize=fuzzer-no-link) so the fuzzed code is instrumented.
FB="$SRC/build-fuzz"
FFLAGS="$SANITIZER_FLAGS $RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
# RelWithDebInfo's default per-type flags carry -DNDEBUG; drop it here so upstream's assert()s stay live
# in the fuzzed code (the test tree below keeps upstream's normal flags).
configure_and_build "$FB" "$FFLAGS" \
    -DCMAKE_C_FLAGS_RELWITHDEBINFO="-O2 -g" -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O2 -g"

# 2) Each harness twice: against libFuzzer and against the standalone run-once driver.
OBJ="$FB/mayhem-obj"
mkdir -p "$OBJ"
# shellcheck disable=SC2086
HFLAGS="$SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -O2 $DEFS $(inc_flags "$FB")"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -x c++ -o "$OBJ/lsan_off.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
# shellcheck disable=SC2086
$CC $HFLAGS -c "$SRC/mayhem/csc2_db_stubs.c" -o "$OBJ/csc2_db_stubs.o"

# Without ASan nothing provides the SanCov callbacks the instrumented library calls; take them from
# libFuzzer's main-less runtime.
case "$SANITIZER_FLAGS" in
*address*) COVRT="" ;;
*) COVRT="$($CC -print-file-name=libclang_rt.fuzzer_no_main-"$(uname -m)".a) -lstdc++" ;;
esac

CSC2_LIBS="-Wl,--start-group $FB/csc2/libcsc2.a $FB/util/libutil.a $FB/mem/libmem.a $FB/dlmalloc/libdlmalloc.a -Wl,--end-group -lunwind -lpthread -lm"
declare -A EXTRA_OBJ LIBS
EXTRA_OBJ[fuzz_csc2]="$OBJ/csc2_db_stubs.o"
LIBS[fuzz_csc2]="$CSC2_LIBS"
EXTRA_OBJ[fuzz_cson]=""
LIBS[fuzz_cson]="$FB/cson/libcson.a -lpthread -lm"
EXTRA_OBJ[fuzz_comdb2rle]=""
LIBS[fuzz_comdb2rle]="$FB/comdb2rle/libcomdb2rle.a -lm"
EXTRA_OBJ[fuzz_decquad]=""
LIBS[fuzz_decquad]="$FB/dfp/libdfpal.a -lm"

for t in fuzz_csc2 fuzz_cson fuzz_comdb2rle fuzz_decquad; do
    # shellcheck disable=SC2086
    $CC $HFLAGS $LIB_FUZZING_ENGINE "$SRC/mayhem/$t.c" ${EXTRA_OBJ[$t]} "$OBJ/lsan_off.o" ${LIBS[$t]} -o "$SRC/$t"
    # shellcheck disable=SC2086
    $CC $HFLAGS "$OBJ/standalone_main.o" "$SRC/mayhem/$t.c" ${EXTRA_OBJ[$t]} "$OBJ/lsan_off.o" ${LIBS[$t]} $COVRT -o "$SRC/$t-standalone"
done

# 3) The test binaries, from a separate build with the project's normal flags (no sanitizers, no DWARF
#    override): the upstream unit tests tests/tools/{crle,cson_test}.c and our known-answer probe.
TB="$SRC/build-tests"
configure_and_build "$TB" "$COVERAGE_FLAGS"
TOBJ="$TB/mayhem-obj"
mkdir -p "$TOBJ" "$TB/bin"
# shellcheck disable=SC2086
TFLAGS="-O2 $COVERAGE_FLAGS $DEFS $(inc_flags "$TB")"
# shellcheck disable=SC2086
$CC $TFLAGS -c "$SRC/mayhem/csc2_db_stubs.c" -o "$TOBJ/csc2_db_stubs.o"
# shellcheck disable=SC2086
$CC $TFLAGS "$SRC/tests/tools/crle.c" -o "$TB/bin/crle"
# shellcheck disable=SC2086
$CC $TFLAGS "$SRC/tests/tools/cson_test.c" "$TB/cson/libcson.a" -lpthread -lm -o "$TB/bin/cson_test"
# shellcheck disable=SC2086
$CC $TFLAGS "$SRC/mayhem/kat.c" "$TOBJ/csc2_db_stubs.o" \
    "$TB/cson/libcson.a" "$TB/comdb2rle/libcomdb2rle.a" "$TB/dfp/libdfpal.a" \
    -Wl,--start-group "$TB/csc2/libcsc2.a" "$TB/util/libutil.a" "$TB/mem/libmem.a" "$TB/dlmalloc/libdlmalloc.a" -Wl,--end-group \
    -lunwind -lpthread -lm -o "$TB/bin/kat"
