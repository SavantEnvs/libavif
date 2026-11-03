#!/usr/bin/env bash
#
# mayhem/build.sh — build libavif's fuzz harnesses (sanitized) and its unit-test suite (normal flags).
# Runs inside the commit image as `mayhem` in /mayhem; re-runnable and offline: every dependency is
# an apt -dev package baked into the image.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
# Edge coverage for the fuzzed code (library + harness); the libFuzzer runtime only comes in at link time.
FUZZ_COV="-fsanitize=fuzzer-no-link"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

CODECS=(-DAVIF_CODEC_AOM=SYSTEM -DAVIF_CODEC_AOM_DECODE=ON -DAVIF_CODEC_AOM_ENCODE=ON
        -DAVIF_CODEC_DAV1D=SYSTEM -DAVIF_LIBYUV=SYSTEM -DAVIF_LIBSHARPYUV=SYSTEM
        -DAVIF_JPEG=SYSTEM -DAVIF_ZLIBPNG=SYSTEM -DAVIF_LIBXML2=SYSTEM)

# 1) The test suite first, with the project's NORMAL flags, in its own (gitignored) build tree.
TESTS=(avifbasictest avifdecodetest avifencodetest avifrgbtest avifrgbtoyuvtest avifcolrtest
       avifclaptest avifutilstest avifstreamtest avifpropinternaltest avifimagetest avifgridapitest
       avifincrtest avifreadimagetest avifanimationtest avif16bittest avifmetadatatest aviftilingtest
       avifopaquetest avifpixitest avifalphapremtest avifcicptest avifchangesettingtest)
cmake -S . -B build-tests -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
      -DBUILD_SHARED_LIBS=OFF "${CODECS[@]}" -DAVIF_BUILD_TESTS=ON -DAVIF_GTEST=SYSTEM
cmake --build build-tests --parallel "$MAYHEM_JOBS" --target "${TESTS[@]}"

# 2) The project itself (static libavif) with the sanitizers and DWARF <= 3.
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $FUZZ_COV $DEBUG_FLAGS" -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $FUZZ_COV $DEBUG_FLAGS" \
      -DBUILD_SHARED_LIBS=OFF "${CODECS[@]}"
cmake --build build --parallel "$MAYHEM_JOBS" --target avif

# 3) The apps' shared image readers (JPEG/PNG/Y4M), which the read_image harness fuzzes.
OBJ=build/mayhem-obj
mkdir -p "$OBJ"
XML_CFLAGS=$(pkg-config --cflags libxml-2.0)
for src in apps/shared/avifexif.c apps/shared/avifjpeg.c apps/shared/avifpng.c apps/shared/avifutil.c \
           apps/shared/iccmaker.c apps/shared/y4m.c third_party/iccjpeg/iccjpeg.c; do
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $FUZZ_COV $DEBUG_FLAGS -O2 -DAVIF_ENABLE_JPEG_GAIN_MAP_CONVERSION $XML_CFLAGS \
      -Iinclude -Iapps/shared -Ithird_party/iccjpeg -c "$src" -o "$OBJ/app_$(basename "$src" .c).o"
done

# 4) Harnesses: each linked once with libFuzzer and once with the run-once standalone driver.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OBJ/lsan_off.o"
LIBS=(build/libavif_internal.a $(pkg-config --libs dav1d aom libsharpyuv libxml-2.0) -lyuv -ljpeg -lpng -lz -lm -lpthread)
TARGETS=(avif_fuzztest_dec avif_fuzztest_dec_incr avif_fuzztest_read_image avif_fuzztest_yuvrgb
         avif_fuzztest_enc_dec avif_fuzztest_enc_dec_anim avif_fuzztest_enc_dec_incr
         avif_fuzztest_enc_dec_layered avif_fuzztest_properties)
for t in "${TARGETS[@]}"; do
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $FUZZ_COV $DEBUG_FLAGS -O1 -std=c++17 -Iinclude -Iapps/shared -Imayhem/harnesses \
      -c "mayhem/harnesses/$t.cc" -o "$OBJ/$t.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/$t.o" "$OBJ"/app_*.o "$OBJ/lsan_off.o" "${LIBS[@]}" -o "/mayhem/$t"
  $CXX $SANITIZER_FLAGS $FUZZ_COV $DEBUG_FLAGS "$OBJ/$t.o" "$OBJ"/app_*.o "$OBJ/standalone_main.o" "$OBJ/lsan_off.o" "${LIBS[@]}" \
      -o "/mayhem/$t-standalone"
done
