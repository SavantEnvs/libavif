// Shared helpers for the libavif libFuzzer harnesses: carve parameters off the front of the fuzz
// input, build a small valid image from the rest of the bytes, configure an encoder / decoder.
#ifndef MAYHEM_HARNESS_COMMON_H
#define MAYHEM_HARNESS_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "avif/avif.h"

struct Bytes {
  const uint8_t* d;
  size_t n;
  // Parameters are read off the end instead of the front, so the remaining bytes stay a valid file.
  bool from_back = false;
  uint8_t U8() {
    if (n == 0) return 0;
    --n;
    return from_back ? d[n] : *d++;
  }
  uint32_t U16() {
    uint32_t hi = U8();
    return (hi << 8) | U8();
  }
  template <typename T, size_t N>
  T Pick(const T (&a)[N]) {
    return a[U8() % N];
  }
};

// A broken libavif invariant: crash so the fuzzer records it.
#define INVARIANT(cond)  \
  do {                   \
    if (!(cond)) abort(); \
  } while (0)

// libavif's destroy functions do not accept NULL.
inline void SafeDestroy(avifImage* p) { if (p) avifImageDestroy(p); }
inline void SafeDestroy(avifEncoder* p) { if (p) avifEncoderDestroy(p); }
inline void SafeDestroy(avifDecoder* p) { if (p) avifDecoderDestroy(p); }

struct ImageSpec {
  uint32_t width, height;
  uint32_t depth;
  avifPixelFormat format;
  avifRange range;
  bool alpha;
  avifColorPrimaries cp;
  avifTransferCharacteristics tc;
  avifMatrixCoefficients mc;
};

inline ImageSpec ReadImageSpec(Bytes& in, bool allow16) {
  static const uint32_t kDepth[] = {8, 10, 12, 16};
  static const avifPixelFormat kFormat[] = {
      AVIF_PIXEL_FORMAT_YUV444, AVIF_PIXEL_FORMAT_YUV422,
      AVIF_PIXEL_FORMAT_YUV420, AVIF_PIXEL_FORMAT_YUV400};
  static const avifColorPrimaries kCp[] = {
      AVIF_COLOR_PRIMARIES_BT709, AVIF_COLOR_PRIMARIES_UNSPECIFIED,
      AVIF_COLOR_PRIMARIES_BT2020, AVIF_COLOR_PRIMARIES_SMPTE432};
  static const avifTransferCharacteristics kTc[] = {
      AVIF_TRANSFER_CHARACTERISTICS_SRGB, AVIF_TRANSFER_CHARACTERISTICS_PQ,
      AVIF_TRANSFER_CHARACTERISTICS_UNSPECIFIED,
      AVIF_TRANSFER_CHARACTERISTICS_HLG};
  static const avifMatrixCoefficients kMc[] = {
      AVIF_MATRIX_COEFFICIENTS_BT601, AVIF_MATRIX_COEFFICIENTS_BT709,
      AVIF_MATRIX_COEFFICIENTS_BT2020_NCL, AVIF_MATRIX_COEFFICIENTS_YCGCO,
      AVIF_MATRIX_COEFFICIENTS_IDENTITY};
  ImageSpec s;
  s.width = 1 + in.U16() % 96;
  s.height = 1 + in.U16() % 96;
  s.depth = kDepth[in.U8() % (allow16 ? 4 : 3)];
  s.format = in.Pick(kFormat);
  s.range = (in.U8() & 1) ? AVIF_RANGE_FULL : AVIF_RANGE_LIMITED;
  s.alpha = (in.U8() & 1) != 0;
  s.cp = in.Pick(kCp);
  s.tc = in.Pick(kTc);
  s.mc = in.Pick(kMc);
  // Identity matrix coefficients are only valid with 4:4:4 (or monochrome-less) content.
  if (s.mc == AVIF_MATRIX_COEFFICIENTS_IDENTITY &&
      s.format != AVIF_PIXEL_FORMAT_YUV444) {
    s.mc = AVIF_MATRIX_COEFFICIENTS_BT601;
  }
  return s;
}

// Builds an image whose samples are taken, cyclically, from `payload` starting at `offset`.
// Returns nullptr when there is no payload to draw samples from.
inline avifImage* BuildImage(const ImageSpec& s, const uint8_t* payload,
                             size_t payload_size, size_t offset = 0) {
  if (payload_size == 0) return nullptr;
  avifImage* image = avifImageCreate(s.width, s.height, s.depth, s.format);
  if (image == nullptr) return nullptr;
  image->yuvRange = s.range;
  image->colorPrimaries = s.cp;
  image->transferCharacteristics = s.tc;
  image->matrixCoefficients = s.mc;
  const avifPlanesFlags planes =
      s.alpha ? AVIF_PLANES_ALL : AVIF_PLANES_YUV;
  if (avifImageAllocatePlanes(image, planes) != AVIF_RESULT_OK) {
    avifImageDestroy(image);
    return nullptr;
  }
  size_t pos = offset;
  const uint32_t mask = (1u << s.depth) - 1;
  const bool u16 = avifImageUsesU16(image);
  avifPixelFormatInfo info;
  avifGetPixelFormatInfo(s.format, &info);
  for (int plane = 0; plane < 4; ++plane) {
    uint8_t* base = plane == 3 ? image->alphaPlane : image->yuvPlanes[plane];
    if (base == nullptr) continue;
    const uint32_t rowBytes =
        plane == 3 ? image->alphaRowBytes : image->yuvRowBytes[plane];
    uint32_t w = s.width, h = s.height;
    if (plane == 1 || plane == 2) {
      w = (w + info.chromaShiftX) >> info.chromaShiftX;
      h = (h + info.chromaShiftY) >> info.chromaShiftY;
    }
    for (uint32_t y = 0; y < h; ++y) {
      uint8_t* row = base + (size_t)y * rowBytes;
      for (uint32_t x = 0; x < w; ++x) {
        uint32_t v = payload[pos++ % payload_size];
        if (u16) v |= (uint32_t)payload[pos++ % payload_size] << 8;
        v &= mask;
        if (u16) {
          ((uint16_t*)row)[x] = (uint16_t)v;
        } else {
          row[x] = (uint8_t)v;
        }
      }
    }
  }
  return image;
}

inline avifEncoder* ReadEncoder(Bytes& in) {
  avifEncoder* e = avifEncoderCreate();
  if (e == nullptr) return nullptr;
  e->codecChoice = AVIF_CODEC_CHOICE_AOM;
  e->maxThreads = 1;
  e->speed = 6 + in.U8() % 5;
  e->quality = in.U8() % 101;
  e->qualityAlpha = in.U8() % 101;
  e->tileRowsLog2 = in.U8() % 2;
  e->tileColsLog2 = in.U8() % 2;
  return e;
}

inline avifDecoder* ReadDecoder(Bytes& in) {
  avifDecoder* d = avifDecoderCreate();
  if (d == nullptr) return nullptr;
  d->codecChoice = AVIF_CODEC_CHOICE_DAV1D;
  d->maxThreads = 1;
  const uint8_t flags = in.U8();
  d->strictFlags = (flags & 1) ? AVIF_STRICT_ENABLED : AVIF_STRICT_DISABLED;
  d->allowProgressive = (flags & 2) != 0;
  d->allowIncremental = (flags & 4) != 0;
  d->ignoreExif = (flags & 8) != 0;
  d->ignoreXMP = (flags & 16) != 0;
  return d;
}

#endif  // MAYHEM_HARNESS_COMMON_H
