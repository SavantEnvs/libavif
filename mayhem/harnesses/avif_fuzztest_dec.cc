// Parses and decodes an arbitrary byte sequence as an AVIF file (ports ParseAvifTest.Parse and
// DecodeAvifTest.Decode from tests/gtest/avif_fuzztest_dec.cc).
#include <algorithm>

#include "common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Bytes in{data, size, /*from_back=*/true};
  const uint8_t flags = in.U8();
  const bool persistent = flags & 1;
  const bool parse_only = flags & 2;
  avifDecoder* decoder = ReadDecoder(in);
  if (decoder == nullptr) return 0;
  decoder->imageContentToDecode =
      (flags & 4) ? AVIF_IMAGE_CONTENT_ALL : AVIF_IMAGE_CONTENT_DECODE_DEFAULT;
  if (flags & 8) decoder->imageContentToDecode = AVIF_IMAGE_CONTENT_NONE;
  decoder->imageCountLimit = 0;

  avifIO* io = avifIOCreateMemoryReader(in.d, in.n);
  if (io == nullptr) {
    SafeDestroy(decoder);
    return 0;
  }
  io->persistent = persistent;
  avifDecoderSetIO(decoder, io);
  if (parse_only) {
    // Parsing only: huge dimensions are fine because nothing is allocated for them.
    decoder->imageSizeLimit = AVIF_DEFAULT_IMAGE_SIZE_LIMIT;
    decoder->imageDimensionLimit = UINT32_MAX;
  } else {
    decoder->imageSizeLimit = 4096 * 4096;
  }

  avifResult result = avifDecoderParse(decoder);
  INVARIANT(result != AVIF_RESULT_INTERNAL_ERROR);
  int ret = -1;
  if (result == AVIF_RESULT_OK) {
    ret = 0;
    for (size_t i = 0; i < decoder->image->numProperties; ++i) {
      const avifRWData& box = decoder->image->properties[i].boxPayload;
      // Each custom property must be found as is in the input bitstream.
      INVARIANT(std::search(in.d, in.d + in.n, box.data, box.data + box.size) !=
                in.d + in.n);
    }
    if (!parse_only) {
      while ((result = avifDecoderNextImage(decoder)) == AVIF_RESULT_OK) {
        INVARIANT(decoder->image->width > 0 && decoder->image->height > 0);
      }
      INVARIANT(result != AVIF_RESULT_INTERNAL_ERROR);
      // Loop once more.
      result = avifDecoderReset(decoder);
      INVARIANT(result != AVIF_RESULT_INTERNAL_ERROR);
      if (result == AVIF_RESULT_OK) {
        while ((result = avifDecoderNextImage(decoder)) == AVIF_RESULT_OK) {
        }
        INVARIANT(result != AVIF_RESULT_INTERNAL_ERROR);
      }
    }
  }
  SafeDestroy(decoder);
  return ret;
}
