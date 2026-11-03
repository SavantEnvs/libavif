// Encodes an image built from the fuzz bytes with random encoder options, decodes it back and
// checks it round-trips structurally (ports EncodeDecodeAvifFuzzTest.EncodeDecodeValid).
#include "common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Bytes in{data, size};
  avifEncoder* encoder = ReadEncoder(in);
  avifDecoder* decoder = ReadDecoder(in);
  const ImageSpec spec = ReadImageSpec(in, /*allow16=*/false);
  avifImage* image = BuildImage(spec, in.d, in.n);
  if (encoder == nullptr || decoder == nullptr || image == nullptr) {
    SafeDestroy(encoder);
    SafeDestroy(decoder);
    SafeDestroy(image);
    return -1;
  }
  avifRWData encoded = AVIF_DATA_EMPTY;
  const avifResult enc = avifEncoderWrite(encoder, image, &encoded);
  INVARIANT(enc == AVIF_RESULT_OK);

  avifImage* decoded = avifImageCreateEmpty();
  const avifResult dec =
      avifDecoderReadMemory(decoder, decoded, encoded.data, encoded.size);
  INVARIANT(dec == AVIF_RESULT_OK);
  INVARIANT(decoded->width == image->width);
  INVARIANT(decoded->height == image->height);
  INVARIANT(decoded->depth == image->depth);
  INVARIANT(decoded->yuvFormat == image->yuvFormat);
  if (avifImageIsOpaque(image)) INVARIANT(avifImageIsOpaque(decoded));

  avifRWDataFree(&encoded);
  SafeDestroy(decoded);
  SafeDestroy(image);
  SafeDestroy(encoder);
  SafeDestroy(decoder);
  return 0;
}
