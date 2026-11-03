// Encodes a four-layer (spatially scalable) image with random per-layer scaling modes and decodes
// it progressively (ports LayeredEncodeDecodeAvifFuzzTest.EncodeDecodeDimensionChange).
#include <algorithm>

#include "common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Bytes in{data, size};
  static const avifFraction kScales[] = {{1, 8}, {1, 4}, {1, 2},
                                         {3, 5}, {3, 4}, {4, 5}};
  avifEncoder* encoder = ReadEncoder(in);
  avifDecoder* decoder = ReadDecoder(in);
  avifScalingMode modes[4];
  for (int i = 0; i < 3; ++i) {
    modes[i].horizontal = in.Pick(kScales);
    modes[i].vertical = in.Pick(kScales);
  }
  modes[3].horizontal = modes[3].vertical = avifFraction{1, 1};
  ImageSpec spec = ReadImageSpec(in, /*allow16=*/false);
  // Keep every scaled layer at least a few pixels wide; scaling needs even dimensions for 4:2:0.
  spec.width = std::max<uint32_t>(16, spec.width) & ~1u;
  spec.height = std::max<uint32_t>(16, spec.height) & ~1u;
  if (encoder == nullptr || decoder == nullptr || in.n == 0) {
    SafeDestroy(encoder);
    SafeDestroy(decoder);
    return -1;
  }
  encoder->codecChoice = AVIF_CODEC_CHOICE_AOM;
  encoder->extraLayerCount = 3;

  int ret = 0;
  avifRWData encoded = AVIF_DATA_EMPTY;
  bool encode_ok = true;
  for (int i = 0; i < 4 && encode_ok; ++i) {
    avifImage* layer = BuildImage(spec, in.d, in.n, i * 7919);
    INVARIANT(layer != nullptr);
    encoder->scalingMode = modes[i];
    encode_ok = avifEncoderAddImage(encoder, layer, 1, AVIF_ADD_IMAGE_FLAG_NONE) ==
                AVIF_RESULT_OK;
    SafeDestroy(layer);
  }
  if (encode_ok) encode_ok = avifEncoderFinish(encoder, &encoded) == AVIF_RESULT_OK;
  if (!encode_ok) {
    ret = -1;
  } else {
    INVARIANT(avifDecoderSetIOMemory(decoder, encoded.data, encoded.size) ==
              AVIF_RESULT_OK);
    INVARIANT(avifDecoderParse(decoder) == AVIF_RESULT_OK);
    const int num_decodes = decoder->allowProgressive ? 4 : 1;
    INVARIANT(decoder->imageCount == num_decodes);
    for (int i = 0; i < num_decodes; ++i) {
      INVARIANT(avifDecoderNextImage(decoder) == AVIF_RESULT_OK);
      INVARIANT(decoder->image->width == spec.width);
      INVARIANT(decoder->image->height == spec.height);
      INVARIANT(decoder->image->depth == spec.depth);
      INVARIANT(decoder->image->yuvFormat == spec.format);
    }
    INVARIANT(avifDecoderNextImage(decoder) == AVIF_RESULT_NO_IMAGES_REMAINING);
  }
  avifRWDataFree(&encoded);
  SafeDestroy(encoder);
  SafeDestroy(decoder);
  return ret;
}
