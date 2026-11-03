// Encodes an animation of up to four frames and decodes it back, checking frame count, duration and
// per-frame properties (ports EncodeDecodeAvifFuzzTest.EncodeDecodeAnimation).
#include "common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Bytes in{data, size};
  avifEncoder* encoder = ReadEncoder(in);
  avifDecoder* decoder = ReadDecoder(in);
  const size_t num_frames = 1 + in.U8() % 4;
  uint8_t durations[4];
  avifAddImageFlags flags[4];
  for (size_t i = 0; i < 4; ++i) {
    durations[i] = 1 + in.U8() % 10;
    flags[i] = (in.U8() & 1) ? AVIF_ADD_IMAGE_FLAG_FORCE_KEYFRAME
                             : AVIF_ADD_IMAGE_FLAG_NONE;
  }
  const ImageSpec spec = ReadImageSpec(in, /*allow16=*/false);
  if (encoder == nullptr || decoder == nullptr || in.n == 0) {
    SafeDestroy(encoder);
    SafeDestroy(decoder);
    return -1;
  }
  encoder->timescale = 30;

  uint64_t total_duration = 0;
  for (size_t i = 0; i < num_frames; ++i) {
    avifImage* frame = BuildImage(spec, in.d, in.n, i * 7919);
    INVARIANT(frame != nullptr);
    total_duration += durations[i];
    const avifResult r =
        avifEncoderAddImage(encoder, frame, durations[i], flags[i]);
    SafeDestroy(frame);
    INVARIANT(r == AVIF_RESULT_OK);
  }
  avifRWData encoded = AVIF_DATA_EMPTY;
  INVARIANT(avifEncoderFinish(encoder, &encoded) == AVIF_RESULT_OK);

  INVARIANT(avifDecoderSetIOMemory(decoder, encoded.data, encoded.size) ==
            AVIF_RESULT_OK);
  INVARIANT(avifDecoderParse(decoder) == AVIF_RESULT_OK);
  if (num_frames == 1) {
    INVARIANT(decoder->imageCount == 1);
  } else {
    INVARIANT((size_t)decoder->imageCount == num_frames);
    INVARIANT(decoder->durationInTimescales == total_duration);
    for (size_t i = 0; i < num_frames; ++i) {
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
  return 0;
}
