// YUV <-> RGB conversion over arbitrary images and options (ports YuvRgbFuzzTest.Convert).
#include "common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Bytes in{data, size};
  static const int kRgbDepth[] = {8, 10, 12, 16};
  static const avifChromaUpsampling kUp[] = {
      AVIF_CHROMA_UPSAMPLING_AUTOMATIC, AVIF_CHROMA_UPSAMPLING_FASTEST,
      AVIF_CHROMA_UPSAMPLING_BEST_QUALITY, AVIF_CHROMA_UPSAMPLING_NEAREST,
      AVIF_CHROMA_UPSAMPLING_BILINEAR};
  static const avifChromaDownsampling kDown[] = {
      AVIF_CHROMA_DOWNSAMPLING_AUTOMATIC, AVIF_CHROMA_DOWNSAMPLING_FASTEST,
      AVIF_CHROMA_DOWNSAMPLING_BEST_QUALITY, AVIF_CHROMA_DOWNSAMPLING_AVERAGE,
      AVIF_CHROMA_DOWNSAMPLING_SHARP_YUV};
  static const int kThreads[] = {-1, 0, 1, 2, 8};
  const int rgb_depth = in.Pick(kRgbDepth);
  const int rgb_format = in.U8() % AVIF_RGB_FORMAT_COUNT;
  const avifChromaUpsampling up = in.Pick(kUp);
  const avifChromaDownsampling down = in.Pick(kDown);
  const uint8_t flags = in.U8();
  const int max_threads = in.Pick(kThreads);
  const bool avoid_libyuv = flags & 1, ignore_alpha = flags & 2,
             premultiplied = flags & 4, is_float = flags & 8;
  const ImageSpec spec = ReadImageSpec(in, /*allow16=*/true);
  avifImage* image = BuildImage(spec, in.d, in.n);
  if (image == nullptr) return -1;

  avifRGBImage rgb;
  avifRGBImageSetDefaults(&rgb, image);
  rgb.depth = rgb_depth;
  rgb.format = (avifRGBFormat)rgb_format;
  rgb.chromaUpsampling = up;
  rgb.chromaDownsampling = down;
  rgb.avoidLibYUV = avoid_libyuv;
  rgb.ignoreAlpha = ignore_alpha;
  rgb.alphaPremultiplied = premultiplied;
  rgb.isFloat = is_float;
  rgb.maxThreads = max_threads;
  if (avifRGBImageAllocatePixels(&rgb) != AVIF_RESULT_OK) {
    SafeDestroy(image);
    return 0;
  }

  // Unsupported option combinations are rejected with an error code; only crashes matter here.
  (void)avifImageYUVToRGB(image, &rgb);
  (void)avifImageRGBToYUV(image, &rgb);
  avifRGBImageFreePixels(&rgb);
  SafeDestroy(image);
  return 0;
}
