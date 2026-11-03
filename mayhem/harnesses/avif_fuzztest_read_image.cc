// Reads an arbitrary byte sequence as a JPEG / PNG / Y4M image through the apps' avifReadImage()
// (ports ReadImageFuzzTest.ReadImageFile). avifReadImage() takes a path, so the input is staged
// in a scratch file under $TMPDIR.
#include <stdio.h>
#include <unistd.h>

#include <string>

#include "avifutil.h"
#include "common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Bytes in{data, size, /*from_back=*/true};
  static const avifPixelFormat kFormat[] = {
      AVIF_PIXEL_FORMAT_YUV444, AVIF_PIXEL_FORMAT_YUV422,
      AVIF_PIXEL_FORMAT_YUV420, AVIF_PIXEL_FORMAT_YUV400};
  static const int kDepth[] = {0, 8, 10, 12};
  static const avifChromaDownsampling kDown[] = {
      AVIF_CHROMA_DOWNSAMPLING_AUTOMATIC, AVIF_CHROMA_DOWNSAMPLING_FASTEST,
      AVIF_CHROMA_DOWNSAMPLING_BEST_QUALITY, AVIF_CHROMA_DOWNSAMPLING_AVERAGE,
      AVIF_CHROMA_DOWNSAMPLING_SHARP_YUV};
  static const avifMatrixCoefficients kMc[] = {
      AVIF_MATRIX_COEFFICIENTS_IDENTITY,   AVIF_MATRIX_COEFFICIENTS_BT709,
      AVIF_MATRIX_COEFFICIENTS_UNSPECIFIED, AVIF_MATRIX_COEFFICIENTS_FCC,
      AVIF_MATRIX_COEFFICIENTS_BT470BG,    AVIF_MATRIX_COEFFICIENTS_BT601,
      AVIF_MATRIX_COEFFICIENTS_SMPTE240,   AVIF_MATRIX_COEFFICIENTS_YCGCO,
      AVIF_MATRIX_COEFFICIENTS_BT2020_NCL, AVIF_MATRIX_COEFFICIENTS_BT2020_CL,
      AVIF_MATRIX_COEFFICIENTS_SMPTE2085,
      AVIF_MATRIX_COEFFICIENTS_CHROMA_DERIVED_NCL,
      AVIF_MATRIX_COEFFICIENTS_CHROMA_DERIVED_CL,
      AVIF_MATRIX_COEFFICIENTS_ICTCP};
  const avifPixelFormat requested_format = in.Pick(kFormat);
  const int requested_depth = in.Pick(kDepth);
  const avifChromaDownsampling downsampling = in.Pick(kDown);
  const uint8_t flags = in.U8();
  const avifMatrixCoefficients mc = in.Pick(kMc);
  if (in.n == 0) return -1;

  const char* tmpdir = getenv("TMPDIR");
  std::string path = std::string(tmpdir && *tmpdir ? tmpdir : "/tmp") + "/avif_read_image_XXXXXX";
  const int fd = mkstemp(&path[0]);
  if (fd < 0) return 0;
  FILE* f = fdopen(fd, "wb");
  if (f == nullptr) {
    close(fd);
    unlink(path.c_str());
    return 0;
  }
  fwrite(in.d, 1, in.n, f);
  fclose(f);

  avifImage* image = avifImageCreateEmpty();
  INVARIANT(image != nullptr);
  image->matrixCoefficients = mc;
  uint32_t out_depth;
  avifAppSourceTiming timing;
  constexpr uint32_t kImageSizeLimit = 2560u * 1024 * 1024 / 5 / 2 / 4;
  const uint32_t limit =
      (downsampling == AVIF_CHROMA_DOWNSAMPLING_SHARP_YUV &&
       requested_format == AVIF_PIXEL_FORMAT_YUV420)
          ? kImageSizeLimit / 8
          : kImageSizeLimit;
  const avifAppFileFormat format = avifReadImage(
      path.c_str(), AVIF_APP_FILE_FORMAT_UNKNOWN, requested_format,
      requested_depth, downsampling, /*ignoreColorProfile=*/flags & 1,
      /*ignoreExif=*/(flags >> 1) & 1, /*ignoreXMP=*/(flags >> 2) & 1,
      /*ignoreAlpha=*/AVIF_FALSE, /*ignoreGainMap=*/(flags >> 3) & 1, limit,
      image, &out_depth, &timing, /*frameIter=*/nullptr);
  unlink(path.c_str());

  int ret = -1;
  if (format != AVIF_APP_FILE_FORMAT_UNKNOWN) {
    ret = 0;
    INVARIANT(image->width > 0 && image->height > 0);
    if (requested_depth != 0 && format != AVIF_APP_FILE_FORMAT_Y4M) {
      INVARIANT((int)image->depth == requested_depth);
    }
    if (format != AVIF_APP_FILE_FORMAT_Y4M) {
      INVARIANT(image->yuvFormat == requested_format);
    }
    if (flags & 1) INVARIANT(image->icc.size == 0);
    if (flags & 2) INVARIANT(image->exif.size == 0);
    if (flags & 4) INVARIANT(image->xmp.size == 0);
  }
  SafeDestroy(image);
  return ret;
}
