// Encodes a grid of equally sized cells and decodes the file incrementally, the IO exposing a
// growing prefix (ports EncodeDecodeAvifFuzzTest.EncodeDecodeGridValid).
#include <algorithm>
#include <vector>

#include "common.h"

namespace {

struct Feed {
  const uint8_t* bytes;
  size_t total;
  size_t available;
};

avifResult FeedRead(avifIO* io, uint32_t read_flags, uint64_t offset,
                    size_t size, avifROData* out) {
  Feed* feed = reinterpret_cast<Feed*>(io->data);
  if (read_flags != 0 || feed == nullptr || feed->total < offset) {
    return AVIF_RESULT_IO_ERROR;
  }
  const size_t want = std::min(size, feed->total - static_cast<size_t>(offset));
  if (offset + want > feed->available) return AVIF_RESULT_WAITING_ON_IO;
  out->data = feed->bytes + offset;
  out->size = want;
  return AVIF_RESULT_OK;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Bytes in{data, size};
  avifEncoder* encoder = ReadEncoder(in);
  avifDecoder* decoder = ReadDecoder(in);
  const uint32_t cols = 1 + in.U8() % 3;
  const uint32_t rows = 1 + in.U8() % 3;
  const bool size_hint = in.U8() & 1;
  ImageSpec spec = ReadImageSpec(in, /*allow16=*/false);
  // Cells of a multi-cell grid must be at least 64x64 with even dimensions.
  if (cols > 1 || rows > 1) {
    spec.width = 64 + (spec.width & ~1u) % 34;
    spec.height = 64 + (spec.height & ~1u) % 34;
  }
  if (encoder == nullptr || decoder == nullptr || in.n == 0) {
    SafeDestroy(encoder);
    SafeDestroy(decoder);
    return -1;
  }

  std::vector<avifImage*> cells;
  for (uint32_t i = 0; i < cols * rows; ++i) {
    avifImage* cell = BuildImage(spec, in.d, in.n, i * 104729);
    INVARIANT(cell != nullptr);
    cells.push_back(cell);
  }
  avifRWData encoded = AVIF_DATA_EMPTY;
  const avifResult add = avifEncoderAddImageGrid(
      encoder, cols, rows, cells.data(), AVIF_ADD_IMAGE_FLAG_SINGLE);
  INVARIANT(add == AVIF_RESULT_OK);
  INVARIANT(avifEncoderFinish(encoder, &encoded) == AVIF_RESULT_OK);
  for (avifImage* cell : cells) SafeDestroy(cell);

  Feed feed = {encoded.data, encoded.size, 0};
  avifIO io = {};
  io.read = FeedRead;
  io.sizeHint = size_hint ? encoded.size : 0;
  io.persistent = AVIF_TRUE;
  io.data = &feed;
  avifDecoderSetIO(decoder, &io);
  decoder->allowIncremental = AVIF_TRUE;
  const size_t chunk = std::max<size_t>(1, encoded.size / 16);
  avifResult result;
  size_t rounds = 0;
  while ((result = avifDecoderParse(decoder)) == AVIF_RESULT_WAITING_ON_IO &&
         rounds++ < 64) {
    feed.available = std::min(feed.total, feed.available + chunk);
  }
  INVARIANT(result == AVIF_RESULT_OK);
  rounds = 0;
  while ((result = avifDecoderNextImage(decoder)) == AVIF_RESULT_WAITING_ON_IO &&
         rounds++ < 64) {
    feed.available = std::min(feed.total, feed.available + chunk);
  }
  INVARIANT(result == AVIF_RESULT_OK);
  INVARIANT(decoder->image->width == spec.width * cols);
  INVARIANT(decoder->image->height == spec.height * rows);
  INVARIANT(decoder->image->depth == spec.depth);
  INVARIANT(decoder->image->yuvFormat == spec.format);

  avifRWDataFree(&encoded);
  SafeDestroy(encoder);
  SafeDestroy(decoder);
  return 0;
}
