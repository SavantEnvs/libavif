// Decodes an arbitrary byte sequence incrementally: the IO only exposes a growing prefix of the
// file and answers AVIF_RESULT_WAITING_ON_IO for the rest (ports DecodeAvifFuzzTest.DecodeIncr).
#include <algorithm>

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
  Bytes in{data, size, /*from_back=*/true};
  const uint8_t flags = in.U8();
  avifDecoder* decoder = ReadDecoder(in);
  if (decoder == nullptr) return 0;
  decoder->imageContentToDecode =
      (flags & 1) ? AVIF_IMAGE_CONTENT_ALL : AVIF_IMAGE_CONTENT_DECODE_DEFAULT;
  decoder->allowIncremental = AVIF_TRUE;
  decoder->imageSizeLimit = 2048 * 2048;
  const bool use_nth = flags & 2;

  Feed feed = {in.d, in.n, 0};
  avifIO io = {};
  io.read = FeedRead;
  io.sizeHint = (flags & 4) ? in.n : 0;
  io.persistent = AVIF_TRUE;
  io.data = &feed;
  avifDecoderSetIO(decoder, &io);

  // Reveal the file in 1 + (flags>>4) chunks per round.
  const size_t chunk = std::max<size_t>(1, in.n / (1 + (flags >> 4)));
  int ret = -1;
  avifResult result;
  size_t rounds = 0;
  while ((result = avifDecoderParse(decoder)) == AVIF_RESULT_WAITING_ON_IO &&
         feed.available < feed.total && rounds++ < 64) {
    feed.available = std::min(feed.total, feed.available + chunk);
  }
  INVARIANT(result != AVIF_RESULT_INTERNAL_ERROR);
  if (result == AVIF_RESULT_OK) {
    ret = 0;
    uint32_t decoded = 0;
    rounds = 0;
    for (;;) {
      if (use_nth) {
        result = avifDecoderNthImage(decoder, decoded);
      } else {
        result = avifDecoderNextImage(decoder);
      }
      if (result == AVIF_RESULT_WAITING_ON_IO && feed.available < feed.total &&
          rounds++ < 64) {
        feed.available = std::min(feed.total, feed.available + chunk);
        continue;
      }
      if (result != AVIF_RESULT_OK) break;
      INVARIANT(decoder->image->width > 0 && decoder->image->height > 0);
      if (++decoded >= 4) break;
    }
    INVARIANT(result != AVIF_RESULT_INTERNAL_ERROR);
  }
  SafeDestroy(decoder);
  return ret;
}
