// Attaches arbitrary opaque / UUID properties to an image, encodes and decodes it, and checks the
// properties come back byte for byte (ports PropertiesAvifFuzzTest.EncodeDecode).
#include <string.h>

#include <string>
#include <vector>

#include "avif/internal.h"
#include "common.h"

struct TestProp {
  uint8_t fourcc[4];
  uint8_t uuid[16];
  bool is_uuid;
  std::vector<uint8_t> body;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Bytes in{data, size};
  avifEncoder* encoder = ReadEncoder(in);
  avifDecoder* decoder = ReadDecoder(in);
  const ImageSpec spec = ReadImageSpec(in, /*allow16=*/false);
  const size_t num_props = in.U8() % 9;
  std::vector<TestProp> props(num_props);
  for (TestProp& p : props) {
    p.is_uuid = in.U8() & 1;
    for (uint8_t& b : p.fourcc) b = in.U8();
    for (uint8_t& b : p.uuid) b = in.U8();
    if (p.is_uuid) memcpy(p.fourcc, "uuid", 4);
    p.body.resize(in.U8() % 32);
    for (uint8_t& b : p.body) b = in.U8();
  }
  avifImage* image = BuildImage(spec, in.d, in.n);
  if (encoder == nullptr || decoder == nullptr || image == nullptr) {
    SafeDestroy(encoder);
    SafeDestroy(decoder);
    SafeDestroy(image);
    return -1;
  }

  std::vector<const TestProp*> valid;
  for (const TestProp& p : props) {
    if (p.is_uuid) {
      const avifResult r = avifImageAddUUIDProperty(
          image, p.uuid, p.body.data(), p.body.size());
      if (avifIsValidUUID(p.uuid)) {
        valid.push_back(&p);
        INVARIANT(r == AVIF_RESULT_OK);
      } else {
        INVARIANT(r == AVIF_RESULT_INVALID_ARGUMENT);
      }
    } else {
      const avifResult r = avifImageAddOpaqueProperty(
          image, p.fourcc, p.body.data(), p.body.size());
      if (avifIsKnownPropertyType(p.fourcc)) {
        INVARIANT(r == AVIF_RESULT_INVALID_ARGUMENT);
      } else {
        valid.push_back(&p);
        INVARIANT(r == AVIF_RESULT_OK);
      }
    }
  }

  avifRWData encoded = AVIF_DATA_EMPTY;
  INVARIANT(avifEncoderWrite(encoder, image, &encoded) == AVIF_RESULT_OK);
  avifImage* decoded = avifImageCreateEmpty();
  INVARIANT(avifDecoderReadMemory(decoder, decoded, encoded.data,
                                  encoded.size) == AVIF_RESULT_OK);
  INVARIANT(decoder->image->numProperties == valid.size());
  for (size_t i = 0; i < valid.size(); ++i) {
    const avifImageItemProperty& got = decoder->image->properties[i];
    INVARIANT(memcmp(got.boxtype, valid[i]->fourcc, 4) == 0);
    INVARIANT(got.boxPayload.size == valid[i]->body.size());
    INVARIANT(valid[i]->body.empty() ||
              memcmp(got.boxPayload.data, valid[i]->body.data(),
                     valid[i]->body.size()) == 0);
  }
  avifRWDataFree(&encoded);
  SafeDestroy(decoded);
  SafeDestroy(image);
  SafeDestroy(encoder);
  SafeDestroy(decoder);
  return 0;
}
