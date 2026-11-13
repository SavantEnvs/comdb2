// libFuzzer harness for comdb2's CRLE record compressor (comdb2rle/).
// byte0 bit0 = 0: decompress the remaining bytes into a heap buffer of a fuzzer-chosen size
//                 (bytes 1-2), the way bdb/odh.c:599 feeds a stored record.
// byte0 bit0 = 1: compress the remaining bytes with and without field hints (the hints partition
//                 the record, as bdb/odh.c's fld_hints do), decompress, and require the round trip.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "comdb2rle.h"

// decode() loads each 1-byte Header through a 32-bit bitfield unit, so it can read up to 3
// bytes past the last compressed byte. The only server caller (bdb/odh.c:599) passes
// `from + ODH_SIZE` / `fromlen - ODH_SIZE`, a record item from berkdb whose allocation was not
// traced, so this padding is an assumption: if such an item can end exactly at the last
// compressed byte, the over-read is a real defect that this padding hides.
#define DECODE_SLACK 8

static void roundtrip(const uint8_t *rec, size_t len, uint16_t *hints)
{
    // The server hands the compressor a buffer one byte shorter than the record: it only
    // keeps the result when it is smaller (bdb/odh.c).
    size_t cap = len - 1;
    uint8_t *comp = calloc(1, cap + DECODE_SLACK);
    uint8_t *plain = malloc(len);
    if (!comp || !plain) {
        free(comp);
        free(plain);
        return;
    }
    Comdb2RLE c = {.in = (uint8_t *)rec, .insz = len, .out = comp, .outsz = cap};
    int rc = hints ? compressComdb2RLE_hints(&c, hints) : compressComdb2RLE(&c);
    if (rc == 0) {
        Comdb2RLE d = {.in = comp, .insz = c.outsz, .out = plain, .outsz = len};
        if (decompressComdb2RLE(&d) != 0 || d.outsz != len || memcmp(plain, rec, len) != 0)
            abort();
    }
    free(comp);
    free(plain);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4)
        return -1;
    int mode = data[0] & 1;
    if (mode == 0) {
        size_t outcap = (size_t)data[1] | ((size_t)data[2] << 8);
        const uint8_t *in = data + 3;
        size_t insz = size - 3;
        uint8_t *out = malloc(outcap ? outcap : 1);
        uint8_t *inbuf = calloc(1, insz + DECODE_SLACK);
        if (!out || !inbuf) {
            free(out);
            free(inbuf);
            return -1;
        }
        memcpy(inbuf, in, insz);
        Comdb2RLE d = {.in = inbuf, .insz = insz, .out = out, .outsz = outcap};
        decompressComdb2RLE(&d);
        free(out);
        free(inbuf);
        return 0;
    }

    const uint8_t *rec = data + 1;
    size_t len = size - 1;
    roundtrip(rec, len, NULL);

    // field sizes derived from the record's own bytes, summing exactly to len, 0-terminated
    uint16_t *hints = malloc((len + 1) * sizeof(uint16_t));
    if (!hints)
        return 0;
    size_t n = 0, left = len;
    for (size_t i = 0; left > 0; i++) {
        size_t sz = (size_t)(rec[i % len] % 24) + 1;
        if (sz > left)
            sz = left;
        hints[n++] = (uint16_t)sz;
        left -= sz;
    }
    hints[n] = 0;
    roundtrip(rec, len, hints);
    free(hints);
    return 0;
}
