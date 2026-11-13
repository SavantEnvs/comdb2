// libFuzzer harness for the decNumber fixed-width decimal formats comdb2 uses for its DECIMAL
// types (dfp/decNumber via dfp/dfpal, db/types.c, sqlite/src/vdbemem.c).
// Input: byte0 picks rounding mode and operation; the rest is two decimal strings separated by '\n'.
// Only entry points comdb2 calls are exercised: decQuadFromString (vdbemem.c) and decDoubleFromString
// (dfpal_decimal64FromString) on user text; decQuad arithmetic as in vdbemem.c; packed/wider/string
// conversions as in db/types.c. decSingle is reached by comdb2 only through decSingleFromPacked.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "decContext.h"
#include "decQuad.h"
#include "decDouble.h"
#include "decSingle.h"

static const enum rounding modes[] = {DEC_ROUND_CEILING, DEC_ROUND_UP, DEC_ROUND_HALF_UP, DEC_ROUND_HALF_EVEN,
                                      DEC_ROUND_HALF_DOWN, DEC_ROUND_DOWN, DEC_ROUND_FLOOR, DEC_ROUND_05UP};

static void run(const char *a, const char *b, unsigned sel)
{
    decContext ctx;
    decContextDefault(&ctx, DEC_INIT_DECIMAL128);
    decContextSetRounding(&ctx, modes[(sel >> 4) % 8]);
    decContext ctx64;
    decContextDefault(&ctx64, DEC_INIT_DECIMAL64);

    char qs[DECQUAD_String], ds[DECDOUBLE_String];
    decQuad x, y, z;
    decQuadFromString(&x, a, &ctx);
    decQuadFromString(&y, b, &ctx);
    decQuadToString(&x, qs);

    switch (sel & 7) {
    case 0: decQuadAdd(&z, &x, &y, &ctx); break;
    case 1: decQuadSubtract(&z, &x, &y, &ctx); break;
    case 2: decQuadMultiply(&z, &x, &y, &ctx); break;
    case 3: decQuadDivide(&z, &x, &y, &ctx); break;
    case 4: decQuadRemainder(&z, &x, &y, &ctx); break;
    case 5: decQuadCompare(&z, &x, &y, &ctx); break;
    case 6: decQuadCompareTotal(&z, &x, &y); break;
    default: decQuadToIntegralValue(&z, &x, &ctx, ctx.round); break;
    }
    decQuadToString(&z, qs);
    decQuadAbs(&z, &z, &ctx);
    decQuadIsSigned(&z);
    decQuadIsZero(&z);
    decQuadIsNaN(&z);
    decQuadIsInfinite(&z);
    decQuadIsSignaling(&z);

    uint8_t packed[DECQUAD_Pmax / 2 + 1];
    int32_t exp;
    decQuadToPacked(&x, &exp, packed);
    decQuadFromPacked(&z, exp, packed);

    decDouble dbl;
    decDoubleFromString(&dbl, a, &ctx64);
    decDoubleToString(&dbl, ds);
    decDoubleIsSigned(&dbl);
    decDoubleIsNaN(&dbl);
    decDoubleIsInfinite(&dbl);
    decDoubleIsSignaling(&dbl);
    decQuad wide;
    decDoubleToWider(&dbl, &wide);
    decQuadToString(&wide, qs);
    decDoubleFromWider(&dbl, &x, &ctx64);
    uint8_t dpacked[DECDOUBLE_Pmax / 2 + 1];
    int32_t dexp;
    decDoubleToPacked(&dbl, &dexp, dpacked);
    decDoubleFromPacked(&dbl, dexp, dpacked);

    // decFloatFromPacked's contract (decCommon.c) is an in-range exponent: [Emin-(Pmax-1), Emax-(Pmax-1)]
    // for decSingle. The last 4 bytes of a decDouble's packed form (7 digits plus the sign nibble)
    // are a valid packed decSingle coefficient.
    if (dexp >= DECSINGLE_Emin - (DECSINGLE_Pmax - 1) && dexp <= DECSINGLE_Emax - (DECSINGLE_Pmax - 1)) {
        decSingle sgl;
        decDouble swide;
        decSingleFromPacked(&sgl, dexp, dpacked + sizeof(dpacked) - 4);
        decSingleToWider(&sgl, &swide);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > 4096)
        return -1;
    unsigned sel = data[0];
    size_t n = size - 1;
    char *buf = malloc(n + 1);
    if (!buf)
        return -1;
    memcpy(buf, data + 1, n);
    buf[n] = 0;
    const char *b = "";
    char *nl = memchr(buf, '\n', n);
    if (nl) {
        *nl = 0;
        b = nl + 1;
    }
    run(buf, b, sel);
    free(buf);
    return 0;
}
