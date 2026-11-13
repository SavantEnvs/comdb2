// Known-answer probe for the comdb2 libraries fuzzed from mayhem/: csc2, cson, comdb2rle, decNumber.
// Built with the project's normal flags by mayhem/build.sh; mayhem/test.sh diffs its stdout against
// mayhem/kat.expected, so every line is a behavioral known-input -> known-output assertion.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "comdb2rle.h"
#include "cson.h"
#include "decContext.h"
#include "decQuad.h"
#include "dynschemaload.h"

extern int comdb2ma_init(size_t init_sz, size_t max_cap);

static void kat_rle(void)
{
    uint8_t rec[96];
    memset(rec, 0, 40);
    memset(rec + 40, 0xab, 24);
    for (int i = 64; i < 96; i++)
        rec[i] = (uint8_t)i;

    uint8_t comp[128 + 8] = {0};
    Comdb2RLE c = {.in = rec, .insz = sizeof(rec), .out = comp, .outsz = sizeof(rec) - 1};
    int rc = compressComdb2RLE(&c);
    printf("rle compress rc=%d size=%zu\n", rc, (size_t)c.outsz);
    printf("rle bytes:");
    for (size_t i = 0; i < c.outsz; i++)
        printf(" %02x", comp[i]);
    printf("\n");

    uint8_t plain[sizeof(rec)];
    Comdb2RLE d = {.in = comp, .insz = c.outsz, .out = plain, .outsz = sizeof(plain)};
    rc = decompressComdb2RLE(&d);
    printf("rle decompress rc=%d size=%zu equal=%d\n", rc, (size_t)d.outsz, memcmp(plain, rec, sizeof(rec)) == 0);
}

static void kat_cson(void)
{
    const char *text = "{\"name\":\"comdb2\",\"n\":[1,2,3],\"ok\":true,\"pi\":2.5,\"nested\":{\"k\":\"v\"}}";
    cson_value *val = NULL;
    int rc = cson_parse_string(&val, text, (unsigned)strlen(text));
    printf("cson parse rc=%d\n", rc);
    if (rc != 0)
        return;
    cson_object *obj = cson_value_get_object(val);
    printf("cson name=%s\n", cson_value_get_cstr(cson_object_get(obj, "name")));
    cson_array *arr = cson_value_get_array(cson_object_get(obj, "n"));
    cson_int_t sum = 0;
    for (unsigned i = 0; i < cson_array_length_get(arr); i++) {
        cson_int_t v = 0;
        cson_value_fetch_integer(cson_array_get(arr, i), &v);
        sum += v;
    }
    printf("cson n.len=%u sum=%d\n", cson_array_length_get(arr), (int)sum);
    printf("cson ok=%d\n", (int)cson_value_get_bool(cson_object_get(obj, "ok")));
    cson_double_t pi = 0;
    cson_value_fetch_double(cson_object_get(obj, "pi"), &pi);
    printf("cson pi=%.2f\n", pi);
    cson_object *nested = cson_value_get_object(cson_object_get(obj, "nested"));
    printf("cson nested.k=%s\n", cson_value_get_cstr(cson_object_get(nested, "k")));
    cson_value_free(val);

    cson_value *bad = NULL;
    printf("cson parse-bad rc=%d\n", cson_parse_string(&bad, "{\"a\":", 5) != 0);
}

static void kat_dec(void)
{
    decContext ctx;
    decContextDefault(&ctx, DEC_INIT_DECIMAL128);
    decQuad a, b, r;
    char s[DECQUAD_String];
    decQuadFromString(&a, "1.10", &ctx);
    decQuadFromString(&b, "2.205", &ctx);
    decQuadAdd(&r, &a, &b, &ctx);
    decQuadToString(&r, s);
    printf("dec 1.10+2.205=%s\n", s);
    decQuadMultiply(&r, &a, &b, &ctx);
    decQuadToString(&r, s);
    printf("dec 1.10*2.205=%s\n", s);
    decQuadFromString(&a, "1", &ctx);
    decQuadFromString(&b, "3", &ctx);
    decQuadDivide(&r, &a, &b, &ctx);
    decQuadToString(&r, s);
    printf("dec 1/3=%s\n", s);
    decQuadFromString(&a, "-12345.6789", &ctx);
    decQuadFromString(&b, "0.01", &ctx);
    decQuadQuantize(&r, &a, &b, &ctx);
    decQuadToString(&r, s);
    printf("dec quantize=%s\n", s);
    decQuadFromString(&a, "NaN", &ctx);
    printf("dec nan=%d\n", (int)decQuadIsNaN(&a));
}

static void kat_csc2(void)
{
    const char *schema = "schema\n"
                         "{\n"
                         "    int id\n"
                         "    cstring name[32]\n"
                         "    longlong big\n"
                         "}\n"
                         "keys\n"
                         "{\n"
                         "    \"ID\" = id\n"
                         "    dup \"BYNAME\" = name\n"
                         "}\n";
    dyns_init_globals();
    int rc = dyns_load_schema_string((char *)schema, "katdb", "kattbl");
    printf("csc2 load rc=%d\n", rc);
    if (rc == 0) {
        char *tag = dyns_get_table_tag(0);
        printf("csc2 tables=%d tag=%s\n", dyns_get_table_count(), tag);
        int n = dyns_get_table_field_count(tag);
        printf("csc2 fields=%d\n", n);
        for (int i = 0; i < n; i++) {
            char name[64];
            int type = 0, offset = 0, elsize = 0, fullsize = 0, arr = 0;
            dyns_get_table_field_info(tag, i, name, sizeof(name), &type, &offset, &elsize, &fullsize, &arr, 1);
            printf("csc2 field %d %s type=%d offset=%d size=%d\n", i, name, type, offset, fullsize);
        }
        int nidx = dyns_get_idx_count();
        printf("csc2 keys=%d\n", nidx);
        for (int i = 0; i < nidx; i++) {
            char ktag[64];
            char *where = NULL;
            dyns_get_idx_tag(i, ktag, sizeof(ktag), &where);
            printf("csc2 key %d %s dup=%d pieces=%d\n", i, ktag, dyns_is_idx_dup(i), dyns_get_idx_piece_count(i));
        }
    }
    dyns_cleanup_globals();
    csc2_free_all();

    dyns_init_globals();
    rc = dyns_load_schema_string("schema { notatype x }", "katdb", "badtbl");
    printf("csc2 bad-schema rc-nonzero=%d\n", rc != 0);
    dyns_cleanup_globals();
    csc2_free_all();
}

int main(void)
{
    comdb2ma_init(0, 0);
    kat_rle();
    kat_cson();
    kat_dec();
    kat_csc2();
    return 0;
}
