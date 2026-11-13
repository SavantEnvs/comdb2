// libFuzzer harness for comdb2's cson JSON library (cson/): parse arbitrary text,
// walk the resulting tree, mutate it (forcing a re-serialisation) and re-parse the output.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cson.h"

// cson_object_get() takes a JSON path ("$.key"), and the library treats a malformed path as an internal
// assertion (cson__not_reached raises a signal). comdb2 only looks up fixed identifiers, so only look up keys
// that are plain identifiers.
static int plain_key(const char *k)
{
    if (!k || !*k)
        return 0;
    for (; *k; k++)
        if (!((*k >= 'a' && *k <= 'z') || (*k >= 'A' && *k <= 'Z') || (*k >= '0' && *k <= '9') || *k == '_'))
            return 0;
    return 1;
}

static void walk(cson_value *v, int depth)
{
    if (v == NULL || depth > 32)
        return;
    if (cson_value_is_object(v)) {
        cson_object *obj = cson_value_get_object(v);
        cson_object_iterator it;
        if (obj && cson_object_iter_init(obj, &it) == 0) {
            cson_kvp *kv;
            while ((kv = cson_object_iter_next(&it)) != NULL) {
                const char *key = cson_string_cstr(cson_kvp_key(kv));
                if (plain_key(key))
                    cson_object_get(obj, key);
                walk(cson_kvp_value(kv), depth + 1);
            }
        }
    } else if (cson_value_is_array(v)) {
        cson_array *arr = cson_value_get_array(v);
        unsigned n = arr ? cson_array_length_get(arr) : 0;
        for (unsigned i = 0; i < n && i < 64; i++)
            walk(cson_array_get(arr, i), depth + 1);
    } else if (cson_value_is_string(v)) {
        cson_value_get_cstr(v);
    } else if (cson_value_is_integer(v)) {
        cson_int_t i;
        cson_value_fetch_integer(v, &i);
    } else if (cson_value_is_double(v)) {
        cson_double_t d;
        cson_value_fetch_double(v, &d);
    } else if (cson_value_is_bool(v)) {
        cson_value_get_bool(v);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > (1u << 20))
        return -1;
    char *text = malloc(size);
    if (!text)
        return -1;
    memcpy(text, data, size);

    cson_value *val = NULL;
    if (cson_parse_string(&val, text, (unsigned)size) == 0) {
        walk(val, 0);

        cson_buffer buf;
        cson_output_buffer(val, &buf);

        // The cson_value_get_* accessors do not check the type, so branch on it explicitly.
        if (cson_value_is_object(val)) {
            cson_object *obj = cson_value_get_object(val);
            cson_object_set(obj, "fuzz_key", cson_value_new_integer(size));
            cson_object_unset(obj, "fuzz_key");
        } else if (cson_value_is_array(val)) {
            cson_array_append(cson_value_get_array(val), cson_value_new_string("fuzz", 4));
        }
        cson_output_buffer(val, &buf);
        if (buf.mem && buf.used > 0) {
            cson_value *again = NULL;
            if (cson_parse_string(&again, buf.mem, (unsigned)buf.used) == 0) {
                walk(again, 0);
                cson_value_free(again);
            }
        }
        cson_value_free(val);
    }
    free(text);
    return 0;
}
