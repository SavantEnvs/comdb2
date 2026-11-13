// libFuzzer harness for comdb2's csc2 schema-definition-language parser (csc2/).
// Same entry points the server uses in db/macc_glue.c:create_new_dbtable():
// dyns_init_globals -> dyns_load_schema_string -> accessors -> dyns_cleanup_globals.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dynschemaload.h"

extern int comdb2ma_init(size_t init_sz, size_t max_cap);

// csc2/macc_so.c keeps the field options of the field being parsed in globals that a parse error leaves
// half-filled; the next parse then copies stale options whose strings live in the freed csc2 arena.
// Reset them per input so every crash reproduces from its single input file.
extern int nfieldopt;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    comdb2ma_init(0, 0);
    return 0;
}

static void exercise_table(char *tag)
{
    int nfields = dyns_get_table_field_count(tag);
    for (int i = 0; i < nfields; i++) {
        char name[256];
        int type = 0, offset = 0, elsize = 0, fullsize = 0, arr = 0;
        dyns_get_table_field_info(tag, i, name, sizeof(name), &type, &offset, &elsize, &fullsize, &arr, 1);
        dyns_get_table_field_info(tag, i, name, sizeof(name), &type, &offset, &elsize, &fullsize, &arr, 0);
        int dims[8], ndims = 0;
        if (dyns_is_table_field_array(tag, i))
            dyns_get_table_field_arr_dims(tag, i, dims, 8, &ndims);
        dpth_t depth[8];
        int ndepth = 0;
        dyns_table_field_depth(tag, i, depth, 8, &ndepth);
        for (int opt = 0; opt < FLDOPT_MAX; opt++) {
            int vtype = 0, vsz = 0;
            char vbuf[256];
            char *func = NULL;
            dyns_get_table_field_option(tag, i, opt, &vtype, &vsz, vbuf, sizeof(vbuf), &func);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *schema = malloc(size + 1);
    if (!schema)
        return -1;
    memcpy(schema, data, size);
    schema[size] = 0;

    nfieldopt = 0;
    dyns_init_globals();
    int rc = dyns_load_schema_string(schema, "fuzzdb", "fuzztbl");
    if (rc == 0) {
        int ntables = dyns_get_table_count();
        for (int t = 0; t < ntables; t++) {
            char *tag = dyns_get_table_tag(t);
            if (tag) {
                dyns_get_table_tag_size(tag);
                exercise_table(tag);
            }
        }

        int nfields = dyns_get_field_count();
        for (int i = 0; i < nfields; i++) {
            char name[256];
            int type, offset, elsize, fullsize;
            dyns_get_field_info(i, name, sizeof(name), &type, &offset, &elsize, &fullsize);
        }

        int nidx = dyns_get_idx_count();
        for (int i = 0; i < nidx; i++) {
            char tag[256];
            char *where = NULL;
            dyns_is_idx_dup(i);
            dyns_is_idx_recnum(i);
            dyns_is_idx_primary(i);
            dyns_is_idx_datacopy(i);
            dyns_is_idx_partial_datacopy(i);
            dyns_is_idx_uniqnulls(i);
            dyns_get_idx_size(i);
            dyns_get_idx_tag(i, tag, sizeof(tag), &where);
            struct partial_datacopy *pd = NULL;
            dyns_get_idx_partial_datacopy(i, &pd);
            int npieces = dyns_get_idx_piece_count(i);
            for (int p = 0; p < npieces; p++) {
                char pname[256];
                int ptype, poffset, plen, descend;
                char *expr = NULL;
                dyns_get_idx_piece(i, p, pname, sizeof(pname), &ptype, &poffset, &plen, &descend, &expr);
            }
        }

        int ncons = dyns_get_constraint_count();
        for (int i = 0; i < ncons; i++) {
            char *cname, *kname;
            int rulecnt = 0, flags = 0;
            if (dyns_get_constraint_at(i, &cname, &kname, &rulecnt, &flags) == 0) {
                for (int r = 0; r < rulecnt; r++) {
                    char *tbl, *key;
                    dyns_get_constraint_rule(i, r, &tbl, &key);
                }
            }
        }
        int nchecks = dyns_get_check_constraint_count();
        for (int i = 0; i < nchecks; i++) {
            char *cname, *expr;
            dyns_get_check_constraint_at(i, &cname, &expr);
        }

        char buf[256];
        dyns_get_db_num();
        dyns_get_db_name(buf, sizeof(buf));
        dyns_get_db_table_size();
    }
    dyns_cleanup_globals();
    csc2_free_all();
    free(schema);
    return 0;
}
