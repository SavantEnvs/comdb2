// Stand-ins for the handful of database-layer callbacks the csc2 library links against
// (the server defines them in db/glue.c, db/macc_glue.c, db/sqlglue.c, db/comdb2.c, ...).
#include <stdlib.h>
#include <pthread.h>

#include "types.h"

int comdb2_iam_master(void)
{
    return 1;
}

int gbl_broken_max_rec_sz = 0;
int gbl_broken_num_parser = 0;
int gbl_create_mode = 0;
int gbl_ready = 1;
pthread_mutex_t csc2_subsystem_mtx = PTHREAD_MUTEX_INITIALIZER;

// Accept any default-value string/function name; the real checks need a live database.
int is_valid_datetime(const char *str, const char *tz)
{
    (void)str;
    (void)tz;
    return 1;
}
int verify_dbstore_client_function(const char *dbstore)
{
    (void)dbstore;
    return 0;
}
void create_verify_dbstore_clientfunc(const char *dbstore)
{
    (void)dbstore;
}

// Verbatim copy of db/macc_glue.c:dyns_adjust_ondisk_field_length().
int dyns_adjust_ondisk_field_length(int server_type, int len, int client_type)
{
    switch (server_type) {
    case SERVER_BLOB:
        return 5;
    case SERVER_VUTF8:
    case SERVER_BLOB2:
        return (len == -1) ? 5 : (len + 5);
    case SERVER_BCSTR:
        if (client_type == CLIENT_PSTR || client_type == CLIENT_PSTR2)
            return len + 1;
        return len;
    case SERVER_DATETIME:
        return sizeof(server_datetime_t);
    case SERVER_DATETIMEUS:
        return sizeof(server_datetimeus_t);
    case SERVER_INTVYM:
        return sizeof(server_intv_ym_t);
    case SERVER_INTVDS:
        return sizeof(server_intv_ds_t);
    case SERVER_INTVDSUS:
        return sizeof(server_intv_dsus_t);
    case SERVER_DECIMAL:
        switch (len) {
        case 14:
            return sizeof(server_decimal32_t);
        case 24:
            return sizeof(server_decimal64_t);
        case 43:
            return sizeof(server_decimal128_t);
        default:
            abort();
        }
    default:
        return len + 1;
    }
}
