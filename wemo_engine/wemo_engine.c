#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

#include <pthread.h>
#include <stdlib.h>
#include <ixml.h>
#include <sqlite3.h>

#include "wemo_engine.h"

static struct wemo_engine_callback we_callback;

static int socket_fd = -1;
static char ipc_host[64] = IPC_DEFAULT_HOST;
static int ipc_port = IPC_DEFAULT_PORT;
static pthread_mutex_t socket_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t we_ipc_thread;
static int we_ipc_thread_valid = 0;
static int we_initialized = 0;
static uint32_t we_request_id = 1;
static uint32_t we_client_id = 0;
static int we_proto_enabled = 1;
static int we_proto_legacy_fallback = 1;
static int we_txn_trace = 0;
static int we_adaptive_timeout = 1;
static int we_circuit_breaker_enabled = 1;
static int we_get_retry_max = 2;
static int we_probe_retry_max = 2;
static int we_retry_jitter_max_ms = 120;
static int we_health_delta_ttl_sec = 86400;
static int we_health_delta_max_rows = 2048;
static uint64_t we_set_idempotency_seq = 1;
static pthread_mutex_t audit_lock = PTHREAD_MUTEX_INITIALIZER;
static sqlite3 *audit_db = NULL;
static int audit_init_done = 0;
static char audit_db_path[256] = {0};

#define WE_MAX_TRACKED_DEVICES 64
#define WE_CONFIRM_WAIT_SLICE_MS 2000
#define WE_DEGRADED_SCORE_THRESHOLD 4
#define WE_DEGRADED_TIMEOUT_STREAK 2
#define WE_DIMMER_PROBE_STRONG 2
#define WE_DIMMER_PROBE_WEAK 3
#define WE_TIMEOUT_MAX_BOOST_MS 15000
#define WE_TIMEOUT_MAX_TOTAL_MS 30000
#define WE_CIRCUIT_OPEN_TIMEOUT_STREAK 3
#define WE_CIRCUIT_COOLDOWN_BASE_MS 3000
#define WE_CIRCUIT_COOLDOWN_MAX_MS 30000

typedef struct {
    int in_use;
    int wemo_id;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int last_state_valid;
    struct we_state last_state;
    uint32_t state_seq;
    uint32_t pending_request_id;
    int pending_response_ready;
    int pending_status;
    uint32_t pending_completion_request_id;
    int pending_completion_ready;
    int pending_completion_status;
    int pending_completion_outcome;
    uint32_t last_response_request_id;
    int last_response_valid;
    int last_response_status;
    uint32_t last_completion_request_id;
    int last_completion_valid;
    int last_completion_status;
    int last_completion_outcome;
    int health_score;
    int timeout_streak;
    int degraded_mode;
    uint32_t total_applied;
    uint32_t total_timeouts;
    uint32_t total_rejected;
    uint32_t total_retries;
    int last_retry_count;
    int ema_applied_latency_ms;
    int last_applied_latency_ms;
    int64_t breaker_until_ms;
    uint32_t breaker_open_count;
} we_device_ctx_t;

static pthread_mutex_t we_device_table_lock = PTHREAD_MUTEX_INITIALIZER;
static we_device_ctx_t we_device_table[WE_MAX_TRACKED_DEVICES];
static pthread_mutex_t health_delta_lock = PTHREAD_MUTEX_INITIALIZER;
static struct we_health_delta health_delta_ring[WE_HEALTH_DELTA_MAX_ITEMS];
static int health_delta_next = 0;
static int health_delta_count = 0;

static int64_t we_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void we_retry_jitter_sleep(void)
{
    int jitter_ms;
    if (we_retry_jitter_max_ms <= 0) {
        return;
    }
    jitter_ms = rand() % (we_retry_jitter_max_ms + 1);
    usleep((useconds_t)jitter_ms * 1000);
}

static uint32_t we_make_client_id(void)
{
    struct timespec ts;
    uint32_t id;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        ts.tv_sec = 0;
        ts.tv_nsec = 0;
    }
    id = (uint32_t)getpid() ^ (uint32_t)ts.tv_sec ^ (uint32_t)ts.tv_nsec ^ 0x57454d4fU;
    if (id == 0) {
        id = 1;
    }
    return id;
}

static uint64_t we_next_set_idempotency_key(void)
{
    uint64_t seq = __sync_fetch_and_add(&we_set_idempotency_seq, 1);
    uint64_t key = ((uint64_t)we_client_id << 32) ^ seq ^ (uint64_t)we_now_ms();
    if (key == 0) {
        key = (uint64_t)we_client_id << 32 | 1ULL;
    }
    return key;
}

static int we_circuit_cooldown_ms_locked(const we_device_ctx_t *ctx)
{
    int step;
    int cooldown_ms = WE_CIRCUIT_COOLDOWN_BASE_MS;

    if (ctx == NULL) {
        return WE_CIRCUIT_COOLDOWN_BASE_MS;
    }
    step = (ctx->breaker_open_count > 4) ? 4 : (int)ctx->breaker_open_count;
    cooldown_ms <<= step;
    if (ctx->degraded_mode) {
        cooldown_ms += 2000;
    }
    if (cooldown_ms > WE_CIRCUIT_COOLDOWN_MAX_MS) {
        cooldown_ms = WE_CIRCUIT_COOLDOWN_MAX_MS;
    }
    return cooldown_ms;
}

static void we_health_update_locked(we_device_ctx_t *ctx, const struct we_txn_result *result)
{
    if (ctx == NULL || result == NULL) {
        return;
    }
    if (result->retry_count > 0) {
        ctx->total_retries += (uint32_t)result->retry_count;
    }
    ctx->last_retry_count = result->retry_count;
    if (result->outcome == WE_TXN_APPLIED) {
        ctx->total_applied++;
        ctx->timeout_streak = 0;
        if (result->elapsed_ms > 0) {
            ctx->last_applied_latency_ms = result->elapsed_ms;
            if (ctx->ema_applied_latency_ms <= 0) {
                ctx->ema_applied_latency_ms = result->elapsed_ms;
            } else {
                ctx->ema_applied_latency_ms =
                    (ctx->ema_applied_latency_ms * 3 + result->elapsed_ms) / 4;
            }
        }
        if (ctx->health_score > 0) {
            ctx->health_score--;
        }
        if (ctx->breaker_until_ms > 0) {
            ctx->breaker_until_ms = 0;
            ctx->breaker_open_count = 0;
        }
    } else if (result->outcome == WE_TXN_TIMEOUT) {
        int cooldown_ms = 0;
        ctx->total_timeouts++;
        ctx->timeout_streak++;
        ctx->health_score += 2;
        if (we_circuit_breaker_enabled && ctx->timeout_streak >= WE_CIRCUIT_OPEN_TIMEOUT_STREAK) {
            cooldown_ms = we_circuit_cooldown_ms_locked(ctx);
            ctx->breaker_until_ms = we_now_ms() + cooldown_ms;
            if (ctx->breaker_open_count < 1000) {
                ctx->breaker_open_count++;
            }
        }
    } else if (result->outcome == WE_TXN_REJECTED || result->outcome == WE_TXN_MISMATCH) {
        ctx->total_rejected++;
        ctx->health_score++;
    }

    if (ctx->timeout_streak >= WE_DEGRADED_TIMEOUT_STREAK ||
        ctx->health_score >= WE_DEGRADED_SCORE_THRESHOLD) {
        ctx->degraded_mode = 1;
    } else if (ctx->timeout_streak == 0 && ctx->health_score <= 1) {
        ctx->degraded_mode = 0;
    }
}

static int we_effective_timeout_ms_locked(const we_device_ctx_t *ctx, int cmd, int policy, int timeout_ms)
{
    int boost_ms = 0;
    int effective_ms = timeout_ms;

    if (ctx == NULL || timeout_ms <= 0 || !we_adaptive_timeout || policy == WE_CONFIRM_NONE) {
        return timeout_ms;
    }

    if (cmd == CMD_SET && policy == WE_CONFIRM_STATE_MATCH) {
        boost_ms += 1500;
    }
    if (ctx->degraded_mode) {
        boost_ms += 2500;
    }
    if (ctx->timeout_streak > 0) {
        boost_ms += ctx->timeout_streak * 2000;
    }
    if (ctx->ema_applied_latency_ms > timeout_ms) {
        boost_ms += (ctx->ema_applied_latency_ms - timeout_ms) / 2;
    } else if (ctx->ema_applied_latency_ms > (timeout_ms * 7) / 10) {
        boost_ms += 1000;
    }

    if (boost_ms > WE_TIMEOUT_MAX_BOOST_MS) {
        boost_ms = WE_TIMEOUT_MAX_BOOST_MS;
    }
    effective_ms = timeout_ms + boost_ms;
    if (effective_ms > WE_TIMEOUT_MAX_TOTAL_MS) {
        effective_ms = WE_TIMEOUT_MAX_TOTAL_MS;
    }
    if (effective_ms < timeout_ms) {
        effective_ms = timeout_ms;
    }
    return effective_ms;
}

static int we_state_matches_target_relaxed(const struct we_state *actual, const struct we_state *target)
{
    if (actual == NULL || target == NULL) {
        return 0;
    }
    if (target->state >= 0 && actual->state != target->state) {
        return 0;
    }
    if (target->level >= 0 && actual->level >= 0) {
        int delta = actual->level - target->level;
        if (delta < 0) {
            delta = -delta;
        }
        if (delta > 10) {
            return 0;
        }
    }
    return 1;
}

static void we_build_audit_path(void)
{
    const char *home = getenv("HOME");
    if (audit_db_path[0] != '\0') {
        return;
    }
    if (home != NULL && home[0] != '\0') {
        snprintf(audit_db_path, sizeof(audit_db_path),
                 "%s/.local/state/wemo-matter/wemo_txn_audit.db", home);
    } else {
        snprintf(audit_db_path, sizeof(audit_db_path), "/tmp/wemo_txn_audit.db");
    }
}

static void we_build_state_db_path(char *out, size_t out_len)
{
    const char *override = getenv("WEMO_STATE_DB_PATH");
    const char *home = getenv("HOME");
    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (override != NULL && override[0] != '\0') {
        snprintf(out, out_len, "%s", override);
        return;
    }
    if (geteuid() == 0) {
        snprintf(out, out_len, "/var/lib/wemo-matter/wemo_state.db");
        return;
    }
    if (home != NULL && home[0] != '\0') {
        snprintf(out, out_len, "%s/.local/state/wemo-matter/wemo_state.db", home);
        return;
    }
    snprintf(out, out_len, "/var/tmp/wemo-matter/wemo_state.db");
}

static int we_get_online_state_from_db(int wemo_id, int *is_online_out)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char path[256];
    const char *sql = "SELECT is_online FROM state WHERE wemo_id=?;";
    int rc = WE_STATUS_INVALID;

    if (wemo_id <= 0 || is_online_out == NULL) {
        return WE_STATUS_INVALID;
    }
    we_build_state_db_path(path, sizeof(path));
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db != NULL) {
            sqlite3_close(db);
        }
        return WE_STATUS_INTERNAL;
    }
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, wemo_id);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *is_online_out = sqlite3_column_int(stmt, 0);
            rc = WE_STATUS_OK;
        }
    }
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return rc;
}

static void we_ensure_parent_dir(const char *path)
{
    char tmp[256];
    char *p;
    char *slash;

    if (path == NULL || path[0] == '\0') {
        return;
    }
    snprintf(tmp, sizeof(tmp), "%s", path);
    slash = strrchr(tmp, '/');
    if (slash == NULL) {
        return;
    }
    *slash = '\0';
    if (tmp[0] == '\0') {
        return;
    }
    for (p = tmp + 1; *p; p++) {
        if (*p != '/') {
            continue;
        }
        *p = '\0';
        mkdir(tmp, 0700);
        *p = '/';
    }
    mkdir(tmp, 0700);
}

static void we_audit_init(void)
{
    const char *sql = "CREATE TABLE IF NOT EXISTS txn_audit ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "ts_ms INTEGER NOT NULL,"
                      "cmd INTEGER NOT NULL,"
                      "wemo_id INTEGER NOT NULL,"
                      "policy INTEGER NOT NULL,"
                      "used_proto INTEGER NOT NULL,"
                      "request_id INTEGER NOT NULL,"
                      "response_status INTEGER NOT NULL,"
                      "outcome INTEGER NOT NULL,"
                      "elapsed_ms INTEGER NOT NULL,"
                      "retry_count INTEGER NOT NULL DEFAULT 0,"
                      "confirm_source INTEGER NOT NULL,"
                      "health_score INTEGER NOT NULL,"
                      "note TEXT"
                      ");"
                      "CREATE TABLE IF NOT EXISTS device_health ("
                      "wemo_id INTEGER PRIMARY KEY,"
                      "updated_ts_ms INTEGER NOT NULL,"
                      "health_score INTEGER NOT NULL,"
                      "timeout_streak INTEGER NOT NULL,"
                      "degraded_mode INTEGER NOT NULL,"
                      "breaker_open INTEGER NOT NULL,"
                      "breaker_remaining_ms INTEGER NOT NULL,"
                      "breaker_open_count INTEGER NOT NULL,"
                      "total_applied INTEGER NOT NULL,"
                      "total_timeouts INTEGER NOT NULL,"
                      "total_rejected INTEGER NOT NULL,"
                      "total_retries INTEGER NOT NULL DEFAULT 0,"
                      "last_retry_count INTEGER NOT NULL DEFAULT 0,"
                      "ema_applied_latency_ms INTEGER NOT NULL,"
                      "last_applied_latency_ms INTEGER NOT NULL"
                      ");";
    char *err = NULL;

    pthread_mutex_lock(&audit_lock);
    if (audit_init_done) {
        pthread_mutex_unlock(&audit_lock);
        return;
    }
    we_build_audit_path();
    we_ensure_parent_dir(audit_db_path);
    if (sqlite3_open(audit_db_path, &audit_db) != SQLITE_OK) {
        if (audit_db != NULL) {
            sqlite3_close(audit_db);
            audit_db = NULL;
        }
        audit_init_done = 1;
        pthread_mutex_unlock(&audit_lock);
        return;
    }
    sqlite3_busy_timeout(audit_db, 2000);
    if (sqlite3_exec(audit_db, sql, NULL, NULL, &err) != SQLITE_OK) {
        if (err != NULL) {
            sqlite3_free(err);
        }
        sqlite3_close(audit_db);
        audit_db = NULL;
    } else {
        /* Backward compatible migration for existing DB files. */
        sqlite3_exec(audit_db,
                     "ALTER TABLE txn_audit ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0;",
                     NULL, NULL, NULL);
        sqlite3_exec(audit_db,
                     "ALTER TABLE device_health ADD COLUMN total_retries INTEGER NOT NULL DEFAULT 0;",
                     NULL, NULL, NULL);
        sqlite3_exec(audit_db,
                     "ALTER TABLE device_health ADD COLUMN last_retry_count INTEGER NOT NULL DEFAULT 0;",
                     NULL, NULL, NULL);
        sqlite3_exec(audit_db,
                     "CREATE TABLE IF NOT EXISTS health_delta_log ("
                     "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                     "ts_ms INTEGER NOT NULL,"
                     "wemo_id INTEGER NOT NULL,"
                     "health_score INTEGER NOT NULL,"
                     "timeout_streak INTEGER NOT NULL,"
                     "degraded_mode INTEGER NOT NULL,"
                     "breaker_open INTEGER NOT NULL,"
                     "breaker_open_count INTEGER NOT NULL,"
                     "total_applied INTEGER NOT NULL,"
                     "total_timeouts INTEGER NOT NULL,"
                     "total_rejected INTEGER NOT NULL,"
                     "total_retries INTEGER NOT NULL,"
                     "last_retry_count INTEGER NOT NULL"
                     ");",
                     NULL, NULL, NULL);
    }
    audit_init_done = 1;
    pthread_mutex_unlock(&audit_lock);
}

static void we_audit_record(const struct we_txn_result *result, int confirm_source, int health_score, const char *note)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO txn_audit"
                      "(ts_ms,cmd,wemo_id,policy,used_proto,request_id,response_status,outcome,elapsed_ms,retry_count,confirm_source,health_score,note)"
                      " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);";

    if (result == NULL) {
        return;
    }
    we_audit_init();
    pthread_mutex_lock(&audit_lock);
    if (audit_db == NULL) {
        pthread_mutex_unlock(&audit_lock);
        return;
    }
    if (sqlite3_prepare_v2(audit_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&audit_lock);
        return;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)we_now_ms());
    sqlite3_bind_int(stmt, 2, result->cmd);
    sqlite3_bind_int(stmt, 3, result->wemo_id);
    sqlite3_bind_int(stmt, 4, result->policy);
    sqlite3_bind_int(stmt, 5, result->used_proto);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)result->request_id);
    sqlite3_bind_int(stmt, 7, result->response_status);
    sqlite3_bind_int(stmt, 8, result->outcome);
    sqlite3_bind_int(stmt, 9, result->elapsed_ms);
    sqlite3_bind_int(stmt, 10, result->retry_count);
    sqlite3_bind_int(stmt, 11, confirm_source);
    sqlite3_bind_int(stmt, 12, health_score);
    sqlite3_bind_text(stmt, 13, note ? note : "", -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&audit_lock);
}

static void we_health_record(const struct we_device_health *health)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO device_health "
                      "(wemo_id,updated_ts_ms,health_score,timeout_streak,degraded_mode,breaker_open,breaker_remaining_ms,breaker_open_count,total_applied,total_timeouts,total_rejected,total_retries,last_retry_count,ema_applied_latency_ms,last_applied_latency_ms) "
                      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                      "ON CONFLICT(wemo_id) DO UPDATE SET "
                      "updated_ts_ms=excluded.updated_ts_ms,"
                      "health_score=excluded.health_score,"
                      "timeout_streak=excluded.timeout_streak,"
                      "degraded_mode=excluded.degraded_mode,"
                      "breaker_open=excluded.breaker_open,"
                      "breaker_remaining_ms=excluded.breaker_remaining_ms,"
                      "breaker_open_count=excluded.breaker_open_count,"
                      "total_applied=excluded.total_applied,"
                      "total_timeouts=excluded.total_timeouts,"
                      "total_rejected=excluded.total_rejected,"
                      "total_retries=excluded.total_retries,"
                      "last_retry_count=excluded.last_retry_count,"
                      "ema_applied_latency_ms=excluded.ema_applied_latency_ms,"
                      "last_applied_latency_ms=excluded.last_applied_latency_ms;";

    if (health == NULL || health->wemo_id <= 0) {
        return;
    }
    we_audit_init();
    pthread_mutex_lock(&audit_lock);
    if (audit_db == NULL) {
        pthread_mutex_unlock(&audit_lock);
        return;
    }
    if (sqlite3_prepare_v2(audit_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&audit_lock);
        return;
    }
    sqlite3_bind_int(stmt, 1, health->wemo_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)we_now_ms());
    sqlite3_bind_int(stmt, 3, health->health_score);
    sqlite3_bind_int(stmt, 4, health->timeout_streak);
    sqlite3_bind_int(stmt, 5, health->degraded_mode);
    sqlite3_bind_int(stmt, 6, health->breaker_open);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)health->breaker_remaining_ms);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)health->breaker_open_count);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)health->total_applied);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)health->total_timeouts);
    sqlite3_bind_int64(stmt, 11, (sqlite3_int64)health->total_rejected);
    sqlite3_bind_int64(stmt, 12, (sqlite3_int64)health->total_retries);
    sqlite3_bind_int(stmt, 13, health->last_retry_count);
    sqlite3_bind_int(stmt, 14, health->ema_applied_latency_ms);
    sqlite3_bind_int(stmt, 15, health->last_applied_latency_ms);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&audit_lock);
}

static const char *we_confirm_source_to_string(int source)
{
    switch (source) {
    case WE_MSG_RESPONSE:
        return "response";
    case WE_MSG_EVENT:
        return "completion";
    default:
        return "none";
    }
}

static void we_deadline_to_timespec(int64_t deadline_ms, struct timespec *ts)
{
    ts->tv_sec = deadline_ms / 1000;
    ts->tv_nsec = (deadline_ms % 1000) * 1000000;
}

static we_device_ctx_t *we_get_device_ctx(int wemo_id, int create)
{
    int i;
    we_device_ctx_t *free_slot = NULL;

    if (wemo_id <= 0) {
        return NULL;
    }

    pthread_mutex_lock(&we_device_table_lock);
    for (i = 0; i < WE_MAX_TRACKED_DEVICES; i++) {
        if (we_device_table[i].in_use && we_device_table[i].wemo_id == wemo_id) {
            pthread_mutex_unlock(&we_device_table_lock);
            return &we_device_table[i];
        }
        if (!we_device_table[i].in_use && free_slot == NULL) {
            free_slot = &we_device_table[i];
        }
    }

    if (!create || free_slot == NULL) {
        pthread_mutex_unlock(&we_device_table_lock);
        return NULL;
    }

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->in_use = 1;
    free_slot->wemo_id = wemo_id;
    pthread_mutex_init(&free_slot->lock, NULL);
    pthread_cond_init(&free_slot->cond, NULL);

    pthread_mutex_unlock(&we_device_table_lock);
    return free_slot;
}

static int we_state_matches_target(const struct we_state *actual, const struct we_state *target)
{
    if (target->state >= 0 && actual->state != target->state) {
        return 0;
    }
    if (target->level >= 0 && actual->level != target->level) {
        return 0;
    }
    return 1;
}

static int we_write_full(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, p + off, len - off, 0);
        if (n <= 0) {
            if (errno == EINTR) {
                continue;
            }
            return 0;
        }
        off += (size_t)n;
    }
    return 1;
}

static int we_read_full(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, p + off, len - off, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            return 0;
        }
        off += (size_t)n;
    }
    return 1;
}

static int we_fetch_health_snapshot_remote(int wemo_id, struct we_health_snapshot *snapshot, int max_items)
{
    int fd = -1;
    struct sockaddr_in server;
    struct we_ipc_hdr ipchdr;
    struct we_proto_hdr req_proto;
    struct we_health_query query;
    struct we_ipc_hdr rsp_ipchdr;
    char rsp_buf[IPC_DATA_MAX];
    struct we_proto_hdr *rsp_proto;
    uint32_t req_id;

    if (snapshot == NULL) {
        return WE_STATUS_INVALID;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    if (max_items <= 0 || max_items > WE_HEALTH_SNAPSHOT_MAX_ITEMS) {
        max_items = WE_HEALTH_SNAPSHOT_MAX_ITEMS;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return WE_STATUS_INTERNAL;
    }
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((uint16_t)ipc_port);
    if (inet_pton(AF_INET, ipc_host, &server.sin_addr) != 1) {
        close(fd);
        return WE_STATUS_INVALID;
    }
    if (connect(fd, (struct sockaddr *)&server, sizeof(server)) != 0) {
        close(fd);
        return WE_STATUS_INTERNAL;
    }

    memset(&query, 0, sizeof(query));
    query.wemo_id = wemo_id;
    query.max_items = max_items;

    req_id = (uint32_t)we_now_ms();
    if (req_id == 0) {
        req_id = 1;
    }
    memset(&req_proto, 0, sizeof(req_proto));
    req_proto.magic = WE_PROTO_MAGIC;
    req_proto.version = WE_PROTO_VERSION;
    req_proto.msg_type = WE_MSG_REQUEST;
    req_proto.client_id = we_client_id ? we_client_id : we_make_client_id();
    req_proto.request_id = req_id;
    req_proto.op = CMD_GET_HEALTH_SNAPSHOT;
    req_proto.wemo_id = wemo_id;
    req_proto.status = WE_STATUS_OK;
    req_proto.payload_len = sizeof(query);

    memset(&ipchdr, 0, sizeof(ipchdr));
    ipchdr.wemo_id = wemo_id;
    ipchdr.cmd = CMD_PROTO;
    ipchdr.size = sizeof(req_proto) + sizeof(query);

    if (!we_write_full(fd, &ipchdr, sizeof(ipchdr)) ||
        !we_write_full(fd, &req_proto, sizeof(req_proto)) ||
        !we_write_full(fd, &query, sizeof(query))) {
        close(fd);
        return WE_STATUS_INTERNAL;
    }
    if (!we_read_full(fd, &rsp_ipchdr, sizeof(rsp_ipchdr))) {
        close(fd);
        return WE_STATUS_INTERNAL;
    }
    if (rsp_ipchdr.size <= 0 || rsp_ipchdr.size > IPC_DATA_MAX) {
        close(fd);
        return WE_STATUS_INVALID;
    }
    if (!we_read_full(fd, rsp_buf, (size_t)rsp_ipchdr.size)) {
        close(fd);
        return WE_STATUS_INTERNAL;
    }
    close(fd);

    if (rsp_ipchdr.size < (int)sizeof(struct we_proto_hdr)) {
        return WE_STATUS_INVALID;
    }
    rsp_proto = (struct we_proto_hdr *)rsp_buf;
    if (rsp_proto->magic != WE_PROTO_MAGIC ||
        rsp_proto->version != WE_PROTO_VERSION ||
        rsp_proto->msg_type != WE_MSG_RESPONSE ||
        rsp_proto->op != CMD_GET_HEALTH_SNAPSHOT ||
        rsp_proto->status != WE_STATUS_OK) {
        return rsp_proto->status == WE_STATUS_OK ? WE_STATUS_INVALID : rsp_proto->status;
    }
    if ((int)(sizeof(struct we_proto_hdr) + rsp_proto->payload_len) > rsp_ipchdr.size) {
        return WE_STATUS_INVALID;
    }
    if (rsp_proto->payload_len < sizeof(struct we_health_snapshot)) {
        return WE_STATUS_INVALID;
    }
    memcpy(snapshot, rsp_buf + sizeof(struct we_proto_hdr), sizeof(*snapshot));
    if (snapshot->count < 0) {
        snapshot->count = 0;
    }
    if (snapshot->count > WE_HEALTH_SNAPSHOT_MAX_ITEMS) {
        snapshot->count = WE_HEALTH_SNAPSHOT_MAX_ITEMS;
    }
    return WE_STATUS_OK;
}

static int we_health_delta_significant(const struct we_device_health *before,
                                       const struct we_device_health *after)
{
    if (after == NULL) {
        return 0;
    }
    if (before == NULL) {
        return 1;
    }
    if (before->health_score != after->health_score ||
        before->timeout_streak != after->timeout_streak ||
        before->degraded_mode != after->degraded_mode ||
        before->breaker_open != after->breaker_open ||
        before->breaker_open_count != after->breaker_open_count ||
        before->total_applied != after->total_applied ||
        before->total_timeouts != after->total_timeouts ||
        before->total_rejected != after->total_rejected ||
        before->total_retries != after->total_retries ||
        before->last_retry_count != after->last_retry_count) {
        return 1;
    }
    return 0;
}

static void we_health_delta_record(const struct we_device_health *health)
{
    struct we_health_delta *slot;
    sqlite3_stmt *stmt = NULL;
    int64_t now_ms;
    int64_t cutoff_ms;
    const char *insert_sql =
        "INSERT INTO health_delta_log "
        "(ts_ms,wemo_id,health_score,timeout_streak,degraded_mode,breaker_open,breaker_open_count,total_applied,total_timeouts,total_rejected,total_retries,last_retry_count) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?);";
    const char *trim_sql =
        "DELETE FROM health_delta_log WHERE id NOT IN (SELECT id FROM health_delta_log ORDER BY id DESC LIMIT ?);";
    const char *ttl_sql = "DELETE FROM health_delta_log WHERE ts_ms < ?;";
    if (health == NULL) {
        return;
    }
    now_ms = we_now_ms();
    pthread_mutex_lock(&health_delta_lock);
    slot = &health_delta_ring[health_delta_next % WE_HEALTH_DELTA_MAX_ITEMS];
    memset(slot, 0, sizeof(*slot));
    slot->ts_ms = now_ms;
    slot->health = *health;
    health_delta_next = (health_delta_next + 1) % WE_HEALTH_DELTA_MAX_ITEMS;
    if (health_delta_count < WE_HEALTH_DELTA_MAX_ITEMS) {
        health_delta_count++;
    }
    pthread_mutex_unlock(&health_delta_lock);

    we_audit_init();
    pthread_mutex_lock(&audit_lock);
    if (audit_db == NULL) {
        pthread_mutex_unlock(&audit_lock);
        return;
    }
    if (sqlite3_prepare_v2(audit_db, insert_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now_ms);
        sqlite3_bind_int(stmt, 2, health->wemo_id);
        sqlite3_bind_int(stmt, 3, health->health_score);
        sqlite3_bind_int(stmt, 4, health->timeout_streak);
        sqlite3_bind_int(stmt, 5, health->degraded_mode);
        sqlite3_bind_int(stmt, 6, health->breaker_open);
        sqlite3_bind_int64(stmt, 7, (sqlite3_int64)health->breaker_open_count);
        sqlite3_bind_int64(stmt, 8, (sqlite3_int64)health->total_applied);
        sqlite3_bind_int64(stmt, 9, (sqlite3_int64)health->total_timeouts);
        sqlite3_bind_int64(stmt, 10, (sqlite3_int64)health->total_rejected);
        sqlite3_bind_int64(stmt, 11, (sqlite3_int64)health->total_retries);
        sqlite3_bind_int(stmt, 12, health->last_retry_count);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    } else if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }

    if (we_health_delta_max_rows > 0 &&
        sqlite3_prepare_v2(audit_db, trim_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, we_health_delta_max_rows);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    } else if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }

    if (we_health_delta_ttl_sec > 0 &&
        sqlite3_prepare_v2(audit_db, ttl_sql, -1, &stmt, NULL) == SQLITE_OK) {
        cutoff_ms = now_ms - ((int64_t)we_health_delta_ttl_sec * 1000);
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)cutoff_ms);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    } else if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&audit_lock);
}

static void we_fill_device_health_locked(const we_device_ctx_t *ctx, struct we_device_health *health_out)
{
    int64_t now_ms;

    if (ctx == NULL || health_out == NULL) {
        return;
    }
    now_ms = we_now_ms();
    memset(health_out, 0, sizeof(*health_out));
    health_out->wemo_id = ctx->wemo_id;
    health_out->health_score = ctx->health_score;
    health_out->timeout_streak = ctx->timeout_streak;
    health_out->degraded_mode = ctx->degraded_mode;
    health_out->breaker_open = (ctx->breaker_until_ms > now_ms) ? 1 : 0;
    health_out->breaker_remaining_ms =
        (ctx->breaker_until_ms > now_ms) ? (ctx->breaker_until_ms - now_ms) : 0;
    health_out->breaker_open_count = ctx->breaker_open_count;
    health_out->total_applied = ctx->total_applied;
    health_out->total_timeouts = ctx->total_timeouts;
    health_out->total_rejected = ctx->total_rejected;
    health_out->total_retries = ctx->total_retries;
    health_out->last_retry_count = ctx->last_retry_count;
    health_out->ema_applied_latency_ms = ctx->ema_applied_latency_ms;
    health_out->last_applied_latency_ms = ctx->last_applied_latency_ms;
}

static int we_fill_health_from_stmt(sqlite3_stmt *stmt, struct we_device_health *health_out)
{
    if (stmt == NULL || health_out == NULL) {
        return 0;
    }
    memset(health_out, 0, sizeof(*health_out));
    health_out->wemo_id = sqlite3_column_int(stmt, 0);
    health_out->health_score = sqlite3_column_int(stmt, 1);
    health_out->timeout_streak = sqlite3_column_int(stmt, 2);
    health_out->degraded_mode = sqlite3_column_int(stmt, 3);
    health_out->breaker_open = sqlite3_column_int(stmt, 4);
    health_out->breaker_remaining_ms = (int64_t)sqlite3_column_int64(stmt, 5);
    health_out->breaker_open_count = (uint32_t)sqlite3_column_int(stmt, 6);
    health_out->total_applied = (uint32_t)sqlite3_column_int(stmt, 7);
    health_out->total_timeouts = (uint32_t)sqlite3_column_int(stmt, 8);
    health_out->total_rejected = (uint32_t)sqlite3_column_int(stmt, 9);
    health_out->total_retries = (uint32_t)sqlite3_column_int(stmt, 10);
    health_out->last_retry_count = sqlite3_column_int(stmt, 11);
    health_out->ema_applied_latency_ms = sqlite3_column_int(stmt, 12);
    health_out->last_applied_latency_ms = sqlite3_column_int(stmt, 13);
    return 1;
}

static int we_get_device_health_from_db(int wemo_id, struct we_device_health *health_out)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT wemo_id,health_score,timeout_streak,degraded_mode,breaker_open,breaker_remaining_ms,breaker_open_count,total_applied,total_timeouts,total_rejected,total_retries,last_retry_count,ema_applied_latency_ms,last_applied_latency_ms "
                      "FROM device_health WHERE wemo_id=?;";
    int rc = WE_STATUS_INVALID;

    if (wemo_id <= 0 || health_out == NULL) {
        return WE_STATUS_INVALID;
    }
    we_audit_init();
    pthread_mutex_lock(&audit_lock);
    if (audit_db == NULL) {
        pthread_mutex_unlock(&audit_lock);
        return WE_STATUS_INVALID;
    }
    if (sqlite3_prepare_v2(audit_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, wemo_id);
        if (sqlite3_step(stmt) == SQLITE_ROW && we_fill_health_from_stmt(stmt, health_out)) {
            rc = WE_STATUS_OK;
        }
    }
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&audit_lock);
    return rc;
}

static int we_get_health_snapshot_from_db(struct we_device_health *health_out, int max_items)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT wemo_id,health_score,timeout_streak,degraded_mode,breaker_open,breaker_remaining_ms,breaker_open_count,total_applied,total_timeouts,total_rejected,total_retries,last_retry_count,ema_applied_latency_ms,last_applied_latency_ms "
                      "FROM device_health ORDER BY wemo_id ASC LIMIT ?;";
    int count = 0;

    if (health_out == NULL || max_items <= 0) {
        return WE_STATUS_INVALID;
    }
    we_audit_init();
    pthread_mutex_lock(&audit_lock);
    if (audit_db == NULL) {
        pthread_mutex_unlock(&audit_lock);
        return WE_STATUS_INVALID;
    }
    if (sqlite3_prepare_v2(audit_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&audit_lock);
        return WE_STATUS_INVALID;
    }
    sqlite3_bind_int(stmt, 1, max_items);
    while (count < max_items && sqlite3_step(stmt) == SQLITE_ROW) {
        if (!we_fill_health_from_stmt(stmt, &health_out[count])) {
            break;
        }
        count++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&audit_lock);
    return count;
}

int we_get_device_health(int wemo_id, struct we_device_health *health_out)
{
    we_device_ctx_t *ctx = NULL;
    struct we_health_snapshot remote;

    if (wemo_id <= 0 || health_out == NULL) {
        return WE_STATUS_INVALID;
    }
    ctx = we_get_device_ctx(wemo_id, 0);
    if (ctx == NULL) {
        if (we_get_device_health_from_db(wemo_id, health_out) == WE_STATUS_OK) {
            return WE_STATUS_OK;
        }
        if (we_fetch_health_snapshot_remote(wemo_id, &remote, 1) == WE_STATUS_OK && remote.count > 0) {
            *health_out = remote.items[0];
            return WE_STATUS_OK;
        }
        memset(health_out, 0, sizeof(*health_out));
        health_out->wemo_id = wemo_id;
        return WE_STATUS_INVALID;
    }
    pthread_mutex_lock(&ctx->lock);
    we_fill_device_health_locked(ctx, health_out);
    pthread_mutex_unlock(&ctx->lock);
    return WE_STATUS_OK;
}

int we_get_device_health_snapshot(struct we_device_health *health_out, int max_items)
{
    int i;
    int count = 0;

    if (health_out == NULL || max_items <= 0) {
        return WE_STATUS_INVALID;
    }

    pthread_mutex_lock(&we_device_table_lock);
    for (i = 0; i < WE_MAX_TRACKED_DEVICES && count < max_items; i++) {
        we_device_ctx_t *ctx = &we_device_table[i];
        if (!ctx->in_use) {
            continue;
        }
        pthread_mutex_lock(&ctx->lock);
        we_fill_device_health_locked(ctx, &health_out[count]);
        pthread_mutex_unlock(&ctx->lock);
        count++;
    }
    pthread_mutex_unlock(&we_device_table_lock);
    if (count == 0) {
        count = we_get_health_snapshot_from_db(health_out, max_items);
        if (count > 0) {
            return count;
        }
        return we_get_device_health_snapshot_remote(0, health_out, max_items);
    }
    return count;
}

int we_get_device_health_snapshot_remote(int wemo_id, struct we_device_health *health_out, int max_items)
{
    struct we_health_snapshot snapshot;
    int count;
    int i;

    if (health_out == NULL || max_items <= 0) {
        return WE_STATUS_INVALID;
    }
    if (max_items > WE_HEALTH_SNAPSHOT_MAX_ITEMS) {
        max_items = WE_HEALTH_SNAPSHOT_MAX_ITEMS;
    }
    if (we_fetch_health_snapshot_remote(wemo_id, &snapshot, max_items) != WE_STATUS_OK) {
        return WE_STATUS_INTERNAL;
    }
    count = snapshot.count;
    if (count > max_items) {
        count = max_items;
    }
    for (i = 0; i < count; i++) {
        health_out[i] = snapshot.items[i];
    }
    return count;
}

int we_get_health_deltas(struct we_health_delta *out, int max_items)
{
    int n;
    int i;
    int start;
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT ts_ms,wemo_id,health_score,timeout_streak,degraded_mode,breaker_open,breaker_open_count,total_applied,total_timeouts,total_rejected,total_retries,last_retry_count "
        "FROM health_delta_log ORDER BY id DESC LIMIT ?;";

    if (out == NULL || max_items <= 0) {
        return WE_STATUS_INVALID;
    }
    if (max_items > WE_HEALTH_DELTA_MAX_ITEMS) {
        max_items = WE_HEALTH_DELTA_MAX_ITEMS;
    }

    pthread_mutex_lock(&health_delta_lock);
    n = health_delta_count;
    if (n > max_items) {
        n = max_items;
    }
    start = (health_delta_next - n + WE_HEALTH_DELTA_MAX_ITEMS) % WE_HEALTH_DELTA_MAX_ITEMS;
    for (i = 0; i < n; i++) {
        out[i] = health_delta_ring[(start + i) % WE_HEALTH_DELTA_MAX_ITEMS];
    }
    pthread_mutex_unlock(&health_delta_lock);
    if (n > 0) {
        return n;
    }

    we_audit_init();
    pthread_mutex_lock(&audit_lock);
    if (audit_db == NULL) {
        pthread_mutex_unlock(&audit_lock);
        return 0;
    }
    if (sqlite3_prepare_v2(audit_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&audit_lock);
        return 0;
    }
    sqlite3_bind_int(stmt, 1, max_items);
    while (n < max_items && sqlite3_step(stmt) == SQLITE_ROW) {
        struct we_health_delta d;
        memset(&d, 0, sizeof(d));
        d.ts_ms = (int64_t)sqlite3_column_int64(stmt, 0);
        d.health.wemo_id = sqlite3_column_int(stmt, 1);
        d.health.health_score = sqlite3_column_int(stmt, 2);
        d.health.timeout_streak = sqlite3_column_int(stmt, 3);
        d.health.degraded_mode = sqlite3_column_int(stmt, 4);
        d.health.breaker_open = sqlite3_column_int(stmt, 5);
        d.health.breaker_open_count = (uint32_t)sqlite3_column_int(stmt, 6);
        d.health.total_applied = (uint32_t)sqlite3_column_int(stmt, 7);
        d.health.total_timeouts = (uint32_t)sqlite3_column_int(stmt, 8);
        d.health.total_rejected = (uint32_t)sqlite3_column_int(stmt, 9);
        d.health.total_retries = (uint32_t)sqlite3_column_int(stmt, 10);
        d.health.last_retry_count = sqlite3_column_int(stmt, 11);
        out[n++] = d;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&audit_lock);
    for (i = 0; i < n / 2; i++) {
        struct we_health_delta tmp = out[i];
        out[i] = out[n - i - 1];
        out[n - i - 1] = tmp;
    }
    return n;
}

int we_bridge_preflight_device(int wemo_id, struct we_bridge_preflight_result *out)
{
    struct we_device_health health;
    int is_online = 0;
    int health_rc;
    int online_rc;

    if (wemo_id <= 0 || out == NULL) {
        return WE_STATUS_INVALID;
    }
    memset(out, 0, sizeof(*out));
    out->wemo_id = wemo_id;

    health_rc = we_get_device_health(wemo_id, &health);
    online_rc = we_get_online_state_from_db(wemo_id, &is_online);
    out->is_online = (online_rc == WE_STATUS_OK) ? is_online : 0;
    if (health_rc == WE_STATUS_OK) {
        out->health_score = health.health_score;
        out->timeout_streak = health.timeout_streak;
        out->breaker_open = health.breaker_open;
        out->total_applied = health.total_applied;
        out->total_timeouts = health.total_timeouts;
    }

    if (health_rc != WE_STATUS_OK) {
        out->ready = 0;
        return WE_STATUS_OK;
    }
    if (!out->is_online) {
        out->ready = 0;
        return WE_STATUS_OK;
    }
    if (health.breaker_open || health.timeout_streak > 0 || health.health_score > 2) {
        out->ready = 0;
        return WE_STATUS_OK;
    }
    if (health.total_applied < 2) {
        out->ready = 0;
        return WE_STATUS_OK;
    }
    out->ready = 1;
    return WE_STATUS_OK;
}

int we_default_confirm_policy_for_cmd(int cmd)
{
    switch (cmd) {
    case CMD_SET:
        return WE_CONFIRM_STATE_MATCH;
    case CMD_GET:
    case CMD_SETUP:
    case CMD_CONNECTION_STATE:
    case CMD_CLOSESETUP:
    case CMD_DELETE:
    case CMD_DISCOVER:
    case CMD_FIRMWARE_UPDATE:
    case CMD_SET_HKSETUP_STATE:
    case CMD_CHANGE_NAME:
    case CMD_NAME_VALUE:
    case CMD_RESET:
    case CMD_RESTART_RULE:
    case CMD_GET_DEVINFO:
    case CMD_GET_INSIGHTHOME_SETTINGS:
    case CMD_SET_INSIGHTHOME_SETTINGS:
    case CMD_GET_INSIGHT_PARAMS:
    case CMD_SET_POWER_THRESHOLD:
    case CMD_GET_POWER_THRESHOLD:
    case CMD_GET_DATA_EXPORTINFO:
    case CMD_SCHEDULE_DATA_EXPORT:
    case CMD_FORGET:
    case CMD_GET_HEALTH_SNAPSHOT:
        return WE_CONFIRM_RESPONSE;
    default:
        return WE_CONFIRM_NONE;
    }
}

static int we_wait_for_request_locked(we_device_ctx_t *ctx, uint32_t request_id, int64_t deadline_ms,
                                      int *status_out, int *source_out, int *outcome_out)
{
    while (1) {
        int64_t now_ms = we_now_ms();
        struct timespec ts;
        int rc;

        if (ctx->pending_response_ready && ctx->pending_request_id == request_id) {
            if (status_out != NULL) {
                *status_out = ctx->pending_status;
            }
            if (source_out != NULL) {
                *source_out = WE_MSG_RESPONSE;
            }
            if (outcome_out != NULL) {
                *outcome_out = WE_BROKER_OUTCOME_APPLIED;
            }
            return 1;
        }
        if (ctx->last_response_valid && ctx->last_response_request_id == request_id) {
            if (status_out != NULL) {
                *status_out = ctx->last_response_status;
            }
            if (source_out != NULL) {
                *source_out = WE_MSG_RESPONSE;
            }
            if (outcome_out != NULL) {
                *outcome_out = WE_BROKER_OUTCOME_APPLIED;
            }
            return 1;
        }
        if (ctx->pending_completion_ready && ctx->pending_completion_request_id == request_id) {
            if (status_out != NULL) {
                *status_out = ctx->pending_completion_status;
            }
            if (source_out != NULL) {
                *source_out = WE_MSG_EVENT;
            }
            if (outcome_out != NULL) {
                *outcome_out = ctx->pending_completion_outcome;
            }
            return 1;
        }
        if (ctx->last_completion_valid && ctx->last_completion_request_id == request_id) {
            if (status_out != NULL) {
                *status_out = ctx->last_completion_status;
            }
            if (source_out != NULL) {
                *source_out = WE_MSG_EVENT;
            }
            if (outcome_out != NULL) {
                *outcome_out = ctx->last_completion_outcome;
            }
            return 1;
        }
        if (now_ms >= deadline_ms) {
            return 0;
        }
        we_deadline_to_timespec(deadline_ms, &ts);
        rc = pthread_cond_timedwait(&ctx->cond, &ctx->lock, &ts);
        if (rc != 0 && rc != EINTR && rc != ETIMEDOUT) {
            return 0;
        }
    }
}

int we_run_command_txn(int cmd, int wemo_id, const void *payload, int payload_len,
                       const struct we_state *target_state, int timeout_ms, int policy,
                       struct we_txn_result *result_out)
{
    we_device_ctx_t *ctx = NULL;
    int64_t start_ms = we_now_ms();
    int64_t deadline_ms = start_ms + timeout_ms;
    int64_t next_poll_ms = start_ms + WE_CONFIRM_WAIT_SLICE_MS;
    int effective_timeout_ms = timeout_ms;
    int used_proto = 0;
    int response_status = WE_STATUS_OK;
    int response_source = 0;
    int completion_outcome = WE_BROKER_OUTCOME_APPLIED;
    uint32_t request_id = 0;
    int get_retry_used = 0;
    int probe_success_count = 0;
    int retry_count = 0;
    int health_score_snapshot = 0;
    struct we_device_health health_before;
    int have_health_before = 0;
    struct we_device_health health_snapshot;
    int have_health_snapshot = 0;
    const char *audit_note = "";
    struct we_state query_state;
    int wait_ok = 1;
    int rc = WE_STATUS_OK;
    struct we_txn_result result;

    memset(&result, 0, sizeof(result));
    result.cmd = cmd;
    result.wemo_id = wemo_id;
    result.policy = policy;
    result.response_status = WE_STATUS_OK;
    result.outcome = WE_TXN_SEND_FAILED;
    result.retry_count = 0;

    if (timeout_ms <= 0) {
        timeout_ms = 1000;
        deadline_ms = start_ms + timeout_ms;
    }
    if (policy == WE_CONFIRM_STATE_MATCH && target_state == NULL) {
        result.outcome = WE_TXN_MISMATCH;
        result.response_status = WE_STATUS_INVALID;
        rc = WE_STATUS_INVALID;
        goto done;
    }

    ctx = we_get_device_ctx(wemo_id, 1);
    if (ctx == NULL) {
        result.outcome = WE_TXN_SEND_FAILED;
        result.response_status = WE_STATUS_INTERNAL;
        rc = WE_STATUS_INTERNAL;
        goto done;
    }

    memset(&query_state, 0, sizeof(query_state));
    pthread_mutex_lock(&ctx->lock);
    if (we_circuit_breaker_enabled && ctx->breaker_until_ms > 0 && we_now_ms() < ctx->breaker_until_ms) {
        if (cmd != CMD_GET) {
            int64_t remaining_ms = ctx->breaker_until_ms - we_now_ms();
            uint32_t open_count = ctx->breaker_open_count;
            int timeout_streak = ctx->timeout_streak;
            if (remaining_ms < 0) {
                remaining_ms = 0;
            }
            pthread_mutex_unlock(&ctx->lock);
            result.outcome = WE_TXN_REJECTED;
            result.response_status = WE_STATUS_INTERNAL;
            audit_note = "circuit_open";
            rc = WE_STATUS_INTERNAL;
            if (we_txn_trace) {
                fprintf(stderr,
                        "txn_trace: cmd=%d wemo_id=%d circuit_open remaining_ms=%lld open_count=%u timeout_streak=%d\n",
                        cmd,
                        wemo_id,
                        (long long)remaining_ms,
                        open_count,
                        timeout_streak);
            }
            goto done;
        }
        audit_note = "circuit_probe";
    }
    effective_timeout_ms = we_effective_timeout_ms_locked(ctx, cmd, policy, timeout_ms);
    deadline_ms = start_ms + effective_timeout_ms;
    if (next_poll_ms > deadline_ms) {
        next_poll_ms = deadline_ms;
    }
    if (we_txn_trace && effective_timeout_ms != timeout_ms) {
        fprintf(stderr,
                "txn_trace: cmd=%d wemo_id=%d adaptive_timeout base_ms=%d effective_ms=%d timeout_streak=%d health=%d ema_ms=%d degraded=%d\n",
                cmd,
                wemo_id,
                timeout_ms,
                effective_timeout_ms,
                ctx->timeout_streak,
                ctx->health_score,
                ctx->ema_applied_latency_ms,
                ctx->degraded_mode);
    }

    if (!we_send_command_ex(cmd, wemo_id, payload, payload_len, &request_id, &used_proto)) {
        pthread_mutex_unlock(&ctx->lock);
        result.outcome = WE_TXN_SEND_FAILED;
        result.response_status = WE_STATUS_INTERNAL;
        rc = WE_STATUS_INTERNAL;
        goto done;
    }
    result.request_id = request_id;
    result.used_proto = used_proto;
    result.outcome = WE_TXN_ACCEPTED;

    if (policy == WE_CONFIRM_NONE) {
        pthread_mutex_unlock(&ctx->lock);
        rc = WE_STATUS_OK;
        goto done;
    }

    if (used_proto) {
wait_for_proto_confirmation:
        ctx->pending_request_id = request_id;
        ctx->pending_response_ready = 0;
        ctx->pending_completion_request_id = request_id;
        ctx->pending_completion_ready = 0;
        wait_ok = we_wait_for_request_locked(ctx, request_id, deadline_ms,
                                             &response_status, &response_source, &completion_outcome);
        if (!wait_ok && policy == WE_CONFIRM_RESPONSE && cmd == CMD_GET &&
            get_retry_used < we_get_retry_max &&
            we_now_ms() < deadline_ms) {
            uint32_t retry_request_id = 0;
            int retry_used_proto = used_proto;
            get_retry_used++;
            retry_count++;
            pthread_mutex_unlock(&ctx->lock);
            we_retry_jitter_sleep();
            pthread_mutex_lock(&ctx->lock);
            if (we_send_command_ex(cmd, wemo_id, payload, payload_len, &retry_request_id, &retry_used_proto) &&
                retry_used_proto && retry_request_id != 0) {
                request_id = retry_request_id;
                result.request_id = request_id;
                if (we_txn_trace) {
                    fprintf(stderr, "txn_trace: cmd=%d wemo_id=%d get_retry=%d request_id=%u\n",
                            cmd, wemo_id, get_retry_used, request_id);
                }
                goto wait_for_proto_confirmation;
            }
        }
        if (!wait_ok && policy == WE_CONFIRM_RESPONSE) {
            pthread_mutex_unlock(&ctx->lock);
            result.outcome = WE_TXN_TIMEOUT;
            result.response_status = WE_STATUS_INTERNAL;
            rc = WE_STATUS_INTERNAL;
            goto done;
        }
        if (wait_ok) {
            result.response_status = response_status;
        } else {
            result.response_status = WE_STATUS_INTERNAL;
        }
        if (wait_ok && response_source == WE_MSG_EVENT &&
            (completion_outcome == WE_BROKER_OUTCOME_FAILED ||
             completion_outcome == WE_BROKER_OUTCOME_TIMEOUT ||
             completion_outcome == WE_BROKER_OUTCOME_MISMATCH)) {
            pthread_mutex_unlock(&ctx->lock);
            result.outcome = WE_TXN_REJECTED;
            rc = (response_status == WE_STATUS_OK) ? WE_STATUS_INTERNAL : response_status;
            goto done;
        }
        if (wait_ok && response_status != WE_STATUS_OK) {
            pthread_mutex_unlock(&ctx->lock);
            result.outcome = WE_TXN_REJECTED;
            rc = response_status;
            goto done;
        }
    }

    if (policy == WE_CONFIRM_RESPONSE) {
        pthread_mutex_unlock(&ctx->lock);
        result.outcome = WE_TXN_APPLIED;
        rc = WE_STATUS_OK;
        goto done;
    }

    while (1) {
        int64_t now_ms = we_now_ms();
        int64_t wait_until_ms;
        struct timespec ts;
        int wait_rc;

        if (ctx->last_state_valid) {
            result.final_state_valid = 1;
            result.final_state = ctx->last_state;
            if (we_state_matches_target(&ctx->last_state, target_state)) {
                pthread_mutex_unlock(&ctx->lock);
                result.outcome = WE_TXN_APPLIED;
                rc = WE_STATUS_OK;
                goto done;
            }
        }
        if (now_ms >= deadline_ms) {
            pthread_mutex_unlock(&ctx->lock);
            result.outcome = WE_TXN_TIMEOUT;
            rc = WE_STATUS_INTERNAL;
            goto done;
        }

        wait_until_ms = next_poll_ms;
        if (wait_until_ms > deadline_ms) {
            wait_until_ms = deadline_ms;
        }
        we_deadline_to_timespec(wait_until_ms, &ts);
        wait_rc = pthread_cond_timedwait(&ctx->cond, &ctx->lock, &ts);
        if (wait_rc == ETIMEDOUT || we_now_ms() >= next_poll_ms) {
            uint32_t probe_req_id = 0;
            int probe_used_proto = 0;
            int probe_status = WE_STATUS_INTERNAL;
            int probe_source = 0;
            int probe_outcome = WE_BROKER_OUTCOME_APPLIED;
            int64_t probe_deadline = we_now_ms() + 1500;
            int probe_wait_ok = 0;
            int probe_attempt;

            if (probe_deadline > deadline_ms) {
                probe_deadline = deadline_ms;
            }
            for (probe_attempt = 0; probe_attempt <= we_probe_retry_max; probe_attempt++) {
                if (probe_attempt > 0) {
                    retry_count++;
                    pthread_mutex_unlock(&ctx->lock);
                    we_retry_jitter_sleep();
                    pthread_mutex_lock(&ctx->lock);
                }
                if (we_send_command_ex(CMD_GET, wemo_id, &query_state, sizeof(struct we_state),
                                       &probe_req_id, &probe_used_proto) &&
                    probe_used_proto && probe_req_id != 0 && probe_deadline > we_now_ms()) {
                    probe_wait_ok = we_wait_for_request_locked(ctx,
                                                               probe_req_id,
                                                               probe_deadline,
                                                               &probe_status,
                                                               &probe_source,
                                                               &probe_outcome);
                    if (probe_wait_ok && probe_status == WE_STATUS_OK) {
                        probe_success_count++;
                        break;
                    }
                }
            }

            if (cmd == CMD_SET &&
                response_status == WE_STATUS_OK &&
                (completion_outcome == WE_BROKER_OUTCOME_APPLIED || completion_outcome == WE_BROKER_OUTCOME_QUEUED)) {
                int relaxed_ok = 0;
                int probe_threshold = ctx->degraded_mode ? WE_DIMMER_PROBE_STRONG : WE_DIMMER_PROBE_WEAK;
                if (ctx->last_state_valid) {
                    if (we_state_matches_target_relaxed(&ctx->last_state, target_state)) {
                        relaxed_ok = 1;
                    }
                } else if (probe_success_count >= probe_threshold) {
                    relaxed_ok = 1;
                }
                if (relaxed_ok) {
                    pthread_mutex_unlock(&ctx->lock);
                    result.outcome = WE_TXN_APPLIED;
                    audit_note = "adaptive_set_confirm";
                    rc = WE_STATUS_OK;
                    goto done;
                }
            }
            next_poll_ms = we_now_ms() + WE_CONFIRM_WAIT_SLICE_MS;
        } else if (wait_rc != 0 && wait_rc != EINTR) {
            pthread_mutex_unlock(&ctx->lock);
            result.outcome = WE_TXN_TIMEOUT;
            result.response_status = WE_STATUS_INTERNAL;
            rc = WE_STATUS_INTERNAL;
            goto done;
        }
    }

done:
    result.elapsed_ms = (int)(we_now_ms() - start_ms);
    result.retry_count = retry_count;
    if (ctx != NULL) {
        pthread_mutex_lock(&ctx->lock);
        we_fill_device_health_locked(ctx, &health_before);
        have_health_before = 1;
        we_health_update_locked(ctx, &result);
        health_score_snapshot = ctx->health_score;
        we_fill_device_health_locked(ctx, &health_snapshot);
        have_health_snapshot = 1;
        pthread_mutex_unlock(&ctx->lock);
    }
    we_audit_record(&result, response_source, health_score_snapshot, audit_note);
    if (have_health_snapshot) {
        we_health_record(&health_snapshot);
        if (we_health_delta_significant(have_health_before ? &health_before : NULL, &health_snapshot)) {
            we_health_delta_record(&health_snapshot);
            if (we_callback.health_callback) {
                we_callback.health_callback(health_snapshot.wemo_id, &health_snapshot);
            }
        }
    }
    if (we_txn_trace) {
        fprintf(stderr,
                "txn_trace: cmd=%d wemo_id=%d request_id=%u policy=%d source=%s status=%d outcome=%d elapsed_ms=%d retries=%d used_proto=%d health=%d probes=%d note=%s\n",
                cmd,
                wemo_id,
                result.request_id,
                policy,
                we_confirm_source_to_string(response_source),
                result.response_status,
                result.outcome,
                result.elapsed_ms,
                result.retry_count,
                result.used_proto,
                health_score_snapshot,
                probe_success_count,
                audit_note);
    }
    if (result_out != NULL) {
        *result_out = result;
    }
    return rc;
}

static void we_configure_protocol_mode(void)
{
    const char *env_proto = getenv("WEMO_ENGINE_PROTO");
    const char *env_fallback = getenv("WEMO_ENGINE_PROTO_FALLBACK");

    if (env_proto != NULL && env_proto[0] != '\0') {
        we_proto_enabled = atoi(env_proto) != 0;
    }
    if (env_fallback != NULL && env_fallback[0] != '\0') {
        we_proto_legacy_fallback = atoi(env_fallback) != 0;
    }
    if (getenv("WEMO_ENGINE_TXN_TRACE") != NULL) {
        we_txn_trace = atoi(getenv("WEMO_ENGINE_TXN_TRACE")) != 0;
    }
    if (getenv("WEMO_ENGINE_ADAPTIVE_TIMEOUT") != NULL) {
        we_adaptive_timeout = atoi(getenv("WEMO_ENGINE_ADAPTIVE_TIMEOUT")) != 0;
    }
    if (getenv("WEMO_ENGINE_CIRCUIT_BREAKER") != NULL) {
        we_circuit_breaker_enabled = atoi(getenv("WEMO_ENGINE_CIRCUIT_BREAKER")) != 0;
    }
    if (getenv("WEMO_ENGINE_GET_RETRY_MAX") != NULL) {
        int v = atoi(getenv("WEMO_ENGINE_GET_RETRY_MAX"));
        if (v >= 0 && v <= 5) {
            we_get_retry_max = v;
        }
    }
    if (getenv("WEMO_ENGINE_PROBE_RETRY_MAX") != NULL) {
        int v = atoi(getenv("WEMO_ENGINE_PROBE_RETRY_MAX"));
        if (v >= 0 && v <= 5) {
            we_probe_retry_max = v;
        }
    }
    if (getenv("WEMO_ENGINE_RETRY_JITTER_MS") != NULL) {
        int v = atoi(getenv("WEMO_ENGINE_RETRY_JITTER_MS"));
        if (v >= 0 && v <= 1000) {
            we_retry_jitter_max_ms = v;
        }
    }
    if (getenv("WEMO_HEALTH_DELTA_TTL_SEC") != NULL) {
        int v = atoi(getenv("WEMO_HEALTH_DELTA_TTL_SEC"));
        if (v >= 60 && v <= 604800) {
            we_health_delta_ttl_sec = v;
        }
    }
    if (getenv("WEMO_HEALTH_DELTA_MAX_ROWS") != NULL) {
        int v = atoi(getenv("WEMO_HEALTH_DELTA_MAX_ROWS"));
        if (v >= WE_HEALTH_DELTA_MAX_ITEMS && v <= 100000) {
            we_health_delta_max_rows = v;
        }
    }
}

static char *getFirstDocumentItem(IXML_Document *doc, const char *item)
{
	IXML_NodeList *nodeList = NULL;
	IXML_Node *textNode = NULL;
	IXML_Node *tmpNode = NULL;
	char *ret = NULL;

	nodeList = ixmlDocument_getElementsByTagName(doc, (char *)item);
	if (nodeList) {
		tmpNode = ixmlNodeList_item(nodeList, 0);
		if (tmpNode) {
			textNode = ixmlNode_getFirstChild(tmpNode);
			if (!textNode) {
				ret = strdup("");
				goto epilogue;
			}
			if (!ixmlNode_getNodeValue(textNode)) {
				ret = strdup("");
				goto epilogue;
			} else {
				ret = strdup(ixmlNode_getNodeValue(textNode));
			}
		} else {
			goto epilogue;
		}
	}

epilogue:
	if (nodeList) {
		ixmlNodeList_free(nodeList);
	}

	return ret;
}

static int we_handleGetInformationResult(char *result, struct we_dev_information *info)
{
    IXML_Document *Device = NULL;
    char *result_item = NULL;

    Device = ixmlParseBuffer(result);

    memset(info, 0, sizeof(struct we_dev_information));
    if ((result_item = getFirstDocumentItem(Device, "firmwareVersion"))) {
        /* string */
        printf("%s: firmwareVersion : %s\n", __FUNCTION__, result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "iconVersion"))) {
        /* integer */
        printf("%s: : iconVersion : %s\n", __FUNCTION__, result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "iconPort"))) {
        /* integer */
        printf("%s: : iconPort : %s\n", __FUNCTION__, result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "macAddress"))) {
        /* string */
        printf("%s: : macAddress : %s\n", __FUNCTION__, result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "binaryState"))) {
        /* integer */
        printf("%s: : binaryState : %s\n", __FUNCTION__, result_item);
        info->binaryState = atoi(result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "hwVersion"))) {
        /* integer */
        printf("%s: : hwVersion : %s\n", __FUNCTION__, result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "deviceCurrentTime"))) {
        /* long integer */
        printf("%s: : deviceCurrentTime : %s\n", __FUNCTION__, result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "productName"))) {
        /* string */
        printf("%s: : productName : %s\n", __FUNCTION__, result_item);
        if (strlen(result_item)) {
            info->productName = result_item;
        }
        else {
            free(result_item);
        }
    }
    if ((result_item = getFirstDocumentItem(Device, "FriendlyName"))) {
        /* string */
        printf("%s: : FriendlyName : %s\n", __FUNCTION__, result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "currentFWUpdateState"))) {
        /* integer */
        printf("%s: : currentFWUpdateState : %s\n", __FUNCTION__, result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "brightness"))) {
        /* integer */
        printf("%s: : brightness : %s\n", __FUNCTION__, result_item);
        info->brightness = atoi(result_item);
        free(result_item);
    }
    else {
        printf("%s: : not a dimmer, brightness : -1\n", __FUNCTION__);
        info->brightness = -1;
    }
    if ((result_item = getFirstDocumentItem(Device, "fader"))) {
        /* string */
        printf("%s: : fader : %s\n", __FUNCTION__, result_item);
        if (strlen(result_item)) {
            info->fader = result_item;
        }
        else {
            free(result_item);
        }
    }
    if ((result_item = getFirstDocumentItem(Device, "OverTemp"))) {
        /* integer */
        printf("%s: : OverTemp : %s\n", __FUNCTION__, result_item);
        info->OverTemp = atoi(result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "nightMode"))) {
        /* integer */
        printf("%s: : nightMode : %s\n", __FUNCTION__, result_item);
        info->nightMode = atoi(result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "startTime"))) {
        /* long integer */
        printf("%s: : startTime : %s\n", __FUNCTION__, result_item);
        info->startTime = atol(result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "endTime"))) {
        /* long integer */
        printf("%s: : endTime : %s\n", __FUNCTION__, result_item);
        info->endTime = atol(result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "nightModeBrightness"))) {
        /* integer */
        printf("%s: : nightModeBrightness : %s\n", __FUNCTION__, result_item);
        info->nightModeBrightness = atoi(result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "CountdownEndTime"))) {
        /* long integer */
        printf("%s: : CountdownEndTime : %s\n", __FUNCTION__, result_item);
        info->CountdownEndTime = atol(result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "longPressRuleDeviceCnt"))) {
        /* integer */
        printf("%s: : longPressRuleDeviceCnt : %s\n", __FUNCTION__, result_item);
        info->longPressRuleDeviceCnt = atoi(result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "longPressRuleDeviceUdn"))) {
        /* string */
        printf("%s: : longPressRuleDeviceUdn : %s\n", __FUNCTION__, result_item);
        if (strlen(result_item)) {
            info->longPressRuleDeviceUdn = result_item;
        }
        else {
            free(result_item);
        }
    }
    if ((result_item = getFirstDocumentItem(Device, "longPressRuleAction"))) {
        /* integer */
        printf("%s: : longPressRuleAction : %s\n", __FUNCTION__, result_item);
        info->longPressRuleAction = atoi(result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "longPressRuleState"))) {
        /* integer */
        printf("%s: : longPressRuleState : %s\n", __FUNCTION__, result_item);
        info->longPressRuleState = atoi(result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "dbVersion"))) {
        /* integer */
        printf("%s: : dbVersion : %s\n", __FUNCTION__, result_item);
        free(result_item);
    }
    if ((result_item = getFirstDocumentItem(Device, "hushMode"))) {
        /* string */
        printf("%s: : hushMode : %s\n", __FUNCTION__, result_item);
        if (strlen(result_item)) {
            info->hushMode = result_item;
        }
        else {
            free(result_item);
        }
    }

    if (Device)
        ixmlDocument_free(Device);

    return 0;
}

void *we_comm_task(void *args)
{
    fd_set rfds;
    int fd = -1;
    int retval;
    ssize_t result = 0;
    struct we_ipc_hdr ipchdr;
    char ipc_data[IPC_DATA_MAX + 1];

    while(1) {
        pthread_mutex_lock(&socket_lock);
        fd = socket_fd;
        pthread_mutex_unlock(&socket_lock);
        if (fd < 0) {
            break;
        }

        do {
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);

            retval = select(fd + 1, &rfds, NULL, NULL, NULL);
        } while (retval == -1 && errno == EINTR);
        if (retval > 0) {
            if (FD_ISSET(fd, &rfds)) {
                /* fd has data available to be read */
                size_t expected = sizeof(struct we_ipc_hdr);
                size_t offset = 0;
                while (offset < expected) {
                    result = recv(fd, ((char *) &ipchdr) + offset, expected - offset, 0);
                    if (result <= 0) {
                        goto thr_exit;
                    }
                    offset += (size_t) result;
                }
                if (result == 0) {
                    /* This means the other side closed the socket */
                    goto thr_exit;
                }
                if (ipchdr.size < 0 || ipchdr.size > IPC_DATA_MAX) {
                    fprintf(stderr, "Invalid ipc_data size (%d)\n", ipchdr.size);
                    continue;
                }
                if (ipchdr.size > 0) {
                    expected = (size_t) ipchdr.size;
                    offset = 0;
                    while (offset < expected) {
                        result = recv(fd, ipc_data + offset, expected - offset, 0);
                        if (result <= 0) {
                            goto thr_exit;
                        }
                        offset += (size_t) result;
                    }
                }
                switch(ipchdr.cmd) {
                case EVENT_SETUP:
                    break;
                case EVENT_CONNECTION_STATE:
                    if (ipchdr.size < (int) sizeof(struct we_network_status)) {
                        fprintf(stderr, "EVENT_CONNECTION_STATE payload too short (%d)\n", ipchdr.size);
                        break;
                    }
                    if (we_callback.netstate_callback)
                        we_callback.netstate_callback(ipchdr.wemo_id, (struct we_network_status *)ipc_data);
                    break;
                case EVENT_STATE:
                    if (ipchdr.size < (int) sizeof(struct we_state)) {
                        fprintf(stderr, "EVENT_STATE payload too short (%d)\n", ipchdr.size);
                        break;
                    }
                    {
                        we_device_ctx_t *ctx = we_get_device_ctx(ipchdr.wemo_id, 1);
                        if (ctx != NULL) {
                            pthread_mutex_lock(&ctx->lock);
                            ctx->last_state_valid = 1;
                            ctx->last_state = *(struct we_state *)ipc_data;
                            ctx->state_seq++;
                            pthread_cond_broadcast(&ctx->cond);
                            pthread_mutex_unlock(&ctx->lock);
                        }
                    }
                    if (we_callback.event_callback) {
                        we_callback.event_callback(ipchdr.wemo_id, (struct we_state *)ipc_data);
                    }
                    break;
                case EVENT_NAME_CHANGE:
                    if (ipchdr.size < (int) sizeof(struct we_name_change)) {
                        fprintf(stderr, "EVENT_NAME_CHANGE payload too short (%d)\n", ipchdr.size);
                        break;
                    }
                    if (we_callback.name_change_callback) {
                        we_callback.name_change_callback(ipchdr.wemo_id, (struct we_name_change *)ipc_data);
                    }
                    break;
                case EVENT_NAME_VALUE:
                    if (ipchdr.size < (int) sizeof(struct we_name_value)) {
                        fprintf(stderr, "EVENT_NAME_VALUE payload too short (%d)\n", ipchdr.size);
                        break;
                    }
                    if (we_callback.name_value_callback) {
                        we_callback.name_value_callback(ipchdr.wemo_id, (struct we_name_value *)ipc_data);
                    }
                    break;
                case EVENT_DEVICE_INFO:
                    if (we_callback.dev_info_callback) {
                        /* parse the XML payload */
                        struct we_dev_information info;
                        ipc_data[ipchdr.size] = '\0';
                        we_handleGetInformationResult(ipc_data, &info);
                        we_callback.dev_info_callback(ipchdr.wemo_id, &info);

                        if (info.productName)
                            free(info.productName);
                        if (info.fader)
                            free(info.fader);
                        if (info.hushMode)
                            free(info.hushMode);
                        if (info.longPressRuleDeviceUdn)
                            free(info.longPressRuleDeviceUdn);
                    }
                    break;
                case EVENT_INSIGHT_HOME_SETTINGS:
                    if (ipchdr.size < (int) sizeof(struct we_insight_home_settings)) {
                        fprintf(stderr, "EVENT_INSIGHT_HOME_SETTINGS payload too short (%d)\n", ipchdr.size);
                        break;
                    }
                    if (we_callback.insight_home_settings_callback) {
                        we_callback.insight_home_settings_callback(ipchdr.wemo_id, (struct we_insight_home_settings *)ipc_data);
                    }
                    break;
                case EVENT_PROTO:
                    if (ipchdr.size < (int) sizeof(struct we_proto_hdr)) {
                        fprintf(stderr, "EVENT_PROTO payload too short (%d)\n", ipchdr.size);
                        break;
                    } else {
                        struct we_proto_hdr *proto = (struct we_proto_hdr *) ipc_data;
                        const void *payload = NULL;

                        if (proto->magic != WE_PROTO_MAGIC || proto->version != WE_PROTO_VERSION) {
                            fprintf(stderr, "EVENT_PROTO invalid magic/version (%u/%u)\n",
                                    proto->magic, proto->version);
                            break;
                        }
                        if (proto->client_id != 0 && proto->client_id != we_client_id) {
                            break;
                        }
                        if ((int)(sizeof(struct we_proto_hdr) + proto->payload_len) > ipchdr.size) {
                            fprintf(stderr, "EVENT_PROTO invalid payload_len=%u size=%d\n",
                                    proto->payload_len, ipchdr.size);
                            break;
                        }
                        if (proto->payload_len > 0) {
                            payload = ipc_data + sizeof(struct we_proto_hdr);
                        }
                        if (proto->msg_type == WE_MSG_RESPONSE) {
                            we_device_ctx_t *ctx = we_get_device_ctx(proto->wemo_id, 1);
                            if (ctx != NULL) {
                                pthread_mutex_lock(&ctx->lock);
                                ctx->last_response_request_id = proto->request_id;
                                ctx->last_response_status = proto->status;
                                ctx->last_response_valid = 1;
                                if (ctx->pending_request_id == proto->request_id) {
                                    ctx->pending_status = proto->status;
                                    ctx->pending_response_ready = 1;
                                    pthread_cond_broadcast(&ctx->cond);
                                }
                                pthread_mutex_unlock(&ctx->lock);
                            }
                        } else if (proto->msg_type == WE_MSG_EVENT) {
                            if (payload != NULL &&
                                proto->payload_len >= sizeof(struct we_broker_completion)) {
                                const struct we_broker_completion *completion =
                                    (const struct we_broker_completion *)payload;
                                we_device_ctx_t *ctx = we_get_device_ctx(completion->wemo_id, 1);
                                if (ctx != NULL) {
                                    pthread_mutex_lock(&ctx->lock);
                                    ctx->last_completion_request_id = completion->request_id;
                                    ctx->last_completion_status = completion->status;
                                    ctx->last_completion_outcome = completion->outcome;
                                    ctx->last_completion_valid = 1;
                                    if (ctx->pending_completion_request_id == completion->request_id) {
                                        ctx->pending_completion_status = completion->status;
                                        ctx->pending_completion_outcome = completion->outcome;
                                        ctx->pending_completion_ready = 1;
                                        pthread_cond_broadcast(&ctx->cond);
                                    }
                                    pthread_mutex_unlock(&ctx->lock);
                                }
                            }
                        }
                        if (we_callback.proto_callback) {
                            we_callback.proto_callback(proto, payload);
                        }
                    }
                    break;
                default:
                    fprintf(stderr, "%s: Unknown EVENT %d\n", __FUNCTION__, ipchdr.cmd);
                    break;
                }
            }
        }
        else {
            /* An error ocurred, just print it to stdout */
            printf("Error on select(): %s", strerror(errno));
        }
    }
thr_exit:
    pthread_mutex_lock(&socket_lock);
    if (socket_fd != -1) {
        close(socket_fd);
        socket_fd = -1;
    }
    pthread_mutex_unlock(&socket_lock);

    return NULL;
}

int we_init()
{
    struct sockaddr_in name;
    int local_sock = -1;

    pthread_mutex_lock(&init_lock);
    if (we_initialized) {
        pthread_mutex_unlock(&init_lock);
        return 1;
    }
    we_configure_protocol_mode();
    if (we_client_id == 0) {
        we_client_id = we_make_client_id();
    }
    srand((unsigned int)(time(NULL) ^ getpid() ^ we_client_id));
    memset(&we_callback, 0, sizeof(struct wemo_engine_callback));

    if ((local_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "we_init: socket failed: %s\n", strerror(errno));
        pthread_mutex_unlock(&init_lock);
        return 0;
    }
    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons((uint16_t)ipc_port);
    if (inet_pton(AF_INET, ipc_host, &name.sin_addr) != 1) {
        fprintf(stderr, "we_init: invalid ipc host %s\n", ipc_host);
        close(local_sock);
        pthread_mutex_unlock(&init_lock);
        return 0;
    }
    if (connect(local_sock, (const struct sockaddr *)&name, sizeof(name)) == -1) {
        fprintf(stderr, "we_init: connect %s:%d failed: %s\n", ipc_host, ipc_port, strerror(errno));
        close(local_sock);
        pthread_mutex_unlock(&init_lock);
        return 0;
    }

    pthread_mutex_lock(&socket_lock);
    socket_fd = local_sock;
    pthread_mutex_unlock(&socket_lock);

    if (pthread_create(&we_ipc_thread, NULL, we_comm_task, NULL) != 0) {
        fprintf(stderr, "we_init: pthread_create failed: %s\n", strerror(errno));
        pthread_mutex_lock(&socket_lock);
        if (socket_fd != -1) {
            close(socket_fd);
            socket_fd = -1;
        }
        pthread_mutex_unlock(&socket_lock);
        pthread_mutex_unlock(&init_lock);
        return 0;
    }
    we_ipc_thread_valid = 1;
    we_initialized = 1;
    pthread_mutex_unlock(&init_lock);

    return 1;
}

int we_set_ipc_target(const char *host, int port)
{
    if (host != NULL && host[0] != '\0') {
        strncpy(ipc_host, host, sizeof(ipc_host) - 1);
        ipc_host[sizeof(ipc_host) - 1] = '\0';
    }
    if (port > 0 && port < 65536) {
        ipc_port = port;
    }
    return 1;
}

int we_register_event_callback(void (*callback) (int wemo_id, struct we_state *data))
{
    we_callback.event_callback = callback;
    return 1;
}

int we_register_netstate_callback(void (*callback) (int wemo_id, struct we_network_status *data))
{
    we_callback.netstate_callback = callback;
    return 1;
}

int we_register_name_change_callback(void (*callback) (int wemo_id, struct we_name_change *data))
{
    we_callback.name_change_callback = callback;
    return 1;
}

int we_register_name_value_callback(void (*callback) (int wemo_id, struct we_name_value *data))
{
    we_callback.name_value_callback = callback;
    return 1;
}

int we_register_dev_info_callback(void (*callback) (int wemo_id, struct we_dev_information *data))
{
    we_callback.dev_info_callback = callback;
    return 1;
}

int we_register_insight_home_settings_callback(void (*callback) (int wemo_id, struct we_insight_home_settings *data))
{
    we_callback.insight_home_settings_callback = callback;
    return 1;
}

int we_register_proto_callback(void (*callback)(const struct we_proto_hdr *hdr, const void *payload))
{
    we_callback.proto_callback = callback;
    return 1;
}

int we_register_health_callback(void (*callback)(int wemo_id, const struct we_device_health *health))
{
    we_callback.health_callback = callback;
    return 1;
}

static int we_send_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;
    ssize_t rc;

    while (sent < len) {
        rc = send(fd, p + sent, len - sent, 0);
        if (rc <= 0) {
            return 0;
        }
        sent += (size_t)rc;
    }
    return 1;
}

int we_send_envelope(int op, int wemo_id, const void *payload, uint32_t payload_len, uint32_t *request_id_out)
{
    struct we_ipc_hdr ipchdr;
    struct we_proto_hdr proto;
    char buffer[IPC_DATA_MAX];
    uint32_t req_id;
    int fd;
    int ok = 1;

    if ((sizeof(struct we_proto_hdr) + payload_len) > sizeof(buffer)) {
        fprintf(stderr, "we_send_envelope too large: %u\n", payload_len);
        return 0;
    }

    req_id = __sync_fetch_and_add(&we_request_id, 1);
    if (req_id == 0) {
        req_id = __sync_fetch_and_add(&we_request_id, 1);
    }

    memset(&proto, 0, sizeof(proto));
    proto.magic = WE_PROTO_MAGIC;
    proto.version = WE_PROTO_VERSION;
    proto.msg_type = WE_MSG_REQUEST;
    proto.client_id = we_client_id;
    proto.request_id = req_id;
    proto.op = op;
    proto.wemo_id = wemo_id;
    proto.status = WE_STATUS_OK;
    proto.payload_len = payload_len;

    memcpy(buffer, &proto, sizeof(proto));
    if (payload_len > 0 && payload != NULL) {
        memcpy(buffer + sizeof(proto), payload, payload_len);
    }

    ipchdr.wemo_id = wemo_id;
    ipchdr.cmd = CMD_PROTO;
    ipchdr.size = (int)(sizeof(proto) + payload_len);

    pthread_mutex_lock(&socket_lock);
    fd = socket_fd;
    if (fd == -1) {
        pthread_mutex_unlock(&socket_lock);
        return 0;
    }

    if (!we_send_all(fd, &ipchdr, sizeof(ipchdr))) {
        fprintf(stderr, "we_send_envelope failure sending header\n");
        ok = 0;
    }
    if (ok && !we_send_all(fd, buffer, (size_t)ipchdr.size)) {
        fprintf(stderr, "we_send_envelope failure sending payload\n");
        ok = 0;
    }
    pthread_mutex_unlock(&socket_lock);

    if (!ok) {
        return 0;
    }

    if (request_id_out != NULL) {
        *request_id_out = req_id;
    }
    return 1;
}

static int we_send_legacy_command(int cmd, int wemo_id, const void *payload, int payload_len)
{
    struct we_ipc_hdr ipchdr;
    int fd;
    int ok = 1;

    ipchdr.wemo_id = wemo_id;
    ipchdr.cmd = cmd;
    ipchdr.size = payload_len;

    pthread_mutex_lock(&socket_lock);
    fd = socket_fd;
    if (fd == -1) {
        pthread_mutex_unlock(&socket_lock);
        return 0;
    }

    if (!we_send_all(fd, &ipchdr, sizeof(ipchdr))) {
        ok = 0;
    }
    if (ok && payload_len > 0 && payload != NULL) {
        if (!we_send_all(fd, payload, (size_t)payload_len)) {
            ok = 0;
        }
    }
    pthread_mutex_unlock(&socket_lock);

    if (!ok) {
        return 0;
    }
    return 1;
}

int we_send_command_ex(int cmd, int wemo_id, const void *payload, int payload_len,
                       uint32_t *request_id_out, int *used_proto_out)
{
    const void *proto_payload = payload;
    int proto_payload_len = payload_len;
    struct we_set_idempotent_request idemp_req;

    if (request_id_out != NULL) {
        *request_id_out = 0;
    }
    if (used_proto_out != NULL) {
        *used_proto_out = 0;
    }

    if (cmd == CMD_SET && payload != NULL && payload_len >= (int)sizeof(struct we_state)) {
        memset(&idemp_req, 0, sizeof(idemp_req));
        memcpy(&idemp_req.state, payload, sizeof(struct we_state));
        idemp_req.idempotency_key = we_next_set_idempotency_key();
        proto_payload = &idemp_req;
        proto_payload_len = (int)sizeof(idemp_req);
    }

    if (we_proto_enabled) {
        uint32_t req_id = 0;
        if (we_send_envelope(cmd, wemo_id, proto_payload, (uint32_t)proto_payload_len, &req_id)) {
            if (request_id_out != NULL) {
                *request_id_out = req_id;
            }
            if (used_proto_out != NULL) {
                *used_proto_out = 1;
            }
            return 1;
        }
        if (!we_proto_legacy_fallback) {
            return 0;
        }
    }
    return we_send_legacy_command(cmd, wemo_id, payload, payload_len);
}

static int we_send_command(int cmd, int wemo_id, const void *payload, int payload_len)
{
    return we_send_command_ex(cmd, wemo_id, payload, payload_len, NULL, NULL);
}

int we_get_action (int wemo_id, struct we_state *we_state_data)
{
    return we_send_command(CMD_GET, wemo_id, we_state_data, sizeof(struct we_state));
}

int we_set_action (int wemo_id, struct we_state *we_state_data)
{
    return we_send_command(CMD_SET, wemo_id, we_state_data, sizeof(struct we_state));
}

int we_set_action_confirmed(int wemo_id, struct we_state *target_state, int timeout_ms)
{
    return we_run_command_txn(CMD_SET, wemo_id, target_state, sizeof(struct we_state),
                              target_state, timeout_ms, WE_CONFIRM_STATE_MATCH, NULL);
}

int we_del_action (int wemo_id, struct we_state *we_state_data)
{
    return we_send_command(CMD_DELETE, wemo_id, we_state_data, sizeof(struct we_state));
}

int we_get_netstate(int wemo_id, struct we_network_status *network_status)
{
    return we_send_command(CMD_CONNECTION_STATE, wemo_id, network_status, sizeof(struct we_network_status));
}

int we_connect(int wemo_id, struct we_conn_data *conn_data)
{
    return we_send_command(CMD_SETUP, wemo_id, conn_data, sizeof(struct we_conn_data));
}

int we_closesetup(int wemo_id)
{
    return we_send_command(CMD_CLOSESETUP, wemo_id, NULL, 0);
}

int we_discover(int wemo_id)
{
    return we_send_command(CMD_DISCOVER, wemo_id, NULL, 0);
}

int we_forget_action(int wemo_id)
{
    return we_send_command(CMD_FORGET, wemo_id, NULL, 0);
}

int we_firm_update(int wemo_id, struct we_firmware_data *firm_data)
{
    return we_send_command(CMD_FIRMWARE_UPDATE, wemo_id, firm_data, sizeof(struct we_firmware_data));
}

int we_set_hksetup_state(int wemo_id, struct we_hksetup_state *setup_state)
{
    return we_send_command(CMD_SET_HKSETUP_STATE, wemo_id, setup_state, sizeof(struct we_hksetup_state));
}

int we_change_name(int wemo_id, struct we_name_change *name_data)
{
    return we_send_command(CMD_CHANGE_NAME, wemo_id, name_data, sizeof(struct we_name_change));
}

int we_set_name_value(int wemo_id, struct we_name_value *data)
{
    return we_send_command(CMD_NAME_VALUE, wemo_id, data, sizeof(struct we_name_value));
}

int we_reset(int wemo_id, struct we_reset *reset_data)
{
    return we_send_command(CMD_RESET, wemo_id, reset_data, sizeof(struct we_reset));
}

int we_restart_rule(int wemo_id)
{
    return we_send_command(CMD_RESTART_RULE, wemo_id, NULL, 0);
}

int we_get_devinfo(int wemo_id)
{
    return we_send_command(CMD_GET_DEVINFO, wemo_id, NULL, 0);
}

int we_get_insightHomeSettings(int wemo_id)
{
    return we_send_command(CMD_GET_INSIGHTHOME_SETTINGS, wemo_id, NULL, 0);
}

int we_set_insightHomeSettings(int wemo_id, struct we_insight_home_settings *home_settings)
{
    return we_send_command(CMD_SET_INSIGHTHOME_SETTINGS, wemo_id, home_settings, sizeof(struct we_insight_home_settings));
}

int we_get_insightParams(int wemo_id)
{
    return we_send_command(CMD_GET_INSIGHT_PARAMS, wemo_id, NULL, 0);
}

int we_set_powerThreshold(int wemo_id, struct we_insight_threshold *threshold)
{
    return we_send_command(CMD_SET_POWER_THRESHOLD, wemo_id, threshold, sizeof(struct we_insight_threshold));
}

int we_get_powerThreshold(int wemo_id)
{
    return we_send_command(CMD_GET_POWER_THRESHOLD, wemo_id, NULL, 0);
}

int we_get_dataExportInfo(int wemo_id)
{
    return we_send_command(CMD_GET_DATA_EXPORTINFO, wemo_id, NULL, 0);
}

int we_schedule_dataExport(int wemo_id, struct we_insight_export *export)
{
    return we_send_command(CMD_SCHEDULE_DATA_EXPORT, wemo_id, export, sizeof(struct we_insight_export));
}

int we_end()
{
    int fd = -1;

    pthread_mutex_lock(&init_lock);
    pthread_mutex_lock(&socket_lock);
    if (socket_fd != -1) {
        fd = socket_fd;
        socket_fd = -1;
    }
    pthread_mutex_unlock(&socket_lock);

    fprintf(stderr, "we_end: cleaning up : ");
    if (fd != -1) {
        fprintf(stderr, "shutdown/close socket (%d)\n", fd);
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
    if (we_ipc_thread_valid) {
        pthread_join(we_ipc_thread, NULL);
        we_ipc_thread_valid = 0;
    }
    we_initialized = 0;
    pthread_mutex_unlock(&init_lock);

    memset(&we_callback, 0, sizeof(struct wemo_engine_callback));
    return 1;
}
