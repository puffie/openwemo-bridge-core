#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>

#include <semaphore.h>
#include <pthread.h>
#include <sqlite3.h>

#include "wemo_ipc_server.h"
#include "wemo_event_ctrl.h"
#include "wemo_net_ctrl.h"
#include "wemo_firm_ctrl.h"
#include "wemo_name_ctrl.h"
#include "wemo_set_name_value.h"
#include "wemo_reset_ctrl.h"
#include "wemo_dev_info.h"
#include "wemo_insight.h"
#include "logger.h"

#define MAX_CLIENTS         16
#define LISTEN_QUEUE        16
#define SENDBUF_SIZE        (IPC_DATA_MAX + 64)
#define RECVBUF_SIZE        (IPC_DATA_MAX + 64)
#define BROKER_MAX_DEVICES  64
#define BROKER_COMPLETION_HISTORY 256
#define PROTO_ROUTE_MAX      256
#define SET_IDEMPOTENCY_CACHE_MAX 512

typedef enum { DISCONNECTED, CONNECTED, WAIT_FOR_MSG } ProcessingState;

typedef struct {
    int sockfd;
    ProcessingState state;
    char sendbuf[SENDBUF_SIZE];
    char recvbuf[RECVBUF_SIZE];
    int sendlen;
    int recvoff;
    sem_t sem;
} peer_state_t;

typedef struct {
    bool want_read;
    bool want_write;
} fd_status_t;

peer_state_t global_state[MAX_CLIENTS];

const fd_status_t fd_status_R = {.want_read = true, .want_write = false};
const fd_status_t fd_status_W = {.want_read = false, .want_write = true};
const fd_status_t fd_status_RW = {.want_read = true, .want_write = true};
const fd_status_t fd_status_NORW = {.want_read = false, .want_write = false};

int epollfd = 0;

static int run_server = 0;
static int connection_no = 0;
static char ipc_bind_addr[64] = "127.0.0.1";
static int ipc_port = IPC_DEFAULT_PORT;
static void proto_route_record(uint32_t request_id, uint32_t client_id, int wemo_id, int op, int sockfd);
static int proto_route_lookup(uint32_t request_id, uint32_t client_id, int wemo_id, int op, uint32_t *client_id_out);
static void proto_route_purge_sockfd(int sockfd);
static int wemo_ipc_send(struct we_ipc_hdr *ipchdr, char *ipc_data);
static int wemo_ipc_send_to_sock(int sockfd, struct we_ipc_hdr *ipchdr, char *ipc_data);
static int wemo_ipc_send_internal(int target_sockfd, struct we_ipc_hdr *ipchdr, char *ipc_data);

typedef struct broker_cmd_node {
    int cmd;
    int wemo_id;
    uint32_t request_id;
    uint32_t job_id;
    int is_proto_request;
    int payload_size;
    char payload[IPC_DATA_MAX];
    struct broker_cmd_node *next;
} broker_cmd_node_t;

typedef struct {
    int in_use;
    int wemo_id;
    int stop;
    int worker_started;
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    broker_cmd_node_t *head;
    broker_cmd_node_t *tail;
} broker_device_queue_t;

static pthread_mutex_t broker_lock = PTHREAD_MUTEX_INITIALIZER;
static broker_device_queue_t broker_devices[BROKER_MAX_DEVICES];
static pthread_mutex_t broker_history_lock = PTHREAD_MUTEX_INITIALIZER;
static struct we_broker_completion broker_history[BROKER_COMPLETION_HISTORY];
static uint32_t broker_history_next = 0;
static uint32_t broker_job_seq = 1;
static pthread_mutex_t proto_route_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    uint32_t request_id;
    uint32_t client_id;
    int wemo_id;
    int op;
    int sockfd;
    uint64_t updated_ms;
} proto_route_entry_t;

static proto_route_entry_t proto_routes[PROTO_ROUTE_MAX];
static uint32_t proto_route_seq = 0;
static pthread_mutex_t set_idemp_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int in_use;
    uint32_t client_id;
    int wemo_id;
    uint64_t key;
    int status;
    uint64_t updated_ms;
} set_idempotency_entry_t;

static set_idempotency_entry_t set_idemp_cache[SET_IDEMPOTENCY_CACHE_MAX];
static uint32_t set_idemp_seq = 0;

static const char *ipc_cmd_to_string(int cmd)
{
    switch (cmd) {
    case CMD_SETUP: return "setup";
    case CMD_CLOSESETUP: return "closesetup";
    case CMD_CONNECTION_STATE: return "getnetstate";
    case CMD_SET: return "set";
    case CMD_GET: return "getstate";
    case CMD_DELETE: return "deletedev";
    case CMD_FORGET: return "forgetdev";
    case CMD_DISCOVER: return "discover";
    case CMD_FIRMWARE_UPDATE: return "firmup";
    case CMD_SET_HKSETUP_STATE: return "set_hksetup";
    case CMD_CHANGE_NAME: return "changename";
    case CMD_NAME_VALUE: return "name_value";
    case CMD_RESET: return "reset";
    case CMD_RESTART_RULE: return "restartrule";
    case CMD_GET_DEVINFO: return "getinformation";
    case CMD_GET_INSIGHTHOME_SETTINGS: return "gethomesettings";
    case CMD_SET_INSIGHTHOME_SETTINGS: return "sethomesettings";
    case CMD_GET_INSIGHT_PARAMS: return "getinsightparams";
    case CMD_SET_POWER_THRESHOLD: return "setpowerthreshold";
    case CMD_GET_POWER_THRESHOLD: return "getpowerthreshold";
    case CMD_GET_DATA_EXPORTINFO: return "getexportinfo";
    case CMD_SCHEDULE_DATA_EXPORT: return "scheduledataexport";
    case CMD_GET_HEALTH_SNAPSHOT: return "get_health_snapshot";
    default: return "unknown";
    }
}

static const char *ipc_status_to_string(int status)
{
    switch (status) {
    case WE_STATUS_OK: return "ok";
    case WE_STATUS_INVALID: return "invalid";
    case WE_STATUS_UNSUPPORTED: return "unsupported";
    default: return "unknown";
    }
}

void wemo_ipc_server_set_bind(const char *addr, int port)
{
    if (addr != NULL && addr[0] != '\0') {
        strncpy(ipc_bind_addr, addr, sizeof(ipc_bind_addr) - 1);
        ipc_bind_addr[sizeof(ipc_bind_addr) - 1] = '\0';
    }
    if (port > 0 && port < 65536) {
        ipc_port = port;
    }
}

static int listen_socket(void)
{
    int i = 0;
    int sock = -1;
    struct sockaddr_in server;

    for (i = 0; i < MAX_CLIENTS; i++) {
        global_state[i].sockfd = -1;
        global_state[i].state = DISCONNECTED;
        memset(global_state[i].sendbuf, 0x00, SENDBUF_SIZE);
        memset(global_state[i].recvbuf, 0x00, RECVBUF_SIZE);
        global_state[i].sendlen = 0;
        global_state[i].recvoff = 0;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERROR_MSG("error : opening stream socket: %s", strerror(errno));
        return -1;
    }

    // This helps avoid spurious EADDRINUSE when the previous instance of this
    // server died.
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_ERROR_MSG("error : setsockopt: %s", strerror(errno));
        return -1;
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((uint16_t)ipc_port);
    if (inet_pton(AF_INET, ipc_bind_addr, &server.sin_addr) != 1) {
        LOG_ERROR_MSG("invalid bind address: %s", ipc_bind_addr);
        return -1;
    }

    if (bind(sock, (struct sockaddr *) &server, sizeof(server))) {
        LOG_ERROR_MSG("error: binding stream socket: %s", strerror(errno));
        return -1;
    }

    LOG_ERROR_MSG("ipc listen on %s:%d", ipc_bind_addr, ipc_port);

    listen(sock, LISTEN_QUEUE);

    return sock;
}

static int make_socket_non_blocking(int sockfd)
{
    int flags = fcntl(sockfd, F_GETFL, 0);

    if (flags == -1) {
        LOG_ERROR_MSG("error : fcntl F_GETFL");
        return -1;
    }

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_ERROR_MSG("error: fcntl F_SETFL O_NONBLOCK");
        return -1;
    }

    return 0;
}

static fd_status_t on_peer_connected(int connection_no, int sockfd)
{
    int i = 0;

    if (connection_no > MAX_CLIENTS) {
        LOG_ERROR_MSG("invalid connection_no=%d (max=%d)", connection_no, MAX_CLIENTS);
        connection_no = MAX_CLIENTS;
    }
    /* find the empty global_state */
    for (i = 0; i < MAX_CLIENTS; i++) {
        peer_state_t* peerstate = &global_state[i];
        if (peerstate->sockfd == -1) {
            //Initialize state
            peerstate->sockfd = sockfd;
            peerstate->state = CONNECTED;
            memset(peerstate->sendbuf, 0x00, SENDBUF_SIZE);
            memset(peerstate->recvbuf, 0x00, RECVBUF_SIZE);
            peerstate->sendlen = 0;
            peerstate->recvoff = 0;
            if (sem_init(&global_state[i].sem, 0, 1) == 0) {
                LOG_DEBUG_MSG("send semaphore initialized for %d.", i);
            }
            else {
                LOG_ERROR_MSG("send semaphore initialization failed for %d.", i);
                exit(1);
            }
            break;
        }
    }

    if (i == MAX_CLIENTS) {
        LOG_ERROR_MSG("No empty slot - too many clients");
        close(sockfd);
        return fd_status_NORW;
    }
    LOG_DEBUG_MSG("peer client connected to wemo_ctrl service : connection slot = [%d], sockfd = [%d]",
                      i, sockfd);

    // Signal that this socket is ready for reading now.
    return fd_status_R;
}

static void on_peer_closed(int sockfd)
{
    int i = 0;

    for (i = 0; i < MAX_CLIENTS; i++) {
        peer_state_t* peerstate = &global_state[i];
        if (peerstate->sockfd == sockfd) {
            proto_route_purge_sockfd(sockfd);
            close(sockfd);
            peerstate->sockfd = -1;
            peerstate->state = DISCONNECTED;
            peerstate->sendbuf[0] = 0x00;
            peerstate->sendlen = 0;
            peerstate->recvoff = 0;
            connection_no--;
            LOG_DEBUG_MSG("Destroying semaphore = %d.", i);
            sem_destroy(&peerstate->sem);
        }
    }
}

static int wemo_ipc_execute_command(int cmd, int wemo_id, char *ipc_data, int payload_size);
static int wemo_ipc_process_message(int sockfd, const struct we_ipc_hdr *ipchdr, char *ipc_data);

static void wemo_build_audit_db_path(char *out, size_t out_len)
{
    const char *override = getenv("WEMO_AUDIT_DB_PATH");
    const char *home = getenv("HOME");
    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (override != NULL && override[0] != '\0') {
        snprintf(out, out_len, "%s", override);
        return;
    }
    if (home != NULL && home[0] != '\0') {
        snprintf(out, out_len, "%s/.local/state/wemo-matter/wemo_txn_audit.db", home);
        return;
    }
    snprintf(out, out_len, "/tmp/wemo_txn_audit.db");
}

static int wemo_ctrl_get_health_snapshot(int wemo_id, int max_items, struct we_health_snapshot *out)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char path[256];
    const char *sql_all =
        "SELECT wemo_id,health_score,timeout_streak,degraded_mode,breaker_open,breaker_remaining_ms,breaker_open_count,total_applied,total_timeouts,total_rejected,total_retries,last_retry_count,ema_applied_latency_ms,last_applied_latency_ms "
        "FROM device_health ORDER BY wemo_id ASC LIMIT ?;";
    const char *sql_one =
        "SELECT wemo_id,health_score,timeout_streak,degraded_mode,breaker_open,breaker_remaining_ms,breaker_open_count,total_applied,total_timeouts,total_rejected,total_retries,last_retry_count,ema_applied_latency_ms,last_applied_latency_ms "
        "FROM device_health WHERE wemo_id=? LIMIT 1;";
    int count = 0;
    int rc;

    if (out == NULL) {
        return WE_STATUS_INVALID;
    }
    memset(out, 0, sizeof(*out));
    if (max_items <= 0) {
        max_items = WE_HEALTH_SNAPSHOT_MAX_ITEMS;
    }
    if (max_items > WE_HEALTH_SNAPSHOT_MAX_ITEMS) {
        max_items = WE_HEALTH_SNAPSHOT_MAX_ITEMS;
    }

    wemo_build_audit_db_path(path, sizeof(path));
    rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        if (db != NULL) {
            sqlite3_close(db);
        }
        return WE_STATUS_INTERNAL;
    }
    sqlite3_busy_timeout(db, 2000);
    rc = sqlite3_prepare_v2(db, (wemo_id > 0) ? sql_one : sql_all, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return WE_STATUS_INTERNAL;
    }
    if (wemo_id > 0) {
        sqlite3_bind_int(stmt, 1, wemo_id);
    } else {
        sqlite3_bind_int(stmt, 1, max_items);
    }
    while (count < max_items && sqlite3_step(stmt) == SQLITE_ROW) {
        struct we_device_health *h = &out->items[count];
        memset(h, 0, sizeof(*h));
        h->wemo_id = sqlite3_column_int(stmt, 0);
        h->health_score = sqlite3_column_int(stmt, 1);
        h->timeout_streak = sqlite3_column_int(stmt, 2);
        h->degraded_mode = sqlite3_column_int(stmt, 3);
        h->breaker_open = sqlite3_column_int(stmt, 4);
        h->breaker_remaining_ms = (int64_t)sqlite3_column_int64(stmt, 5);
        h->breaker_open_count = (uint32_t)sqlite3_column_int(stmt, 6);
        h->total_applied = (uint32_t)sqlite3_column_int(stmt, 7);
        h->total_timeouts = (uint32_t)sqlite3_column_int(stmt, 8);
        h->total_rejected = (uint32_t)sqlite3_column_int(stmt, 9);
        h->total_retries = (uint32_t)sqlite3_column_int(stmt, 10);
        h->last_retry_count = sqlite3_column_int(stmt, 11);
        h->ema_applied_latency_ms = sqlite3_column_int(stmt, 12);
        h->last_applied_latency_ms = sqlite3_column_int(stmt, 13);
        count++;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    out->count = count;
    return WE_STATUS_OK;
}

static int64_t broker_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int set_idempotency_lookup(uint32_t client_id, int wemo_id, uint64_t key, int *status_out)
{
    int i;
    int found = 0;
    int found_status = WE_STATUS_OK;
    uint64_t latest = 0;

    if (client_id == 0 || wemo_id <= 0 || key == 0) {
        return 0;
    }
    pthread_mutex_lock(&set_idemp_lock);
    for (i = 0; i < SET_IDEMPOTENCY_CACHE_MAX; i++) {
        set_idempotency_entry_t *e = &set_idemp_cache[i];
        if (!e->in_use) {
            continue;
        }
        if (e->client_id == client_id && e->wemo_id == wemo_id && e->key == key) {
            if (!found || e->updated_ms >= latest) {
                latest = e->updated_ms;
                found_status = e->status;
                found = 1;
            }
        }
    }
    pthread_mutex_unlock(&set_idemp_lock);
    if (found && status_out != NULL) {
        *status_out = found_status;
    }
    return found;
}

static void set_idempotency_record(uint32_t client_id, int wemo_id, uint64_t key, int status)
{
    set_idempotency_entry_t *slot;
    uint32_t idx;

    if (client_id == 0 || wemo_id <= 0 || key == 0) {
        return;
    }
    idx = __sync_fetch_and_add(&set_idemp_seq, 1);
    slot = &set_idemp_cache[idx % SET_IDEMPOTENCY_CACHE_MAX];
    pthread_mutex_lock(&set_idemp_lock);
    slot->in_use = 1;
    slot->client_id = client_id;
    slot->wemo_id = wemo_id;
    slot->key = key;
    slot->status = status;
    slot->updated_ms = (uint64_t)broker_now_ms();
    pthread_mutex_unlock(&set_idemp_lock);
}

static void proto_route_record(uint32_t request_id, uint32_t client_id, int wemo_id, int op, int sockfd)
{
    proto_route_entry_t *slot;
    uint32_t idx;

    if (request_id == 0 || sockfd < 0) {
        return;
    }
    idx = __sync_fetch_and_add(&proto_route_seq, 1);
    slot = &proto_routes[idx % PROTO_ROUTE_MAX];

    pthread_mutex_lock(&proto_route_lock);
    slot->request_id = request_id;
    slot->client_id = client_id;
    slot->wemo_id = wemo_id;
    slot->op = op;
    slot->sockfd = sockfd;
    slot->updated_ms = (uint64_t)broker_now_ms();
    pthread_mutex_unlock(&proto_route_lock);
}

static int proto_route_lookup(uint32_t request_id, uint32_t client_id, int wemo_id, int op, uint32_t *client_id_out)
{
    int i;
    int found_sockfd = -1;
    uint32_t found_client_id = 0;
    uint64_t found_ts = 0;

    if (request_id == 0) {
        return -1;
    }

    pthread_mutex_lock(&proto_route_lock);
    for (i = 0; i < PROTO_ROUTE_MAX; i++) {
        proto_route_entry_t *entry = &proto_routes[i];
        if (entry->request_id != request_id) {
            continue;
        }
        if (client_id != 0 && entry->client_id != 0 && entry->client_id != client_id) {
            continue;
        }
        if (entry->wemo_id != wemo_id) {
            continue;
        }
        if (op != 0 && entry->op != 0 && entry->op != op) {
            continue;
        }
        if (entry->updated_ms >= found_ts) {
            found_ts = entry->updated_ms;
            found_sockfd = entry->sockfd;
            found_client_id = entry->client_id;
        }
    }
    pthread_mutex_unlock(&proto_route_lock);
    if (client_id_out != NULL) {
        *client_id_out = found_client_id;
    }
    return found_sockfd;
}

static void proto_route_purge_sockfd(int sockfd)
{
    int i;

    pthread_mutex_lock(&proto_route_lock);
    for (i = 0; i < PROTO_ROUTE_MAX; i++) {
        if (proto_routes[i].sockfd == sockfd) {
            memset(&proto_routes[i], 0, sizeof(proto_routes[i]));
        }
    }
    pthread_mutex_unlock(&proto_route_lock);
}

static uint32_t broker_next_job_id(void)
{
    uint32_t id = __sync_fetch_and_add(&broker_job_seq, 1);
    if (id == 0) {
        id = __sync_fetch_and_add(&broker_job_seq, 1);
    }
    return id;
}

static void broker_record_completion(const struct we_broker_completion *completion)
{
    if (completion == NULL) {
        return;
    }
    pthread_mutex_lock(&broker_history_lock);
    broker_history[broker_history_next % BROKER_COMPLETION_HISTORY] = *completion;
    broker_history_next++;
    pthread_mutex_unlock(&broker_history_lock);
}

static void broker_send_completion_event(const struct we_broker_completion *completion)
{
    struct we_ipc_hdr ipchdr;
    struct we_proto_hdr proto;
    char payload[sizeof(struct we_proto_hdr) + sizeof(struct we_broker_completion)];
    int route_sockfd;
    uint32_t route_client_id = 0;

    if (completion == NULL || completion->request_id == 0) {
        return;
    }

    memset(&proto, 0, sizeof(proto));
    proto.magic = WE_PROTO_MAGIC;
    proto.version = WE_PROTO_VERSION;
    proto.msg_type = WE_MSG_EVENT;
    proto.client_id = 0;
    proto.request_id = completion->request_id;
    proto.op = completion->cmd;
    proto.wemo_id = completion->wemo_id;
    proto.status = completion->status;
    proto.payload_len = sizeof(*completion);

    ipchdr.wemo_id = completion->wemo_id;
    ipchdr.cmd = EVENT_PROTO;
    ipchdr.size = sizeof(payload);
    route_sockfd = proto_route_lookup(completion->request_id,
                                      0,
                                      completion->wemo_id,
                                      completion->cmd,
                                      &route_client_id);
    proto.client_id = route_client_id;
    memcpy(payload, &proto, sizeof(proto));
    memcpy(payload + sizeof(proto), completion, sizeof(*completion));
    if (route_sockfd >= 0) {
        if (wemo_ipc_send_to_sock(route_sockfd, &ipchdr, payload) != 0) {
            LOG_ERROR_MSG("completion send failed request_id=%u wemo_id=%d cmd=%d sockfd=%d",
                          completion->request_id, completion->wemo_id, completion->cmd, route_sockfd);
        }
        return;
    }
    LOG_DEBUG_MSG("completion route missing request_id=%u wemo_id=%d cmd=%d; dropping",
                  completion->request_id, completion->wemo_id, completion->cmd);
}

static int broker_is_queued_cmd(int cmd)
{
    return (cmd == CMD_SET || cmd == CMD_GET);
}

static broker_device_queue_t *broker_find_device_locked(int wemo_id)
{
    int i;
    broker_device_queue_t *free_slot = NULL;

    for (i = 0; i < BROKER_MAX_DEVICES; i++) {
        if (broker_devices[i].in_use && broker_devices[i].wemo_id == wemo_id) {
            return &broker_devices[i];
        }
        if (!broker_devices[i].in_use && free_slot == NULL) {
            free_slot = &broker_devices[i];
        }
    }
    if (free_slot == NULL) {
        return NULL;
    }
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->in_use = 1;
    free_slot->wemo_id = wemo_id;
    pthread_mutex_init(&free_slot->lock, NULL);
    pthread_cond_init(&free_slot->cond, NULL);
    return free_slot;
}

static void *broker_worker(void *arg)
{
    broker_device_queue_t *queue = (broker_device_queue_t *)arg;

    while (1) {
        broker_cmd_node_t *node = NULL;

        pthread_mutex_lock(&queue->lock);
        while (!queue->stop && queue->head == NULL) {
            pthread_cond_wait(&queue->cond, &queue->lock);
        }
        if (queue->stop) {
            pthread_mutex_unlock(&queue->lock);
            break;
        }
        node = queue->head;
        queue->head = node->next;
        if (queue->head == NULL) {
            queue->tail = NULL;
        }
        pthread_mutex_unlock(&queue->lock);

        if (node != NULL) {
            int64_t started_ms = broker_now_ms();
            int status = wemo_ipc_execute_command(node->cmd, node->wemo_id, node->payload, node->payload_size);
            int64_t finished_ms = broker_now_ms();
            struct we_broker_completion completion;
            int64_t latency = 0;

            if (finished_ms >= started_ms) {
                latency = finished_ms - started_ms;
            }
            if (latency > INT32_MAX) {
                latency = INT32_MAX;
            }

            memset(&completion, 0, sizeof(completion));
            completion.job_id = node->job_id;
            completion.request_id = node->request_id;
            completion.cmd = node->cmd;
            completion.wemo_id = node->wemo_id;
            completion.status = status;
            completion.outcome = (status == WE_STATUS_OK) ? WE_BROKER_OUTCOME_APPLIED : WE_BROKER_OUTCOME_FAILED;
            completion.latency_ms = (int32_t)latency;

            LOG_INFO_MSG("broker execute cmd=%s(%d) wemo_id=%d status=%s(%d)",
                         ipc_cmd_to_string(node->cmd),
                         node->cmd,
                         node->wemo_id,
                         ipc_status_to_string(status),
                         status);
            broker_record_completion(&completion);
            if (node->is_proto_request) {
                broker_send_completion_event(&completion);
            }
            free(node);
        }
    }
    return NULL;
}

static int broker_enqueue_command(int cmd,
                                  int wemo_id,
                                  char *ipc_data,
                                  int payload_size,
                                  uint32_t request_id,
                                  int is_proto_request)
{
    broker_cmd_node_t *node;
    broker_device_queue_t *queue;

    if (payload_size < 0 || payload_size > IPC_DATA_MAX) {
        return WE_STATUS_INVALID;
    }
    if (wemo_id <= 0) {
        return WE_STATUS_INVALID;
    }

    node = (broker_cmd_node_t *)calloc(1, sizeof(*node));
    if (node == NULL) {
        return WE_STATUS_INTERNAL;
    }
    node->cmd = cmd;
    node->wemo_id = wemo_id;
    node->request_id = request_id;
    node->job_id = broker_next_job_id();
    node->is_proto_request = is_proto_request;
    node->payload_size = payload_size;
    if (payload_size > 0 && ipc_data != NULL) {
        memcpy(node->payload, ipc_data, payload_size);
    }

    pthread_mutex_lock(&broker_lock);
    queue = broker_find_device_locked(wemo_id);
    if (queue == NULL) {
        pthread_mutex_unlock(&broker_lock);
        free(node);
        return WE_STATUS_INTERNAL;
    }
    if (!queue->worker_started) {
        if (pthread_create(&queue->thread, NULL, broker_worker, queue) != 0) {
            pthread_mutex_unlock(&broker_lock);
            free(node);
            return WE_STATUS_INTERNAL;
        }
        pthread_detach(queue->thread);
        queue->worker_started = 1;
    }
    pthread_mutex_unlock(&broker_lock);

    pthread_mutex_lock(&queue->lock);
    if (queue->tail != NULL) {
        queue->tail->next = node;
    } else {
        queue->head = node;
    }
    queue->tail = node;
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->lock);

    LOG_INFO_MSG("broker enqueue job_id=%u request_id=%u cmd=%s(%d) wemo_id=%d payload_len=%d",
                 node->job_id, node->request_id, ipc_cmd_to_string(cmd), cmd, wemo_id, payload_size);
    return WE_STATUS_OK;
}

static void broker_stop_all(void)
{
    int i;

    pthread_mutex_lock(&broker_lock);
    for (i = 0; i < BROKER_MAX_DEVICES; i++) {
        broker_device_queue_t *queue = &broker_devices[i];
        if (!queue->in_use) {
            continue;
        }
        pthread_mutex_lock(&queue->lock);
        queue->stop = 1;
        pthread_cond_broadcast(&queue->cond);
        while (queue->head != NULL) {
            broker_cmd_node_t *tmp = queue->head;
            queue->head = tmp->next;
            free(tmp);
        }
        queue->tail = NULL;
        pthread_mutex_unlock(&queue->lock);
    }
    pthread_mutex_unlock(&broker_lock);
}

static int wemo_ipc_handle_command(int cmd,
                                   int wemo_id,
                                   char *ipc_data,
                                   int payload_size,
                                   uint32_t request_id,
                                   int is_proto_request)
{
    if (broker_is_queued_cmd(cmd)) {
        return broker_enqueue_command(cmd, wemo_id, ipc_data, payload_size, request_id, is_proto_request);
    }
    return wemo_ipc_execute_command(cmd, wemo_id, ipc_data, payload_size);
}

static int wemo_ipc_execute_command(int cmd, int wemo_id, char *ipc_data, int payload_size)
{
    struct we_state *state;

    switch (cmd) {
    case CMD_SETUP:
        if (payload_size < (int)sizeof(struct we_conn_data)) {
            return WE_STATUS_INVALID;
        }
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) setup command");
        wemoCtrlPointNetworkSetup(wemo_id, (struct we_conn_data *)ipc_data);
        return WE_STATUS_OK;
    case CMD_CLOSESETUP:
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) closesetup command");
        wemoCtrlPointCloseSetup(wemo_id);
        return WE_STATUS_OK;
    case CMD_CONNECTION_STATE:
        if (payload_size < (int)sizeof(struct we_network_status)) {
            return WE_STATUS_INVALID;
        }
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) get connection state command");
        wemoCtrlPointGetNetworkStatus(wemo_id, (struct we_network_status *)ipc_data);
        return WE_STATUS_OK;
    case CMD_SET:
        if (payload_size < (int)sizeof(struct we_state)) {
            return WE_STATUS_INVALID;
        }
        state = (struct we_state *)ipc_data;
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) set command: wemo_id = %d, is_online = %d, state = %d, level = %d",
                     wemo_id, state->is_online, state->state, state->level);
        wemoCtrlPointTriggerAction(wemo_id, state, 1);
        return WE_STATUS_OK;
    case CMD_GET:
        if (payload_size < (int)sizeof(struct we_state)) {
            return WE_STATUS_INVALID;
        }
        state = (struct we_state *)ipc_data;
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) get command: wemo_id = %d, is_online = %d, state = %d, level = %d",
                     wemo_id, state->is_online, state->state, state->level);
        wemoCtrlPointRetrieveState(wemo_id, state);
        return WE_STATUS_OK;
    case CMD_DELETE:
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) delete command: wemo_id = %d", wemo_id);
        wemoCtrlPointDeleteDevice(wemo_id);
        return WE_STATUS_OK;
    case CMD_FORGET:
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) forget command: wemo_id = %d", wemo_id);
        wemoCtrlPointForgetDevice(wemo_id);
        return WE_STATUS_OK;
    case CMD_DISCOVER:
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) discover command");
        wemoRequestDiscover();
        return WE_STATUS_OK;
    case CMD_FIRMWARE_UPDATE:
        if (payload_size < (int)sizeof(struct we_firmware_data)) {
            return WE_STATUS_INVALID;
        }
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) firmware update command");
        wemoCtrlPointFirmwareUpdate(wemo_id, (struct we_firmware_data *)ipc_data);
        return WE_STATUS_OK;
    case CMD_SET_HKSETUP_STATE:
        if (payload_size < (int)sizeof(struct we_hksetup_state)) {
            return WE_STATUS_INVALID;
        }
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) set HK setup state");
        wemoCtrlPointSetHKSetupState(wemo_id, (struct we_hksetup_state *)ipc_data);
        return WE_STATUS_OK;
    case CMD_CHANGE_NAME:
        if (payload_size < (int)sizeof(struct we_name_change)) {
            return WE_STATUS_INVALID;
        }
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) change friendly name");
        wemoCtrlPointChangeName(wemo_id, (struct we_name_change *)ipc_data);
        return WE_STATUS_OK;
    case CMD_NAME_VALUE:
        if (payload_size < (int)sizeof(struct we_name_value)) {
            return WE_STATUS_INVALID;
        }
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) name value");
        wemoCtrlPointSetNameValue(wemo_id, (struct we_name_value *)ipc_data);
        return WE_STATUS_OK;
    case CMD_RESET:
        if (payload_size < (int)sizeof(struct we_reset)) {
            return WE_STATUS_INVALID;
        }
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) reset");
        wemoCtrlPointReset(wemo_id, (struct we_reset *)ipc_data);
        return WE_STATUS_OK;
    case CMD_RESTART_RULE:
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) rule restart command");
        wemoCtrlPointRestartRule(wemo_id);
        return WE_STATUS_OK;
    case CMD_GET_DEVINFO:
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) getInformation command");
        wemoCtrlGetInformation(wemo_id);
        return WE_STATUS_OK;
    case CMD_GET_INSIGHTHOME_SETTINGS:
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) GetInsightHomeSettings command");
        wemoCtrlGetInsightHomeSettings(wemo_id);
        return WE_STATUS_OK;
    case CMD_SET_INSIGHTHOME_SETTINGS:
        if (payload_size < (int)sizeof(struct we_insight_home_settings)) {
            return WE_STATUS_INVALID;
        }
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) SetInsightHomeSettings command");
        wemoCtrlSetInsightHomeSettings(wemo_id, (struct we_insight_home_settings *)ipc_data);
        return WE_STATUS_OK;
    case CMD_GET_INSIGHT_PARAMS:
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) GetInsightParams command");
        wemoCtrlGetInsightParams(wemo_id);
        return WE_STATUS_OK;
    case CMD_SET_POWER_THRESHOLD:
        if (payload_size < (int)sizeof(struct we_insight_threshold)) {
            return WE_STATUS_INVALID;
        }
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) SetPowerThreshold command");
        wemoCtrlSetPowerThreshold(wemo_id, (struct we_insight_threshold *)ipc_data);
        return WE_STATUS_OK;
    case CMD_GET_POWER_THRESHOLD:
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) GetPowerThreshold command");
        wemoCtrlGetPowerThreshold(wemo_id);
        return WE_STATUS_OK;
    case CMD_GET_DATA_EXPORTINFO:
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) GetDataExportInfo command");
        wemoCtrlGetDataExportInfo(wemo_id);
        return WE_STATUS_OK;
    case CMD_SCHEDULE_DATA_EXPORT:
        if (payload_size < (int)sizeof(struct we_insight_export)) {
            return WE_STATUS_INVALID;
        }
        LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) ScheduleDataExport command");
        wemoCtrlScheduleDataExport(wemo_id, (struct we_insight_export *)ipc_data);
        return WE_STATUS_OK;
    default:
        LOG_DEBUG_MSG("wemo_ctrl (wemo_ipc_server) Invalid command!");
        return WE_STATUS_UNSUPPORTED;
    }
}

static fd_status_t on_peer_ready_recv(int sockfd)
{
    int i;
    int rc;
    int frame_offset = 0;
    peer_state_t *peerstate = NULL;

    if (connection_no > MAX_CLIENTS) {
        LOG_ERROR_MSG("invalid connection_no=%d (max=%d)", connection_no, MAX_CLIENTS);
        connection_no = MAX_CLIENTS;
    }

    for (i = 0; i < MAX_CLIENTS; i++) {
        if (global_state[i].sockfd == sockfd) {
            peerstate = &global_state[i];
            break;
        }
    }
    if (peerstate == NULL || peerstate->sockfd == -1) {
        return fd_status_NORW;
    }

    while (1) {
        int room = RECVBUF_SIZE - peerstate->recvoff;
        if (room <= 0) {
            break;
        }
        rc = recv(sockfd, peerstate->recvbuf + peerstate->recvoff, (size_t)room, 0);
        if (rc > 0) {
            peerstate->recvoff += rc;
            continue;
        }
        if (rc == 0) {
            peerstate->state = DISCONNECTED;
            LOG_INFO_MSG("wemo_ctrl (wemo_ipc_server) connection from client ends");
            return fd_status_NORW;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        LOG_ERROR_MSG("ready_recv : failed to read stream message");
        return fd_status_NORW;
    }

    while ((peerstate->recvoff - frame_offset) >= (int)sizeof(struct we_ipc_hdr)) {
        struct we_ipc_hdr ipchdr;
        int frame_len;

        memcpy(&ipchdr, peerstate->recvbuf + frame_offset, sizeof(ipchdr));
        if (ipchdr.size < 0 || ipchdr.size > IPC_DATA_MAX) {
            LOG_ERROR_MSG("Invalid ipc_data size: %d", ipchdr.size);
            return fd_status_NORW;
        }
        frame_len = (int)sizeof(struct we_ipc_hdr) + ipchdr.size;
        if (frame_len > RECVBUF_SIZE) {
            LOG_ERROR_MSG("Invalid frame length: %d", frame_len);
            return fd_status_NORW;
        }
        if ((peerstate->recvoff - frame_offset) < frame_len) {
            break;
        }

        if (wemo_ipc_process_message(sockfd,
                                     &ipchdr,
                                     peerstate->recvbuf + frame_offset + sizeof(struct we_ipc_hdr)) != 0) {
            return fd_status_NORW;
        }
        frame_offset += frame_len;
    }

    if (frame_offset > 0) {
        int remaining = peerstate->recvoff - frame_offset;
        if (remaining > 0) {
            memmove(peerstate->recvbuf, peerstate->recvbuf + frame_offset, (size_t)remaining);
        }
        peerstate->recvoff = remaining;
    } else if (peerstate->recvoff == RECVBUF_SIZE) {
        LOG_ERROR_MSG("Receive buffer full without complete frame");
        return fd_status_NORW;
    }

    return fd_status_RW;
}

static int wemo_ipc_process_message(int sockfd, const struct we_ipc_hdr *ipchdr, char *ipc_data)
{
    if (ipchdr == NULL) {
        return -1;
    }

    if (ipchdr->cmd == CMD_PROTO) {
        struct we_proto_hdr *proto = NULL;
        char *proto_payload = NULL;
        struct we_ipc_hdr rsp;
        struct we_proto_hdr rsp_proto;
        char rsp_data[sizeof(struct we_proto_hdr) + sizeof(struct we_health_snapshot)];
        int rsp_size = sizeof(struct we_proto_hdr);
        int status = WE_STATUS_INVALID;
        uint32_t rsp_payload_len = 0;
        struct we_health_snapshot health_snapshot;

        if (ipchdr->size < (int)sizeof(struct we_proto_hdr)) {
            LOG_ERROR_MSG("CMD_PROTO payload too short (%d)", ipchdr->size);
            return 0;
        }
        proto = (struct we_proto_hdr *)ipc_data;
        if (proto->magic != WE_PROTO_MAGIC || proto->version != WE_PROTO_VERSION) {
            LOG_ERROR_MSG("CMD_PROTO invalid magic/version (%u/%u)", proto->magic, proto->version);
            status = WE_STATUS_INVALID;
        } else if ((int)(sizeof(struct we_proto_hdr) + proto->payload_len) > ipchdr->size) {
            LOG_ERROR_MSG("CMD_PROTO invalid payload_len=%u size=%d", proto->payload_len, ipchdr->size);
            status = WE_STATUS_INVALID;
        } else if (proto->msg_type != WE_MSG_REQUEST) {
            LOG_ERROR_MSG("CMD_PROTO unsupported msg_type=%u", proto->msg_type);
            status = WE_STATUS_UNSUPPORTED;
        } else {
            if (proto->payload_len > 0) {
                proto_payload = ipc_data + sizeof(struct we_proto_hdr);
            }
            proto_route_record(proto->request_id, proto->client_id, proto->wemo_id, proto->op, sockfd);
            LOG_INFO_MSG("ipc request proto request_id=%u cmd=%s(%d) wemo_id=%d payload_len=%u",
                         proto->request_id,
                         ipc_cmd_to_string(proto->op),
                         proto->op,
                         proto->wemo_id,
                         proto->payload_len);
            if (proto->op == CMD_GET_HEALTH_SNAPSHOT) {
                struct we_health_query query;
                memset(&query, 0, sizeof(query));
                if (proto->payload_len >= sizeof(query) && proto_payload != NULL) {
                    memcpy(&query, proto_payload, sizeof(query));
                }
                status = wemo_ctrl_get_health_snapshot(query.wemo_id, query.max_items, &health_snapshot);
                if (status == WE_STATUS_OK) {
                    rsp_payload_len = sizeof(health_snapshot);
                    memcpy(rsp_data + sizeof(struct we_proto_hdr), &health_snapshot, sizeof(health_snapshot));
                    rsp_size += (int)rsp_payload_len;
                }
            } else {
                if (proto->op == CMD_SET &&
                    proto_payload != NULL &&
                    proto->payload_len >= sizeof(struct we_set_idempotent_request)) {
                    const struct we_set_idempotent_request *req =
                        (const struct we_set_idempotent_request *)proto_payload;
                    int cached_status = WE_STATUS_OK;
                    if (set_idempotency_lookup(proto->client_id, proto->wemo_id,
                                               req->idempotency_key, &cached_status)) {
                        LOG_INFO_MSG("idempotent hit client_id=%u request_id=%u wemo_id=%d key=%llu status=%s(%d)",
                                     proto->client_id,
                                     proto->request_id,
                                     proto->wemo_id,
                                     (unsigned long long)req->idempotency_key,
                                     ipc_status_to_string(cached_status),
                                     cached_status);
                        status = cached_status;
                    } else {
                        status = wemo_ipc_handle_command(proto->op,
                                                         proto->wemo_id,
                                                         (char *)&req->state,
                                                         (int)sizeof(req->state),
                                                         proto->request_id,
                                                         1);
                        set_idempotency_record(proto->client_id, proto->wemo_id,
                                               req->idempotency_key, status);
                    }
                } else {
                status = wemo_ipc_handle_command(proto->op,
                                                 proto->wemo_id,
                                                 proto_payload,
                                                 (int)proto->payload_len,
                                                 proto->request_id,
                                                 1);
                }
            }
        }

        memset(&rsp_proto, 0, sizeof(rsp_proto));
        rsp_proto.magic = WE_PROTO_MAGIC;
        rsp_proto.version = WE_PROTO_VERSION;
        rsp_proto.msg_type = WE_MSG_RESPONSE;
        rsp_proto.client_id = proto ? proto->client_id : 0;
        rsp_proto.request_id = proto ? proto->request_id : 0;
        rsp_proto.op = proto ? proto->op : 0;
        rsp_proto.wemo_id = proto ? proto->wemo_id : ipchdr->wemo_id;
        rsp_proto.status = status;
        rsp_proto.payload_len = rsp_payload_len;

        memcpy(rsp_data, &rsp_proto, sizeof(rsp_proto));
        rsp.wemo_id = rsp_proto.wemo_id;
        rsp.cmd = EVENT_PROTO;
        rsp.size = rsp_size;
        LOG_INFO_MSG("ipc response proto request_id=%u cmd=%s(%d) wemo_id=%d status=%s(%d)",
                     rsp_proto.request_id,
                     ipc_cmd_to_string(rsp_proto.op),
                     rsp_proto.op,
                     rsp_proto.wemo_id,
                     ipc_status_to_string(rsp_proto.status),
                     rsp_proto.status);
        wemo_ipc_send_to_sock(sockfd, &rsp, rsp_data);
    } else {
        int legacy_status = wemo_ipc_handle_command(ipchdr->cmd,
                                                    ipchdr->wemo_id,
                                                    ipc_data,
                                                    ipchdr->size,
                                                    0,
                                                    0);
        LOG_INFO_MSG("ipc request legacy cmd=%s(%d) wemo_id=%d payload_len=%d status=%s(%d)",
                     ipc_cmd_to_string(ipchdr->cmd),
                     ipchdr->cmd,
                     ipchdr->wemo_id,
                     ipchdr->size,
                     ipc_status_to_string(legacy_status),
                     legacy_status);
    }

    return 0;
}

static fd_status_t on_peer_ready_send(int sockfd)
{
    int i = 0;
    int sem_value = 0;

    if (connection_no > MAX_CLIENTS) {
        LOG_ERROR_MSG("invalid connection_no=%d (max=%d)", connection_no, MAX_CLIENTS);
        connection_no = MAX_CLIENTS;
    }

    for (i = 0; i < MAX_CLIENTS; i++) {
        peer_state_t* peerstate = &global_state[i];
        if (peerstate->sockfd == -1) {
            continue;
        }
        if (peerstate->sockfd == sockfd) {
            LOG_DEBUG_MSG("sockfd = %d, sendlen = %d", peerstate->sockfd, peerstate->sendlen);

            if (peerstate->sendlen == 0) {
                return fd_status_R;
            }

            int pos = 0;

            while (1) {
                int nsent = send(sockfd, &peerstate->sendbuf[pos], peerstate->sendlen, 0);
                if (nsent == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        sem_post(&peerstate->sem);
                        return fd_status_W;
                    }
                    else {
                        LOG_ERROR_MSG("ready_send : failed to send data");
                        sem_post(&peerstate->sem);
                        sem_getvalue(&peerstate->sem, &sem_value);
                        LOG_DEBUG_MSG("ready_send failed, semaphore value=%d", sem_value);
                        return fd_status_NORW;
                    }
                }

                if (nsent < peerstate->sendlen) {
                    LOG_DEBUG_MSG("need to send more data = [%d]", peerstate->sendlen - nsent);
                    pos = nsent;
                    peerstate->sendlen = peerstate->sendlen - nsent;
                    continue;
                }
                else {
                    // Everything was sent successfully; reset the send queue.
                    memset(peerstate->sendbuf, 0x00, SENDBUF_SIZE);
                    peerstate->sendlen = 0;

                    sem_post(&peerstate->sem);
                    sem_getvalue(&peerstate->sem, &sem_value);
                    LOG_DEBUG_MSG("send complete, semaphore value=%d", sem_value);
                    return fd_status_RW;
                }
            }
        }
    }
    return fd_status_R;
}

void *wemo_ipc_server(void *args)
{
    int i = 0;
    int listener_sock;

    listener_sock = listen_socket();

    LOG_INFO_MSG("Starting ipc_server - listener_sock = [%d]", listener_sock);
    if (listener_sock == -1) {
        exit(1);
    }

    make_socket_non_blocking(listener_sock);

    epollfd = epoll_create1(0);

    if (epollfd < 0) {
        LOG_ERROR_MSG("error : failed to call epoll_create1");
        exit(1);
    }

    LOG_DEBUG_MSG("epollfd = [%d]", epollfd);

    struct epoll_event accept_event;

    memset(&accept_event, 0, sizeof(struct epoll_event));
    accept_event.data.fd = listener_sock;
    accept_event.events = EPOLLIN;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listener_sock, &accept_event) < 0) {
        LOG_ERROR_MSG("error: failed to call epoll_ctl EPOLL_CTL_ADD");
        exit(1);
    }

    struct epoll_event* events = calloc(MAX_CLIENTS + 1, sizeof(struct epoll_event));
    if (events == NULL) {
        LOG_ERROR_MSG("Unable to allocate memory for epoll_events");
        exit(1);
    }

    while (1) {
        int nready = epoll_wait(epollfd, events, MAX_CLIENTS + 1, -1);

        if (nready != 0)
            LOG_DEBUG_MSG("nready = [%d]", nready);

        for (i = 0; i < nready; i++) {
            if (events[i].events & EPOLLERR) {
                int fd = events[i].data.fd;
                LOG_ERROR_MSG("error : epoll_wait returned EPOLLERR on fd=%d", fd);
                if (fd >= 0) {
                    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
                        LOG_ERROR_MSG("EPOLLERR : failed to call epoll_ctl EPOLL_CTL_DEL");
                    }
                    on_peer_closed(fd);
                }
                continue;
            }

            LOG_DEBUG_MSG("events[%d].data.fd = [%d]\n", i, events[i].data.fd);

            if (events[i].data.fd == listener_sock) {
                LOG_DEBUG_MSG("listen and accept socket");
                // This listening socket is ready, it means that new peer client is conneting to the wemo_ctrl's ipc server.
                int msgsock = accept(listener_sock, 0, 0);
                if (msgsock < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // This can happen due to the nonblocking socket mode; in this
                        // case don't do anything, but print a notice
                        LOG_ERROR_MSG("accept returned EAGAIN or EWOULDBLOCK");
                    }
                    else {
                        LOG_ERROR_MSG("error : failed to accept a new connection from the peer");
                    }
                }
                else {
                    LOG_DEBUG_MSG("making the msgsock = [%d] as nonblocking mode", msgsock);
                    make_socket_non_blocking(msgsock);
                    if (connection_no >= MAX_CLIENTS) {
                        LOG_ERROR_MSG("connection number (%d) >= MAX_CLIENTS (%d)", connection_no, MAX_CLIENTS);
                    }

                    // Ready to read data from peer client.
                    fd_status_t status = on_peer_connected(connection_no, msgsock);

                    struct epoll_event event = {0};
                    event.data.fd = msgsock;

                    if (status.want_read) {
                        event.events |= EPOLLIN;
                    }
                    if (status.want_write) {
                        event.events |= EPOLLOUT;
                    }

                    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, msgsock, &event) < 0) {
                        LOG_ERROR_MSG("error : epoll_ctl EPOLL_CTL_ADD");
                        exit(1);
                    }
                    LOG_INFO_MSG("connect : fd = [%d], no = [%d]", event.data.fd, connection_no);
                    connection_no++;
                }
            }
            else {
                // A peer socket is ready.
                if (events[i].events & EPOLLIN) {
                    // Ready for reading.
                    int fd = events[i].data.fd;

                    LOG_DEBUG_MSG("call on_peer_ready_recv(%d)", fd);

                    fd_status_t status = on_peer_ready_recv(fd);

                    struct epoll_event event = {0};
                    event.data.fd = fd;

                    if (status.want_read) {
                        event.events |= EPOLLIN;
                    }
                    if (status.want_write) {
                        event.events |= EPOLLOUT;
                    }
                    if (event.events == 0) {
                        LOG_INFO_MSG("socket = [%d] closing", fd);
                        if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
                            LOG_ERROR_MSG("EPOLLIN : failed to call epoll_ctl EPOLL_CTL_DEL");
                        }
                        on_peer_closed(fd);
                    }
                    else if (epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event) < 0) {
                        LOG_ERROR_MSG("EPOLLIN : failed to call epoll_ctl EPOLL_CTL_MOD");
                    }
                } else if (events[i].events & EPOLLOUT) {
                    // Ready for writing.
                    int fd = events[i].data.fd;

                    LOG_DEBUG_MSG("call on_peer_ready_send(%d)", fd);

                    fd_status_t status = on_peer_ready_send(fd);

                    struct epoll_event event = {0};
                    event.data.fd = fd;

                    if (status.want_read) {
                        event.events |= EPOLLIN;
                    }
                    if (status.want_write) {
                        event.events |= EPOLLOUT;
                    }
                    if (event.events == 0) {
                        LOG_INFO_MSG("socket = [%d] closing", fd);
                        if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
                            LOG_ERROR_MSG("EPOLLOUT : failed to call epoll_ctl EPOLL_CTL_DEL");
                        }
                        on_peer_closed(fd);
                    }
                    else if (epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event) < 0) {
                        LOG_ERROR_MSG("EPOLLOUT : failed to call epoll_ctl EPOLL_CTL_MOD");
                    }
                }
            }
        }

        if (wemoTakeDiscoverRequest()) {
            LOG_INFO_MSG("discover requested; running refresh");
            wemoCtrlPointRefresh();
        }
    }
    close(listener_sock);

    return NULL;
}

static int wemo_ipc_send(struct we_ipc_hdr *ipchdr, char *ipc_data)
{
    return wemo_ipc_send_internal(-1, ipchdr, ipc_data);
}

static int wemo_ipc_send_to_sock(int sockfd, struct we_ipc_hdr *ipchdr, char *ipc_data)
{
    return wemo_ipc_send_internal(sockfd, ipchdr, ipc_data);
}

static int wemo_ipc_send_internal(int target_sockfd, struct we_ipc_hdr *ipchdr, char *ipc_data)
{
    int i, rc = 0;
    struct timespec ts;
    int s;
    int frame_size;
    int sent_any = 0;

    if (ipchdr == NULL) {
        return -1;
    }
    if (ipchdr->size < 0 || ipchdr->size > IPC_DATA_MAX) {
        LOG_ERROR_MSG("ipc send invalid payload size=%d cmd=%d", ipchdr->size, ipchdr->cmd);
        return -1;
    }
    if (ipchdr->size > 0 && ipc_data == NULL) {
        LOG_ERROR_MSG("ipc send missing payload cmd=%d size=%d", ipchdr->cmd, ipchdr->size);
        return -1;
    }
    frame_size = (int)sizeof(struct we_ipc_hdr) + ipchdr->size;
    if (frame_size > SENDBUF_SIZE) {
        LOG_ERROR_MSG("ipc send frame too large=%d (max=%d) cmd=%d", frame_size, SENDBUF_SIZE, ipchdr->cmd);
        return -1;
    }

    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        /* handle error */
        return -1;
    }

    ts.tv_sec += 3;

    for (i = 0; i < MAX_CLIENTS; i++) {
        if (target_sockfd >= 0 && global_state[i].sockfd != target_sockfd) {
            continue;
        }
        if (global_state[i].state == CONNECTED) {
            if (global_state[i].sockfd != -1) {
                LOG_DEBUG_MSG("Try wait for semaphore[%d]...", i);
                while ((s = sem_timedwait(&global_state[i].sem, &ts)) == -1 && errno == EINTR)
                    continue;
                /* Check what happened */
                if (s == -1) {
                    if (errno == ETIMEDOUT) {
                        LOG_DEBUG_MSG("Wait timeout, move on...");
                        continue;
                    }
                    else {
                        LOG_DEBUG_MSG("sem_timedwait failed...");
                        continue;
                    }
                } else {
                    LOG_DEBUG_MSG("Move on...");
                }
                global_state[i].sendlen = frame_size;
                memcpy(global_state[i].sendbuf, (char* )ipchdr, sizeof(struct we_ipc_hdr));
                if (ipchdr->size > 0) {
                    memcpy(global_state[i].sendbuf + sizeof(struct we_ipc_hdr), (char *)ipc_data, (size_t)ipchdr->size);
                }

                struct epoll_event event = {0};
                event.data.fd = global_state[i].sockfd;
                event.events |= EPOLLOUT;
                if (epoll_ctl(epollfd, EPOLL_CTL_MOD, global_state[i].sockfd, &event) < 0) {
                    LOG_ERROR_MSG("ipc_send_event EPOLLOUT : failed to call epoll_ctl EPOLL_CTL_MOD");
                    // If epoll_ctl is failed to modify the event attribute to send data, call send() function directly.
                    rc = send(global_state[i].sockfd, global_state[i].sendbuf, global_state[i].sendlen, 0);
                    if (rc != global_state[i].sendlen) {
                        LOG_ERROR_MSG("error sending event");
                        if (errno == EPIPE || errno == EBADF || errno == ECONNRESET) {
                            if (epoll_ctl(epollfd, EPOLL_CTL_DEL, global_state[i].sockfd, NULL) < 0) {
                                LOG_ERROR_MSG("ipc_send_event : failed to call epoll_ctl EPOLL_CTL_DEL");
                            }
                            on_peer_closed(global_state[i].sockfd);
                        }
                    }
                }
                sent_any = 1;
                if (target_sockfd >= 0) {
                    break;
                }
            }
        }
    }
    if (target_sockfd >= 0 && !sent_any) {
        return -1;
    }
    return rc;
}

void wemo_ipc_send_event(int wemo_id, struct we_state *state_buffer)
{
    struct we_ipc_hdr ipchdr;

    ipchdr.wemo_id = wemo_id;
    ipchdr.cmd = EVENT_STATE;
    ipchdr.size = sizeof(struct we_state);

    wemo_ipc_send(&ipchdr, (char *) state_buffer);
}

void wemo_ipc_send_netstate(int wemo_id, struct we_network_status *net_state)
{
    struct we_ipc_hdr ipchdr;

    ipchdr.wemo_id = wemo_id;
    ipchdr.cmd = EVENT_CONNECTION_STATE;
    ipchdr.size = sizeof(struct we_network_status);

    wemo_ipc_send(&ipchdr, (char *) net_state);
}

void wemo_ipc_send_devinfo(int wemo_id, char *data)
{
    struct we_ipc_hdr ipchdr;

    ipchdr.wemo_id = wemo_id;
    ipchdr.cmd = EVENT_DEVICE_INFO;
    ipchdr.size = strlen(data) + 1;

    wemo_ipc_send(&ipchdr, (char *) data);
}

void wemo_ipc_send_name_change(int wemo_id, struct we_name_change *name_change)
{
    struct we_ipc_hdr ipchdr;

    ipchdr.wemo_id = wemo_id;
    ipchdr.cmd = EVENT_NAME_CHANGE;
    ipchdr.size = sizeof(struct we_name_change);

    wemo_ipc_send(&ipchdr, (char *) name_change);
}

void wemo_ipc_send_name_value(int wemo_id, struct we_name_value *name_value)
{
    struct we_ipc_hdr ipchdr;

    ipchdr.wemo_id = wemo_id;
    ipchdr.cmd = EVENT_NAME_VALUE;
    ipchdr.size = sizeof(struct we_name_value);

    wemo_ipc_send(&ipchdr, (char *) name_value);
}

void wemo_ipc_send_insight_home_settings(int wemo_id, struct we_insight_home_settings *settings)
{
    struct we_ipc_hdr ipchdr;

    ipchdr.wemo_id = wemo_id;
    ipchdr.cmd = EVENT_INSIGHT_HOME_SETTINGS;
    ipchdr.size = sizeof(struct we_insight_home_settings);

    wemo_ipc_send(&ipchdr, (char *) settings);
}

void wemo_ipc_server_init()
{
    ithread_t wemo_ipc_thread;
    run_server = 1;

    ithread_create(&wemo_ipc_thread, NULL, wemo_ipc_server, NULL);
    ithread_detach(wemo_ipc_thread);
}

void wemo_ipc_server_finish()
{
    run_server = 0;
    broker_stop_all();
}
