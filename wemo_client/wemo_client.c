#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include "aes.h"
#include "wemo_engine.h"

#define DEVICE_TABLE "wemo_device"
#define STATE_TABLE "state"

#define CONFIG_FILE_PATH "/etc/wemo_ctrl.conf"
#define DEFAULT_STATE_DIR_ROOT "/var/lib/wemo-matter"
#define DEFAULT_STATE_DIR_HOME ".local/state/wemo-matter"
#define DEFAULT_STATE_DIR_FALLBACK "/var/tmp/wemo-matter"
#define DEFAULT_IFNAME "eth2"

char wemo_device_db[128];
char wemo_state_db[128];
char upnp_ifname[16];
static int ifname_set = 0;
static char ipc_host[64] = IPC_DEFAULT_HOST;
static int ipc_port = IPC_DEFAULT_PORT;
static int client_quiet = 0;
static int client_quiet_all = 0;
static int confirm_timeout_ms = 12000;
static int serial_confirm_mode = 0;
enum cmdloop_cmds {
    HELP = 0,
    POWON,
    POWOFF,
    SETLEVEL,
    SETDIMMER,
    GETSTATE,
    PRTDEV,
    LSTDEV,
    DELDEV,
    FORGETDEV,
    SETUP,
    NETSTATE,
    CLOSESETUP,
    DISCOVER,
    FIRMUPDATE,
    SET_HKSETUP,
    CHANGE_NAME,
    RESET,
    RESTART_RULE,
    GET_INFORMATION,
    SCHEDULE_INSIGHT,
    GET_INSIGHT_EXPORT_INFO,
    SET_INSIGHT_THRESHOLD,
    GET_INSIGHT_THRESHOLD,
    SET_INSIGHT_HOME,
    GET_INSIGHT_HOME,
    HEALTH,
    HEALTHDEV,
    HEALTHCTRL,
    HEALTHDEVCTRL,
    HEALTHLOG,
    PREFLIGHT,
    PREFLIGHTALL,
    EXITCMD
};

struct cmdloop_commands {
    char *str;
    int cmdnum;
    int numargs;
    char *args;
} cmdloop_commands;

static struct cmdloop_commands cmdloop_cmdlist[] = {
    {"help", HELP, 1, ""},
    {"listdev", LSTDEV, 1, ""},
    {"printdev", PRTDEV, 2, "<devnum>"},
    {"poweron", POWON, 2, "<devnum>"},
    {"poweroff", POWOFF, 2, "<devnum>"},
    {"setlevel", SETLEVEL, 3, "<devnum> <level>"},
    {"setdimmer", SETDIMMER, 4, "<devnum> <0/1> <level>"},
    {"getstate", GETSTATE, 2, "<devnum>"},
    {"deletedev", DELDEV, 2, "<devnum>"},
    {"forgetdev", FORGETDEV, 2, "<devnum>"},
    {"setup", SETUP, 7, "<devnum> <ssid> <passphrase> <auth> <encrypt> <channel>"},
    {"getnetstate", NETSTATE, 2, "<devnum>"},
    {"closesetup", CLOSESETUP, 2, "<devnum>"},
    {"discover", DISCOVER, 1, ""},
    {"firmup", FIRMUPDATE, 5, "<devnum> <starttime> <withunsign> <url>"},
    {"set_hksetup", SET_HKSETUP, 3, "<devnum> <HK setup state>"},
    {"changename", CHANGE_NAME, 3, "<devnum> <new name>"},
    {"reset", RESET, 3, "<devnum> <reset type (1: soft, 2: full, 3:remote, 4: insight, 5: wifi)>"},
    {"restartrule", RESTART_RULE, 2, "<devnum>"},
    {"getinformation", GET_INFORMATION, 2, "<devnum>"},
    {"scheduledataexport", SCHEDULE_INSIGHT, 3, "<email> <export type> ONLY for Insight"},
    {"getexportinfo", GET_INSIGHT_EXPORT_INFO, 1, "ONLY for Insight"},
    {"setpowerthreshold", SET_INSIGHT_THRESHOLD, 2, "<threshold> ONLY for Insight"},
    {"getpowerthreshold", GET_INSIGHT_THRESHOLD, 1, "ONLY for Insight"},
    {"sethomesettings", SET_INSIGHT_HOME, 3, "<energyPerUnitCost> <currency> ONLY for Insight"},
    {"gethomesettings", GET_INSIGHT_HOME, 1, "ONLY for Insight"},
    {"health", HEALTH, 1, ""},
    {"healthdev", HEALTHDEV, 2, "<devnum>"},
    {"healthctrl", HEALTHCTRL, 1, ""},
    {"healthdevctrl", HEALTHDEVCTRL, 2, "<devnum>"},
    {"healthlog", HEALTHLOG, 1, ""},
    {"preflight", PREFLIGHT, 2, "<devnum>"},
    {"preflightall", PREFLIGHTALL, 1, ""},
    {"exit", EXITCMD, 1, ""}
};

static int run_cmdloop = 1;

static void set_default_db_paths(void)
{
    const char *home = getenv("HOME");
    const char *base_dir = NULL;

    if (geteuid() == 0) {
        base_dir = DEFAULT_STATE_DIR_ROOT;
    } else if (home != NULL && home[0] != '\0') {
        static char home_dir[PATH_MAX];
        if (snprintf(home_dir, sizeof(home_dir), "%s/%s", home, DEFAULT_STATE_DIR_HOME) < (int)sizeof(home_dir)) {
            base_dir = home_dir;
        } else {
            base_dir = DEFAULT_STATE_DIR_FALLBACK;
        }
    } else {
        base_dir = DEFAULT_STATE_DIR_FALLBACK;
    }

    if (snprintf(wemo_device_db, sizeof(wemo_device_db), "%s/%s", base_dir, "wemo_device.db") >= (int)sizeof(wemo_device_db) ||
        snprintf(wemo_state_db, sizeof(wemo_state_db), "%s/%s", base_dir, "wemo_state.db") >= (int)sizeof(wemo_state_db)) {
        strncpy(wemo_device_db, DEFAULT_STATE_DIR_FALLBACK "/wemo_device.db", sizeof(wemo_device_db) - 1);
        wemo_device_db[sizeof(wemo_device_db) - 1] = '\0';
        strncpy(wemo_state_db, DEFAULT_STATE_DIR_FALLBACK "/wemo_state.db", sizeof(wemo_state_db) - 1);
        wemo_state_db[sizeof(wemo_state_db) - 1] = '\0';
    }
}

static int get_serial_number(char *value, size_t value_len)
{
    const char *env = getenv("WEMO_SERIAL_NUMBER");
    if (env && env[0] != '\0') {
        strncpy(value, env, value_len - 1);
        value[value_len - 1] = '\0';
        return (int)strlen(value);
    }
    /* Fallback for non-embedded builds. */
    strncpy(value, "000000000000", value_len - 1);
    value[value_len - 1] = '\0';
    return (int)strlen(value);
}

static int read_first_line(const char *path, char *buf, size_t buflen)
{
    FILE *f = fopen(path, "r");
    size_t n;
    if (!f) {
        return -1;
    }
    if (!fgets(buf, (int)buflen, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    n = strlen(buf);
    if (n > 0 && buf[n - 1] == '\n') {
        buf[n - 1] = '\0';
    }
    return 0;
}

static int is_wireless(const char *ifname)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", ifname);
    return access(path, F_OK) == 0;
}

static int is_ethernet(const char *ifname)
{
    char path[256];
    char buf[32];
    snprintf(path, sizeof(path), "/sys/class/net/%s/type", ifname);
    if (read_first_line(path, buf, sizeof(buf)) != 0) {
        return 0;
    }
    /* ARPHRD_ETHER == 1 */
    if (strcmp(buf, "1") != 0) {
        return 0;
    }
    return !is_wireless(ifname);
}

static int is_up_or_unknown(const char *ifname)
{
    char path[256];
    char buf[32];
    snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", ifname);
    if (read_first_line(path, buf, sizeof(buf)) != 0) {
        return 0;
    }
    return (strcmp(buf, "up") == 0) || (strcmp(buf, "unknown") == 0);
}

static int get_default_route_ifname(char *out, size_t out_len)
{
    FILE *f = fopen("/proc/net/route", "r");
    char line[256];
    if (!f) {
        return -1;
    }
    /* Skip header */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    while (fgets(line, sizeof(line), f)) {
        char ifname[IFNAMSIZ];
        unsigned long dest = 0;
        unsigned long gateway = 0;
        unsigned long flags = 0;
        if (sscanf(line, "%15s %lx %lx %lx", ifname, &dest, &gateway, &flags) == 4) {
            (void)gateway;
            if (dest == 0 && (flags & 0x2)) {
                strncpy(out, ifname, out_len - 1);
                out[out_len - 1] = '\0';
                fclose(f);
                return 0;
            }
        }
    }
    fclose(f);
    return -1;
}

static int choose_preferred_ifname(char *out, size_t out_len)
{
    DIR *d = opendir("/sys/class/net");
    struct dirent *ent;
    char best_bridge[IFNAMSIZ] = {0};
    char best_eth[IFNAMSIZ] = {0};
    char best_en[IFNAMSIZ] = {0};
    char best_other[IFNAMSIZ] = {0};

    if (d) {
        /* Prefer br-lan, then ethernet: eth* then en* then other. */
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') {
                continue;
            }
            if (strcmp(ent->d_name, "lo") == 0) {
                continue;
            }
            if (strcmp(ent->d_name, "br-lan") == 0 && is_up_or_unknown(ent->d_name)) {
                strncpy(best_bridge, ent->d_name, sizeof(best_bridge) - 1);
                break;
            }
            if (is_ethernet(ent->d_name) && is_up_or_unknown(ent->d_name)) {
                if (strncmp(ent->d_name, "eth", 3) == 0) {
                    strncpy(best_eth, ent->d_name, sizeof(best_eth) - 1);
                    break;
                }
                if (strncmp(ent->d_name, "en", 2) == 0 && best_en[0] == '\0') {
                    strncpy(best_en, ent->d_name, sizeof(best_en) - 1);
                } else if (best_other[0] == '\0') {
                    strncpy(best_other, ent->d_name, sizeof(best_other) - 1);
                }
            }
        }
        closedir(d);
    }

    if (best_bridge[0] == '\0' && best_eth[0] == '\0' && best_en[0] == '\0' && best_other[0] == '\0') {
        /* Fallback to default route interface. */
        if (get_default_route_ifname(best_other, sizeof(best_other)) != 0) {
            return -1;
        }
    }

    if (best_bridge[0] != '\0') {
        strncpy(out, best_bridge, out_len - 1);
    } else if (best_eth[0] != '\0') {
        strncpy(out, best_eth, out_len - 1);
    } else if (best_en[0] != '\0') {
        strncpy(out, best_en, out_len - 1);
    } else {
        strncpy(out, best_other, out_len - 1);
    }
    out[out_len - 1] = '\0';
    return 0;
}

static int get_macaddr_no_colon(const char *interface, char *mac, int mac_len)
{
    int s;
    struct ifreq buffer;
    int i = 0;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        fprintf(stderr, "%s: Error in creating socket for getting mac address", __FUNCTION__);
        return s;
    }

    memset(&buffer, 0x00, sizeof(buffer));

    strcpy(buffer.ifr_name, interface);

    ioctl(s, SIOCGIFHWADDR, &buffer);

    close(s);

    snprintf(mac, mac_len, "%02x%02x%02x%02x%02x%02x",
            (unsigned char)buffer.ifr_hwaddr.sa_data[0],
            (unsigned char)buffer.ifr_hwaddr.sa_data[1],
            (unsigned char)buffer.ifr_hwaddr.sa_data[2],
            (unsigned char)buffer.ifr_hwaddr.sa_data[3],
            (unsigned char)buffer.ifr_hwaddr.sa_data[4],
            (unsigned char)buffer.ifr_hwaddr.sa_data[5]);

    for (i = 0; i < strlen(mac); i++) {
        mac[i] = toupper(mac[i]);
    }

    return 0;
}

static int get_password_key(char *key, int key_len)
{
    size_t i;

    char serial[32];
    char key_data[64];
    char ra0_mac_addr[13];
    /* bVduaWFyZkllaWVAb3RjbHAkcm9uT2Jh */
    const char string[] = "bVdu";
    const char string1[] = "aWFy";
    const char string2[] = "Zkll";
    const char string3[] = "aWVA";
    const char string4[] = "b3Rj";
    const char string5[] = "bHAk";
    const char string6[] = "cm9u";
    const char string7[] = "T2Jh";

    memset(key, 0, key_len);
    memset(key_data, 0, sizeof(key_data));
    memset(serial, 0, sizeof(serial));
    memset(ra0_mac_addr, 0, sizeof(ra0_mac_addr));

    if (upnp_ifname[0] != '\0') {
        get_macaddr_no_colon(upnp_ifname, ra0_mac_addr, sizeof(ra0_mac_addr));
    } else {
        get_macaddr_no_colon("eth0", ra0_mac_addr, sizeof(ra0_mac_addr));
    }

    if (get_serial_number(serial, sizeof(serial)) == 0) {
        fprintf(stderr, "%s : Error getting serial number", __FUNCTION__);
        return 0;
    }

    /* copy 3 MSB of the MAC address */
    memcpy(key_data, ra0_mac_addr, 3);
    /* 9-11 */
    strncat(key_data, ra0_mac_addr + 9, 3);

    /* Append the  serial number */
    strncat(key_data, serial, sizeof(key_data) - strlen(key_data) - 1);

    strncat(key_data, string, 4);
    strncat(key_data, string1, 4);
    strncat(key_data, string2, 4);
    strncat(key_data, string3, 4);
    strncat(key_data, string4, 4);
    strncat(key_data, string5, 4);
    strncat(key_data, string6, 4);
    strncat(key_data, string7, 4);

    /* 6 - 8 */
    strncat(key_data, ra0_mac_addr + 6, 3);
    /* 3 - 5 */
    strncat(key_data, ra0_mac_addr + 3, 3);

    for (i = 0; i < strlen(key_data); i++) {
        key[i] = key_data[i];
    }

    return 1;
}

#define PASSWORD_KEYDATA_LEN 256
#define PASSWORD_SALT_LEN   (8 + 1)
#define PASSWORD_IV_LEN     (16 + 1)

int encryptPassword(char *src, int src_len, char *dst, int dst_len)
{
    int len = 0;
    int cipher_len=0;
    int key_data_len, salt_len, iv_len;

    unsigned char key_data[PASSWORD_KEYDATA_LEN];
    unsigned char salt[PASSWORD_SALT_LEN];
    unsigned char iv[PASSWORD_IV_LEN];

    unsigned char *ciphertext = NULL;

    char *encStr = NULL;
    char lenstr[5];
    char basePassword[256];
    char password_key_data[64];

    memset(key_data, 0, sizeof(key_data));
    memset(salt, 0, sizeof(salt));
    memset(iv, 0, sizeof(iv));
    memset(basePassword, 0, sizeof(basePassword));
    memset(lenstr, 0, sizeof(lenstr));
    memset(password_key_data, 0, sizeof(password_key_data));
    memset(dst, 0, dst_len);

    if (!get_password_key(password_key_data, sizeof(password_key_data))) {
        fprintf(stderr, "%s : Failed to get password key", __FUNCTION__);
        return 0;
    }

    len = src_len;
    strncpy((char *)key_data, password_key_data, sizeof(key_data)-1);
    key_data_len = strlen((char *)key_data);
    memcpy(salt, password_key_data, PASSWORD_SALT_LEN-1);
    memcpy(iv, password_key_data, PASSWORD_IV_LEN-1);
    salt_len = strlen((char *)salt);
    iv_len = strlen((char *)iv);

    ciphertext = pluginAES128Encrypt(key_data, key_data_len, salt, salt_len, iv, iv_len, src, &len);
    if (!ciphertext) {
        fprintf(stderr, "%s : Failed to get cipher text", __FUNCTION__);
        return 0;
    }
    ciphertext[len] = '\0';

    encStr = base64Encode(ciphertext, len);
    cipher_len = strlen(encStr);

    if (cipher_len + 4 > dst_len) {
        fprintf(stderr, "%s : Error: Chiper length is bigger than dst buffer", __FUNCTION__);
        return 0;
    }

    snprintf(dst, dst_len, "%s%02X%02X", encStr, cipher_len, src_len);
    printf("%s: encrypted password = %s", __FUNCTION__, dst);

    free(ciphertext);
    free(encStr);

    return 1;
}

void event_callback(int wemo_id, struct we_state *data)
{
    if (client_quiet) {
        return;
    }
    printf("%s: wemo_id = %d, is_online = %d, state = %d, level = %d\n",
           __FUNCTION__, wemo_id, data->is_online, data->state, data->level);
}

void netstate_callback(int wemo_id, struct we_network_status *data)
{
    if (client_quiet) {
        return;
    }
    printf("%s: wemo_id = %d, netstate = %d\n",
           __FUNCTION__, wemo_id, data->connection_state);
}

void name_change_callback(int wemo_id, struct we_name_change *data)
{
    if (client_quiet) {
        return;
    }
    printf("%s: wemo_id = %d, name = %s\n",
           __FUNCTION__, wemo_id, data->name);
}

void name_value_callback(int wemo_id, struct we_name_value *data)
{
    if (client_quiet) {
        return;
    }
    printf("%s: wemo_id = %d, name = %s, value = %s\n",
           __FUNCTION__, wemo_id, data->name, data->value);
}

void health_callback(int wemo_id, const struct we_device_health *health)
{
    if (client_quiet_all || health == NULL) {
        return;
    }
    printf("health_event: wemo_id=%d health=%d timeout_streak=%d degraded=%d breaker_open=%d breaker_remaining_ms=%lld breaker_open_count=%u totals(applied=%u timeout=%u rejected=%u retries=%u last_retry=%d) latency_ms(ema=%d last=%d)\n",
           wemo_id,
           health->health_score,
           health->timeout_streak,
           health->degraded_mode,
           health->breaker_open,
           (long long)health->breaker_remaining_ms,
           health->breaker_open_count,
           health->total_applied,
           health->total_timeouts,
           health->total_rejected,
           health->total_retries,
           health->last_retry_count,
           health->ema_applied_latency_ms,
           health->last_applied_latency_ms);
}

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
    case CMD_NAME_VALUE: return "set_name_value";
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

static const char *txn_outcome_to_string(int outcome)
{
    switch (outcome) {
    case WE_TXN_ACCEPTED: return "accepted";
    case WE_TXN_APPLIED: return "applied";
    case WE_TXN_TIMEOUT: return "timeout";
    case WE_TXN_MISMATCH: return "mismatch";
    case WE_TXN_REJECTED: return "rejected";
    case WE_TXN_SEND_FAILED: return "send_failed";
    default: return "unknown";
    }
}

static int send_ipc_command(const char *label, int cmd, int wemo_id, const void *payload, int payload_len)
{
    uint32_t request_id = 0;
    int used_proto = 0;
    int rc = 0;
    struct we_txn_result txn;

    if (serial_confirm_mode) {
        int policy = we_default_confirm_policy_for_cmd(cmd);
        memset(&txn, 0, sizeof(txn));
        rc = we_run_command_txn(cmd, wemo_id, payload, payload_len, NULL,
                                confirm_timeout_ms, policy, &txn);
        if (!client_quiet_all) {
            printf("cmd_txn: cmd=%s(%d) wemo_id=%d policy=%d outcome=%s(%d) response=%s(%d) request_id=%u elapsed_ms=%d retries=%d\n",
                   label ? label : ipc_cmd_to_string(cmd),
                   cmd,
                   wemo_id,
                   txn.policy,
                   txn_outcome_to_string(txn.outcome),
                   txn.outcome,
                   ipc_status_to_string(txn.response_status),
                   txn.response_status,
                   txn.request_id,
                   txn.elapsed_ms,
                   txn.retry_count);
        }
        return (rc == WE_STATUS_OK);
    }

    rc = we_send_command_ex(cmd, wemo_id, payload, payload_len, &request_id, &used_proto);

    if (!client_quiet_all) {
        printf("cmd_dispatch: cmd=%s(%d) wemo_id=%d transport=%s request_id=%u send=%s\n",
               label ? label : ipc_cmd_to_string(cmd),
               cmd,
               wemo_id,
               used_proto ? "proto" : "legacy",
               request_id,
               rc ? "ok" : "failed");
    }
    return rc;
}

void proto_callback(const struct we_proto_hdr *hdr, const void *payload)
{
    const struct we_broker_completion *completion;

    if (client_quiet_all || hdr == NULL) {
        return;
    }

    if (hdr->msg_type == WE_MSG_RESPONSE) {
        printf("cmd_response: request_id=%u cmd=%s(%d) wemo_id=%d status=%s(%d) payload_len=%u\n",
               hdr->request_id,
               ipc_cmd_to_string(hdr->op),
               hdr->op,
               hdr->wemo_id,
               ipc_status_to_string(hdr->status),
               hdr->status,
               hdr->payload_len);
        return;
    }

    if (hdr->msg_type != WE_MSG_EVENT) {
        return;
    }

    if (payload == NULL || hdr->payload_len < sizeof(struct we_broker_completion)) {
        printf("cmd_event: request_id=%u cmd=%s(%d) wemo_id=%d invalid_payload_len=%u\n",
               hdr->request_id,
               ipc_cmd_to_string(hdr->op),
               hdr->op,
               hdr->wemo_id,
               hdr->payload_len);
        return;
    }

    completion = (const struct we_broker_completion *)payload;
    printf("cmd_event: request_id=%u job_id=%u cmd=%s(%d) wemo_id=%d outcome=%d status=%s(%d) latency_ms=%d\n",
           completion->request_id,
           completion->job_id,
           ipc_cmd_to_string(completion->cmd),
           completion->cmd,
           completion->wemo_id,
           completion->outcome,
           ipc_status_to_string(completion->status),
           completion->status,
           completion->latency_ms);
}

static void print_confirm_result(const char *label, int wemo_id, int status)
{
    if (client_quiet_all) {
        return;
    }
    printf("cmd_confirm: cmd=%s wemo_id=%d status=%s(%d)\n",
           label, wemo_id, ipc_status_to_string(status), status);
}

static void dispatch_set_command(const char *label, int wemo_id, struct we_state *state)
{
    if (serial_confirm_mode) {
        struct we_txn_result txn;
        int rc;
        memset(&txn, 0, sizeof(txn));
        rc = we_run_command_txn(CMD_SET, wemo_id, state, sizeof(*state),
                                state, confirm_timeout_ms, WE_CONFIRM_STATE_MATCH, &txn);
        if (!client_quiet_all) {
            printf("cmd_txn: cmd=%s(%d) wemo_id=%d policy=%d outcome=%s(%d) response=%s(%d) request_id=%u elapsed_ms=%d retries=%d\n",
                   label, CMD_SET, wemo_id, txn.policy,
                   txn_outcome_to_string(txn.outcome), txn.outcome,
                   ipc_status_to_string(txn.response_status), txn.response_status,
                   txn.request_id, txn.elapsed_ms, txn.retry_count);
        }
        print_confirm_result(label, wemo_id, rc);
    } else {
        send_ipc_command(label, CMD_SET, wemo_id, state, sizeof(struct we_state));
    }
}

void dev_info_callback(int wemo_id, struct we_dev_information *data)
{
    if (client_quiet) {
        return;
    }
    printf("%s: wemo_id = %d\n", __FUNCTION__, wemo_id);
    printf("\tproductName: %s\n", data->productName);
    printf("\tbinaryState: %d\n", data->binaryState);
    printf("\tbrightness: %d\n", data->brightness);
    printf("\tfader: %s\n", data->fader);
    printf("\thushMode: %s\n", data->hushMode);
    printf("\tOverTemp: %d\n", data->OverTemp);
    printf("\tnightMode: %d\n", data->nightMode);
    printf("\t\tstartTime: %ld\n", data->startTime);
    printf("\t\tendTime; %ld\n", data->endTime);
    printf("\t\tnightModeBrightness: %d\n", data->nightModeBrightness);
    printf("\tCountdownEndTime: %ld\n", data->CountdownEndTime);
    printf("\tlongPressRuleDeviceCnt: %d\n", data->longPressRuleDeviceCnt);
    printf("\tlongPressRuleAction: %d\n", data->longPressRuleAction);
    printf("\tlongPressRuleState: %d\n", data->longPressRuleState);
    printf("\tlongPressRuleDeviceUdn: %s\n",
           data->longPressRuleDeviceUdn? data->longPressRuleDeviceUdn : "empty");
}

void printhelp()
{
    printf("commands:\n");
    printf("\thelp\n");
    printf("\tlistdev\n");
    printf("\tprintdev <devnum>\n");
    printf("\tpoweron <devnum>\n");
    printf("\tpoweroff <devnum>\n");
    printf("\tsetlevel <devnum> <level>\n");
    printf("\tsetdimmer <devnum> <0/1> <level>\n");
    printf("\tgetstate <devnum>\n");
    printf("\tdeletedev <devnum>  (mark offline)\n");
    printf("\tforgetdev <devnum>  (hard delete from DB)\n");
    printf("\tsetup <devnum> <ssid> <passphrase> <auth> <encrypt> <channel>\n");
    printf("\tgetnetstate <devnum>\n");
    printf("\tclosesetup <devnum>\n");
    printf("\tdiscover\n");
    printf("\tfirmup <devnum> <starttime> <withunsign> <url>\n");
    printf("\tset_hksetup <devnum> <HK setup state>\n");
    printf("\tchangename <devnum> '<new name>'\n");
    printf("\treset <devnum> <reset type (1: soft, 2: full, 3:remote, 4: insight, 5: wifi)>\n");
    printf("\trestartrule <devnum>\n");
    printf("\tgetinformation <devnum>\n");
    printf("\tscheduledataexport <email> <export type> ONLY for Insight\n");
    printf("\tgetexportinfo (ONLY for Insight)\n");
    printf("\tsetpowerthreshold <threshold> (ONLY for Insight)\n");
    printf("\tgetpowerthreshold (ONLY for Insight)\n");
    printf("\tsethomesettings <energyPerUnitCost> <currency> (ONLY for Insight)\n");
    printf("\tgethomesettings (ONLY for Insight)\n");
    printf("\thealth\n");
    printf("\thealthdev <devnum>\n");
    printf("\thealthctrl\n");
    printf("\thealthdevctrl <devnum>\n");
    printf("\thealthlog\n");
    printf("\tpreflight <devnum>\n");
    printf("\tpreflightall\n");

    printf("\texit\n");
}

static void print_health_row(const struct we_device_health *h)
{
    if (h == NULL || client_quiet_all) {
        return;
    }
    printf("health: wemo_id=%d health=%d timeout_streak=%d degraded=%d breaker_open=%d breaker_remaining_ms=%lld breaker_open_count=%u totals(applied=%u timeout=%u rejected=%u retries=%u last_retry=%d) latency_ms(ema=%d last=%d)\n",
           h->wemo_id,
           h->health_score,
           h->timeout_streak,
           h->degraded_mode,
           h->breaker_open,
           (long long)h->breaker_remaining_ms,
           h->breaker_open_count,
           h->total_applied,
           h->total_timeouts,
           h->total_rejected,
           h->total_retries,
           h->last_retry_count,
           h->ema_applied_latency_ms,
           h->last_applied_latency_ms);
}

static void print_health_snapshot(void)
{
    struct we_device_health rows[64];
    int i;
    int count = we_get_device_health_snapshot(rows, (int)(sizeof(rows) / sizeof(rows[0])));
    if (count < 0) {
        if (!client_quiet_all) {
            printf("health: snapshot unavailable\n");
        }
        return;
    }
    if (count == 0) {
        if (!client_quiet_all) {
            printf("health: no tracked devices in this client session\n");
        }
        return;
    }
    for (i = 0; i < count; i++) {
        print_health_row(&rows[i]);
    }
}

static void print_health_device(int wemo_id)
{
    struct we_device_health row;
    int rc = we_get_device_health(wemo_id, &row);
    if (rc != WE_STATUS_OK) {
        if (!client_quiet_all) {
            printf("health: wemo_id=%d not tracked in this client session\n", wemo_id);
        }
        return;
    }
    print_health_row(&row);
}

static void print_health_snapshot_remote(void)
{
    struct we_device_health rows[WE_HEALTH_SNAPSHOT_MAX_ITEMS];
    int i;
    int count = we_get_device_health_snapshot_remote(0, rows,
                                                     (int)(sizeof(rows) / sizeof(rows[0])));
    if (count <= 0) {
        if (!client_quiet_all) {
            printf("healthctrl: snapshot unavailable\n");
        }
        return;
    }
    for (i = 0; i < count; i++) {
        print_health_row(&rows[i]);
    }
}

static void print_health_device_remote(int wemo_id)
{
    struct we_device_health rows[1];
    int count = we_get_device_health_snapshot_remote(wemo_id, rows, 1);
    if (count <= 0) {
        if (!client_quiet_all) {
            printf("healthctrl: wemo_id=%d unavailable\n", wemo_id);
        }
        return;
    }
    print_health_row(&rows[0]);
}

static void print_health_log(void)
{
    struct we_health_delta deltas[WE_HEALTH_DELTA_MAX_ITEMS];
    int i;
    int count = we_get_health_deltas(deltas, (int)(sizeof(deltas) / sizeof(deltas[0])));
    if (count <= 0) {
        if (!client_quiet_all) {
            printf("healthlog: no recent deltas\n");
        }
        return;
    }
    for (i = 0; i < count; i++) {
        const struct we_health_delta *d = &deltas[i];
        printf("health_log: ts_ms=%lld wemo_id=%d health=%d timeout_streak=%d degraded=%d breaker_open=%d totals(applied=%u timeout=%u rejected=%u retries=%u last_retry=%d)\n",
               (long long)d->ts_ms,
               d->health.wemo_id,
               d->health.health_score,
               d->health.timeout_streak,
               d->health.degraded_mode,
               d->health.breaker_open,
               d->health.total_applied,
               d->health.total_timeouts,
               d->health.total_rejected,
               d->health.total_retries,
               d->health.last_retry_count);
    }
}

static void print_preflight_row(const struct we_bridge_preflight_result *r)
{
    if (r == NULL || client_quiet_all) {
        return;
    }
    printf("preflight: wemo_id=%d ready=%d online=%d health=%d timeout_streak=%d breaker_open=%d totals(applied=%u timeout=%u)\n",
           r->wemo_id,
           r->ready,
           r->is_online,
           r->health_score,
           r->timeout_streak,
           r->breaker_open,
           r->total_applied,
           r->total_timeouts);
}

static void run_preflight_device(int wemo_id)
{
    struct we_bridge_preflight_result r;
    if (we_bridge_preflight_device(wemo_id, &r) != WE_STATUS_OK) {
        if (!client_quiet_all) {
            printf("preflight: wemo_id=%d unavailable\n", wemo_id);
        }
        return;
    }
    print_preflight_row(&r);
}

static void run_preflight_all(void)
{
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT wemo_id FROM wemo_device ORDER BY wemo_id ASC;";
    if (sqlite3_open(wemo_device_db, &db) != SQLITE_OK) {
        if (!client_quiet_all) {
            printf("preflightall: cannot open device db\n");
        }
        return;
    }
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            run_preflight_device(sqlite3_column_int(stmt, 0));
        }
    }
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
}

static int list_device_callback(void *data, int argc, char **argv, char **colName)
{
    if (client_quiet_all) {
        return 0;
    }
    int i;
    printf("%s: ", (const char *)data);
    for (i = 0; i < argc; i++) {
        printf("%s = %s\n", colName[i], argv[i]? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

static int print_device_callback(void *data, int argc, char **argv, char **colName)
{
    if (client_quiet_all) {
        return 0;
    }
    int i;
    printf("%s: ", (const char *)data);
    for (i = 0; i < argc; i++) {
        printf("%s = %s\n", colName[i], argv[i]? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

void wemo_list_devices()
{
    sqlite3 *db;
    char *errmsg = NULL;
    int rc;
    char *sql;
    const char *data = "wemo devices in DB";

    rc = sqlite3_open(wemo_device_db, &db);
    if (rc) {
        if (!client_quiet_all) {
            fprintf(stderr, "can't open database: %s\n", sqlite3_errmsg(db));
        }
        return;
    }
    sql = "SELECT * from wemo_device";
    rc = sqlite3_exec(db, sql, list_device_callback, (void *)data, &errmsg);
    if (rc != SQLITE_OK) {
        if (!client_quiet_all) {
            fprintf(stderr, "%s error: %s\n", __FUNCTION__, errmsg);
        }
        sqlite3_free(errmsg);
    }
    
    sqlite3_close(db);
}

void wemo_print_device(int wemo_id)
{
    sqlite3 *db;
    char *errmsg = NULL;
    int rc;
    char sql[256];
    const char *data = "wemo device";

    rc = sqlite3_open(wemo_device_db, &db);
    if (rc) {
        fprintf(stderr, "can't open database: %s\n", sqlite3_errmsg(db));
        return;
    }

    sprintf(sql, "SELECT * from wemo_device where wemo_id = %d", wemo_id);;
    rc = sqlite3_exec(db, sql, print_device_callback, (void *)data, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s error: %s\n", __FUNCTION__, errmsg);
        sqlite3_free(errmsg);
    }
    
    sqlite3_close(db);
}

void wemo_client_process_command(char *cmdline)
{
    char cmd[100];
    int arg_val_err = -99999;
    int arg1 = arg_val_err;
    int arg2 = arg_val_err;
    int arg3 = arg_val_err;
    int cmdnum = -1;
    int numofcmds = sizeof(cmdloop_cmdlist)/sizeof(cmdloop_commands);
    int cmdfound = 0;
    int i;
    int invalidargs = 0;
    int validargs;

    struct we_state state_buffer;
    struct we_network_status netstate;
    struct we_conn_data conn_data;
    struct we_firmware_data firm_data;
    struct we_hksetup_state hksetup_data;
    struct we_name_change name_data;
    struct we_reset reset_data;
    struct we_insight_export export_data;
    struct we_insight_threshold threshold;
    struct we_insight_home_settings settings;
    char passphrase[128];

    memset((void *)&state_buffer, 0, sizeof(struct we_state));
    memset((void *)&netstate, 0, sizeof(struct we_network_status));
    memset((void *)&conn_data, 0, sizeof(struct we_conn_data));
    memset((void *)&firm_data, 0, sizeof(struct we_firmware_data));
    memset((void *)&hksetup_data, 0, sizeof(struct we_hksetup_state));
    memset((void *)&name_data, 0, sizeof(struct we_name_change));
    memset((void *)&reset_data, 0, sizeof(struct we_reset));

    if (cmdline == NULL) {
        return;
    }

    if (strncmp(cmdline, "setup", 5) == 0) {
        validargs = sscanf(cmdline, "%s %d %s %s %s %s %d", cmd,
                           &arg1,
                           conn_data.ssid,
                           passphrase,
                           conn_data.auth,
                           conn_data.encrypt,
                           &conn_data.channel);
        encryptPassword(passphrase, strlen(passphrase),
                        conn_data.passphrase, sizeof(conn_data.passphrase));
    } else if (strncmp(cmdline, "firmup", 6) == 0) {
        validargs = sscanf(cmdline, "%s %d %ld %d %s", cmd, &arg1,
                           &firm_data.start_time, &firm_data.unsign_img,
                           firm_data.url);
    } else if (strncmp(cmdline, "changename", 10) == 0) {
        validargs = sscanf(cmdline, "%s %d '%[^']'", cmd, &arg1,
                           name_data.name);
    } else if (strncmp(cmdline, "reset", 5) == 0) {
        validargs = sscanf(cmdline, "%s %d %d", cmd, &arg1,
                           (int *)&reset_data.reset_type);
    } else if (strncmp(cmdline, "scheduledataexport", strlen("scheduledataexport")) == 0) {
        memset(&export_data, 0, sizeof(struct we_insight_export));
        validargs = sscanf(cmdline, "%s %s %s",
                           cmd,
                           export_data.email,
                           export_data.export_type);
        printf("%s: %s, %s\n", cmd, export_data.email, export_data.export_type);
    } else if (strncmp(cmdline, "setpowerthreshold", strlen("setpowerthreshold")) == 0) {
        memset(&threshold, 0, sizeof(struct we_insight_threshold));
        validargs = sscanf(cmdline, "%s %s", cmd,
                           threshold.threshold);
    } else if (strncmp(cmdline, "sethomesettings", strlen("sethomesettings")) == 0) {
        memset(&settings, 0, sizeof(struct we_insight_home_settings));
        validargs = sscanf(cmdline, "%s %s %s", cmd,
                           settings.energyPerUnitCost,
                           settings.Currency);
    } else {
        validargs = sscanf(cmdline, "%s %d %d %d", cmd, &arg1, &arg2, &arg3);
    }

    if (validargs < 1) {
        return;
    }

    for(i = 0; i < numofcmds; i++) {
        if (strcasecmp(cmd, cmdloop_cmdlist[i].str) == 0) {
            cmdnum = cmdloop_cmdlist[i].cmdnum;
            cmdfound++;
            if (validargs != cmdloop_cmdlist[i].numargs) {
                invalidargs++;
            }
            break;
        }
    }

    if (!cmdfound) {
        if (!client_quiet_all) {
            printf("Command not found: try 'help'\n");
        }
        return;
    }

    if (invalidargs) {
        if (!client_quiet_all) {
            printf("invalid arguments: try 'help'\n");
        }
        return;
    }

    switch (cmdnum) {
    case HELP:
        printhelp();
        break;
    case POWON:
        state_buffer.is_online = 0; // will be ignored
        state_buffer.state = 1;
        state_buffer.level = -1;
        dispatch_set_command("poweron", arg1, &state_buffer);
        break;
    case POWOFF:
        state_buffer.is_online = 0; // will be ignored
        state_buffer.state = 0;
        state_buffer.level = -1;
        dispatch_set_command("poweroff", arg1, &state_buffer);
        break;
    case SETLEVEL:
        state_buffer.is_online = 0; // will be ignored
        state_buffer.state = -1; // -1 means ignore
        state_buffer.level = arg2;
        dispatch_set_command("setlevel", arg1, &state_buffer);
        break;
    case SETDIMMER:
        state_buffer.is_online = 0; //will be ignored
        state_buffer.state = arg2;
        state_buffer.level = arg3;
        dispatch_set_command("setdimmer", arg1, &state_buffer);
        break;
    case GETSTATE:
        send_ipc_command("getstate", CMD_GET, arg1, &state_buffer, sizeof(struct we_state));
        break;
    case PRTDEV:
        wemo_print_device(arg1);
        break;
    case DELDEV:
        send_ipc_command("deletedev", CMD_DELETE, arg1, &state_buffer, sizeof(struct we_state));
        break;
    case FORGETDEV:
        send_ipc_command("forgetdev", CMD_FORGET, arg1, NULL, 0);
        break;
    case LSTDEV:
        wemo_list_devices();
        break;
    case SETUP:
        send_ipc_command("setup", CMD_SETUP, arg1, &conn_data, sizeof(struct we_conn_data));
        break;
    case NETSTATE:
        send_ipc_command("getnetstate", CMD_CONNECTION_STATE, arg1, &netstate, sizeof(struct we_network_status));
        break;
    case CLOSESETUP:
        send_ipc_command("closesetup", CMD_CLOSESETUP, arg1, NULL, 0);
        break;
    case DISCOVER:
        send_ipc_command("discover", CMD_DISCOVER, arg1, NULL, 0);
        break;
    case FIRMUPDATE:
        send_ipc_command("firmup", CMD_FIRMWARE_UPDATE, arg1, &firm_data, sizeof(struct we_firmware_data));
        break;
    case SET_HKSETUP:
        hksetup_data.hksetup_state = arg2;
        send_ipc_command("set_hksetup", CMD_SET_HKSETUP_STATE, arg1, &hksetup_data, sizeof(struct we_hksetup_state));
        break;
    case CHANGE_NAME:
        send_ipc_command("changename", CMD_CHANGE_NAME, arg1, &name_data, sizeof(struct we_name_change));
        break;
    case RESET:
        send_ipc_command("reset", CMD_RESET, arg1, &reset_data, sizeof(struct we_reset));
        break;
    case RESTART_RULE:
        send_ipc_command("restartrule", CMD_RESTART_RULE, arg1, NULL, 0);
        break;
    case GET_INFORMATION:
        send_ipc_command("getinformation", CMD_GET_DEVINFO, arg1, NULL, 0);
        break;
    case SCHEDULE_INSIGHT:
        send_ipc_command("scheduledataexport", CMD_SCHEDULE_DATA_EXPORT, 1, &export_data, sizeof(struct we_insight_export));
        break;
    case GET_INSIGHT_EXPORT_INFO:
        send_ipc_command("getexportinfo", CMD_GET_DATA_EXPORTINFO, 1, NULL, 0);
        break;
    case SET_INSIGHT_THRESHOLD:
        send_ipc_command("setpowerthreshold", CMD_SET_POWER_THRESHOLD, 1, &threshold, sizeof(struct we_insight_threshold));
        break;
    case GET_INSIGHT_THRESHOLD:
        send_ipc_command("getpowerthreshold", CMD_GET_DATA_EXPORTINFO, 1, NULL, 0);
        break;
    case SET_INSIGHT_HOME:
        send_ipc_command("sethomesettings", CMD_SET_INSIGHTHOME_SETTINGS, 1, &settings, sizeof(struct we_insight_home_settings));
        break;
    case GET_INSIGHT_HOME:
        send_ipc_command("gethomesettings", CMD_GET_INSIGHT_PARAMS, 1, NULL, 0);
        break;
    case HEALTH:
        print_health_snapshot();
        break;
    case HEALTHDEV:
        print_health_device(arg1);
        break;
    case HEALTHCTRL:
        print_health_snapshot_remote();
        break;
    case HEALTHDEVCTRL:
        print_health_device_remote(arg1);
        break;
    case HEALTHLOG:
        print_health_log();
        break;
    case PREFLIGHT:
        run_preflight_device(arg1);
        break;
    case PREFLIGHTALL:
        run_preflight_all();
        break;
    case EXITCMD:
        run_cmdloop = 0;
        break;
    default:
        if (!client_quiet_all) {
            printf("command not implemented: 'help'\n");
        }
        break;
    }
}

void wemo_client_cmdloop()
{
    char cmdline[100];
    size_t i;
    int only_ws;

    while(run_cmdloop) {
        if (!client_quiet_all) {
            printf("\n>> ");
        }
        if (fgets(cmdline, 100, stdin) == NULL) {
            run_cmdloop = 0;
            break;
        }
        only_ws = 1;
        for (i = 0; cmdline[i] != '\0'; i++) {
            if (!isspace((unsigned char)cmdline[i])) {
                only_ws = 0;
                break;
            }
        }
        if (only_ws) {
            continue;
        }
        wemo_client_process_command(cmdline);
    }
}

static void strip_string(char *str)
{
    int str_size = strlen(str);
    if (str_size > 0) {
        if (str[str_size - 1] == '\n') {
            str[str_size - 1] = 0;
            if (str_size > 1 && str[str_size - 2] == '\r') {
                str[str_size - 2] = 0;
            }
        }
    }
}

static char *trim_whitespace(char *str)
{
    char *end;

    if (str == NULL) {
        return NULL;
    }

    while (*str && isspace((unsigned char)*str)) {
        str++;
    }
    if (*str == '\0') {
        return str;
    }

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }
    return str;
}

int process_config()
{
    FILE *conf = fopen (CONFIG_FILE_PATH, "r");

    if (conf != NULL) {
        char line[256];

        while(fgets(line, sizeof(line), conf) != NULL) {
            char *key;
            char *value;
            char *eq;
            char *trimmed = trim_whitespace(line);

            if (trimmed == NULL || trimmed[0] == '\0' || trimmed[0] == '#') {
                continue;
            }

            eq = strchr(trimmed, '=');
            if (eq == NULL) {
                if (!client_quiet_all) {
                    printf("ignoring malformed config line: %s\n", trimmed);
                }
                continue;
            }

            *eq = '\0';
            key = trim_whitespace(trimmed);
            value = trim_whitespace(eq + 1);
            strip_string(value);

            if (!strcasecmp("wemo_device_db", key)) {
                if (value[0] != '\0') {
                    snprintf(wemo_device_db, sizeof(wemo_device_db), "%s", value);
                    if (!client_quiet_all) {
                        printf("wemo_device_db = %s\n", wemo_device_db);
                    }
                }
                else {
                    if (!client_quiet_all) {
                        printf("error parsing wemo_device_db!\n");
                    }
                }
            }
            else if (!strcasecmp("wemo_state_db", key)) {
                if (value[0] != '\0') {
                    snprintf(wemo_state_db, sizeof(wemo_state_db), "%s", value);
                    if (!client_quiet_all) {
                        printf("wemo_state_db = %s\n", wemo_state_db);
                    }
                }
                else {
                    if (!client_quiet_all) {
                        printf("error parsing wemo_state_db!\n");
                    }
                }
            }
            else if (!strcasecmp("ifname", key)) {
                if (value[0] != '\0') {
                    snprintf(upnp_ifname, sizeof(upnp_ifname), "%s", value);
                    if (!client_quiet_all) {
                        printf("upnp interface name= %s\n", upnp_ifname);
                    }
                    ifname_set = 1;
                }
                else {
                    if (!client_quiet_all) {
                        printf("error parsing ifname!\n");
                    }
                }
            }
            else if (!strcasecmp("ipc_host", key)) {
                if (value[0] != '\0') {
                    snprintf(ipc_host, sizeof(ipc_host), "%s", value);
                    if (!client_quiet_all) {
                        printf("ipc host = %s\n", ipc_host);
                    }
                }
                else {
                    if (!client_quiet_all) {
                        printf("error parsing ipc_host!\n");
                    }
                }
            }
            else if (!strcasecmp("ipc_port", key)) {
                if (value[0] != '\0') {
                    ipc_port = atoi(value);
                    if (!client_quiet_all) {
                        printf("ipc port = %d\n", ipc_port);
                    }
                }
                else {
                    if (!client_quiet_all) {
                        printf("error parsing ipc_port!\n");
                    }
                }
            }
            else {
                if (!client_quiet_all) {
                    printf("unknown item %s\n", key);
                }
            }
        }
        fclose(conf);
    }
    else {
        if (!client_quiet_all) {
            printf("No configuration file (/etc/wemo_ctrl.conf)...\n");
            printf("using default DB path %s and %s\n", wemo_device_db, wemo_state_db);
        }
        return 0;
    }

    return 1;
 }
int main()
{
    /* use default values if any one of config item is not found */
    set_default_db_paths();
    strcpy(upnp_ifname, DEFAULT_IFNAME);

    if (getenv("WEMO_CLIENT_QUIET_ALL")) {
        client_quiet_all = 1;
        client_quiet = 1;
    } else if (getenv("WEMO_CLIENT_QUIET")) {
        client_quiet = 1;
    }
    if (getenv("WEMO_CLIENT_CONFIRM_TIMEOUT_MS")) {
        int configured = atoi(getenv("WEMO_CLIENT_CONFIRM_TIMEOUT_MS"));
        if (configured >= 1000 && configured <= 60000) {
            confirm_timeout_ms = configured;
        }
    }
    if (getenv("WEMO_CLIENT_SERIAL_CONFIRM")) {
        serial_confirm_mode = atoi(getenv("WEMO_CLIENT_SERIAL_CONFIRM")) != 0;
    }
    if (process_config() == 0) {
        if (!client_quiet_all) {
            printf("/etc/wemo_ctrl.conf not found using default DB paths\n");
        }
    }
    if (!ifname_set) {
        char selected[IFNAMSIZ] = {0};
        if (choose_preferred_ifname(selected, sizeof(selected)) == 0) {
            strcpy(upnp_ifname, selected);
            if (!client_quiet_all) {
                printf("auto-selected upnp interface name= %s\n", upnp_ifname);
            }
        }
    }
    we_set_ipc_target(ipc_host, ipc_port);
    if (!we_init()) {
        fprintf(stderr, "failed to initialize wemo engine connection to %s:%d\n", ipc_host, ipc_port);
        return 1;
    }
    we_register_event_callback(&event_callback);
    we_register_netstate_callback(&netstate_callback);
    we_register_name_change_callback(&name_change_callback);
    we_register_name_value_callback(&name_value_callback);
    we_register_dev_info_callback(&dev_info_callback);
    we_register_proto_callback(&proto_callback);
    we_register_health_callback(&health_callback);
    wemo_client_cmdloop();
    we_end();
    return 0;
}
