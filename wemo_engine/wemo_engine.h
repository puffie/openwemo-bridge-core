#ifndef WEMO_ENGINE_H_
#define WEMO_ENGINE_H_

#include <stdint.h>

#define IPC_DEFAULT_HOST "127.0.0.1"
#define IPC_DEFAULT_PORT 49153

#define IPC_DATA_MAX 2048
#define WE_PROTO_MAGIC 0x57454d4fU /* "WEMO" */
#define WE_PROTO_VERSION 2

#define STATE_DISCONNECTED		            0
#define STATE_CONNECTED			            1
#define STATE_PAIRING_FAILURE_IND	        2
#define STATE_INTERNET_NOT_CONNECTED	    3
#define STATE_IPADDR_NEGOTIATION_FAILED	    4

typedef enum {
    CMD_SETUP = 1,
    CMD_CONNECTION_STATE,
    CMD_CLOSESETUP,
    CMD_SET,
    CMD_GET,
    CMD_DELETE,
    CMD_DISCOVER,
    CMD_FIRMWARE_UPDATE,
    CMD_SET_HKSETUP_STATE,
    CMD_CHANGE_NAME,
    CMD_NAME_VALUE,
    CMD_RESET,
    CMD_RESTART_RULE,
    CMD_GET_DEVINFO,
    CMD_GET_INSIGHTHOME_SETTINGS,
    CMD_SET_INSIGHTHOME_SETTINGS,
    CMD_GET_INSIGHT_PARAMS,
    CMD_SET_POWER_THRESHOLD,
    CMD_GET_POWER_THRESHOLD,
    CMD_GET_DATA_EXPORTINFO,
    CMD_SCHEDULE_DATA_EXPORT,
    CMD_FORGET,
    CMD_GET_HEALTH_SNAPSHOT,
    CMD_PROTO = 1000,
} ipc_cmd_t;

typedef enum {
    EVENT_SETUP = 1,
    EVENT_CONNECTION_STATE,
    EVENT_STATE,
    EVENT_NAME_CHANGE,
    EVENT_NAME_VALUE,
    EVENT_RESET,
    EVENT_DEVICE_INFO,
    EVENT_INSIGHT_HOME_SETTINGS,
    EVENT_PROTO = 1000,
} ipc_event_t;

typedef enum {
    WE_MSG_REQUEST = 1,
    WE_MSG_RESPONSE = 2,
    WE_MSG_EVENT = 3,
} we_msg_type_t;

typedef enum {
    WE_STATUS_OK = 0,
    WE_STATUS_INVALID = -1,
    WE_STATUS_UNSUPPORTED = -2,
    WE_STATUS_INTERNAL = -3,
} we_status_t;

typedef enum {
    WE_BROKER_OUTCOME_QUEUED = 0,
    WE_BROKER_OUTCOME_APPLIED = 1,
    WE_BROKER_OUTCOME_FAILED = -1,
    WE_BROKER_OUTCOME_TIMEOUT = -2,
    WE_BROKER_OUTCOME_MISMATCH = -3,
} we_broker_outcome_t;

typedef enum {
    WE_CONFIRM_NONE = 0,
    WE_CONFIRM_RESPONSE = 1,
    WE_CONFIRM_STATE_MATCH = 2,
} we_confirm_policy_t;

typedef enum {
    WE_TXN_ACCEPTED = 0,
    WE_TXN_APPLIED = 1,
    WE_TXN_TIMEOUT = -10,
    WE_TXN_MISMATCH = -11,
    WE_TXN_REJECTED = -12,
    WE_TXN_SEND_FAILED = -13,
} we_txn_outcome_t;

/* wemo device types */
typedef enum {
    WEMO_NONE,
    WEMO_SWITCH,
    WEMO_LIGHT,
    WEMO_MINI,
    WEMO_DIMMER,
    WEMO_INSIGHT,
    WEMO_SENSOR,
    WEMO_UNKNOWN
} dev_id_t;

typedef enum {
    CAP_NONE,
    CAP_BINARY,
    CAP_LEVEL,
    CAP_FUTURE
} cap_t;

typedef enum {
    RESET_SOFT = 1,
    RESET_FULL,
    RESET_REMOTE,
    RESET_INSIGHT,
    RESET_WIFI
} resettype_t;

struct we_conn_data {
    char ssid[64];
    char passphrase[128];
    char auth[16];
    char encrypt[16];
    int channel;
};

struct we_network_status {
    int connection_state;
};

struct we_name_change {
    char name[64];
};

struct we_name_value {
    char name[64];
    char value[1280];
};

struct we_dev_information {
    int binaryState;
    int brightness;
    int OverTemp;
    int nightMode;
    long startTime;
    long endTime;
    int nightModeBrightness;
    long CountdownEndTime;
    int longPressRuleDeviceCnt;
    int longPressRuleAction;
    int longPressRuleState;
    char *productName;
    char *fader;
    char *hushMode;
    char *longPressRuleDeviceUdn;
};

/* data structure to be used to communicate to wemo engine */
struct we_state {
    /* indication whether the device is online or not */
    /* 0 : offline or dead, 1: online and controllable */
    int is_online;
    /* triggers on/off */
    /* 0 : off, 1 : on */
    int state;
    /* Dimming range (0 - 100) */
    /* only applicable to dimming capable devices */
    int level;
};

struct we_firmware_data {
    long start_time;
    int unsign_img;
    char url[128];
};

struct we_hksetup_state {
    int hksetup_state;
};

struct we_reset {
    resettype_t reset_type;
};

struct we_insight_home_settings {
    char HomeSettingsVersion[8];
    char energyPerUnitCost[8];
    char Currency[8];
};

struct we_insight_threshold {
    char threshold[8];
};

struct we_insight_export {
    int version;
    char export_type[8];
    char email[256 + 64];
};

struct we_ipc_hdr {
    /* Device ID found from wemo_device.db */
    int wemo_id;
    int cmd;
    int size;
};

struct we_proto_hdr {
    uint32_t magic;
    uint16_t version;
    uint16_t msg_type;
    uint32_t client_id;
    uint32_t request_id;
    int32_t op;
    int32_t wemo_id;
    int32_t status;
    uint32_t payload_len;
};

struct we_broker_completion {
    uint32_t job_id;
    uint32_t request_id;
    int32_t cmd;
    int32_t wemo_id;
    int32_t outcome;
    int32_t status;
    int32_t latency_ms;
};

struct we_set_idempotent_request {
    struct we_state state;
    uint64_t idempotency_key;
};

struct we_txn_result {
    int cmd;
    int wemo_id;
    int policy;
    int used_proto;
    uint32_t request_id;
    int response_status;
    int outcome;
    int elapsed_ms;
    int retry_count;
    int final_state_valid;
    struct we_state final_state;
};

struct we_device_health {
    int wemo_id;
    int health_score;
    int timeout_streak;
    int degraded_mode;
    int breaker_open;
    int64_t breaker_remaining_ms;
    uint32_t breaker_open_count;
    uint32_t total_applied;
    uint32_t total_timeouts;
    uint32_t total_rejected;
    uint32_t total_retries;
    int last_retry_count;
    int ema_applied_latency_ms;
    int last_applied_latency_ms;
};

#define WE_HEALTH_SNAPSHOT_MAX_ITEMS 16

struct we_health_query {
    int32_t wemo_id;
    int32_t max_items;
};

struct we_health_snapshot {
    int32_t count;
    struct we_device_health items[WE_HEALTH_SNAPSHOT_MAX_ITEMS];
};

#define WE_HEALTH_DELTA_MAX_ITEMS 64

struct we_health_delta {
    int64_t ts_ms;
    struct we_device_health health;
};

struct we_bridge_preflight_result {
    int wemo_id;
    int ready;
    int is_online;
    int health_score;
    int timeout_streak;
    int breaker_open;
    uint32_t total_applied;
    uint32_t total_timeouts;
};

typedef void (*event_callback_t)(int wemo_id, struct we_state *data);
typedef void (*netstate_callback_t)(int wemo_id, struct we_network_status *data);
typedef void (*name_change_callback_t)(int wemo_id, struct we_name_change *data);
typedef void (*name_value_callback_t)(int wemo_id, struct we_name_value *data);
typedef void (*dev_info_callback_t)(int wemo_id, struct we_dev_information *data);
typedef void (*insight_home_settings_callback_t)(int wemo_id, struct we_insight_home_settings *data);
typedef void (*proto_callback_t)(const struct we_proto_hdr *hdr, const void *payload);
typedef void (*health_callback_t)(int wemo_id, const struct we_device_health *health);

struct wemo_engine_callback {
    event_callback_t event_callback;
    netstate_callback_t netstate_callback;
    name_change_callback_t name_change_callback;
    name_value_callback_t name_value_callback;
    dev_info_callback_t dev_info_callback;
    insight_home_settings_callback_t insight_home_settings_callback;
    proto_callback_t proto_callback;
    health_callback_t health_callback;
};

/* initialize the TCP IPC client to wemo engine */
/* note: it will spawn a pthread to communicate to wemo engine */
int we_init();
/* This function will register a user defined callback.
   When the notification is arrived from the wemo engine,
   then callback will be called.*/
int we_register_event_callback(void (*callback)(int wemo_id, struct we_state *data));
int we_register_netstate_callback(void (*callback)(int wemo_id, struct we_network_status *data));
int we_register_name_change_callback(void (*callback)(int wemo_id, struct we_name_change *data));
int we_register_name_value_callback(void (*callback)(int wemo_id, struct we_name_value *data));
int we_register_dev_info_callback(void (*callback)(int wemo_id, struct we_dev_information *data));
int we_register_insight_home_settings_callback(void (*callback) (int wemo_id, struct we_insight_home_settings *data));
int we_register_proto_callback(void (*callback)(const struct we_proto_hdr *hdr, const void *payload));
int we_register_health_callback(void (*callback)(int wemo_id, const struct we_device_health *health));

/* This function will pass the get action to to wemo engine */
int we_get_action(int wemo_id, struct we_state *we_state_data);
/* This function will pass the set action to to wemo engine */
int we_set_action(int wemo_id, struct we_state *we_state_data);
/* Send set action and wait for per-device state confirmation. */
int we_set_action_confirmed(int wemo_id, struct we_state *target_state, int timeout_ms);
/* This function will delete the wemo device in DB when called */
/* The user should not delete the device currently online */
int we_del_action(int wemo_id, struct we_state *we_state_data);
/* retrieve network state */
int we_get_netstate(int wemo_id, struct we_network_status *network_status);
/* command wemoApp to connect to designated AP */
int we_connect(int wemo_id, struct we_conn_data *conn_data);
int we_closesetup(int wemo_id);
int we_discover(int wemo_id);
int we_forget_action(int wemo_id);
int we_firm_update(int wemo_id, struct we_firmware_data *firm_data);
int we_set_hksetup_state(int wemo_id, struct we_hksetup_state *setup_state);
int we_change_name(int wemo_id, struct we_name_change *name_data);
int we_set_name_value(int wemo_id, struct we_name_value *data);
int we_reset(int wemo_id, struct we_reset *reset_data);
int we_restart_rule(int wemo_id);
int we_get_devinfo(int wemo_id);
int we_get_insightHomeSettings(int wemo_id);
int we_set_insightHomeSettings(int wemo_id, struct we_insight_home_settings *home_settings);
int we_get_insightParams(int wemo_id);
int we_set_powerThreshold(int wemo_id, struct we_insight_threshold *threshold);
int we_get_powerThreshold(int wemo_id);
int we_get_dataExportInfo(int wemo_id);
int we_schedule_dataExport(int wemo_id, struct we_insight_export *export);
int we_set_ipc_target(const char *host, int port);
int we_send_envelope(int op, int wemo_id, const void *payload, uint32_t payload_len, uint32_t *request_id_out);
int we_send_command_ex(int cmd, int wemo_id, const void *payload, int payload_len,
                       uint32_t *request_id_out, int *used_proto_out);
int we_default_confirm_policy_for_cmd(int cmd);
int we_run_command_txn(int cmd, int wemo_id, const void *payload, int payload_len,
                       const struct we_state *target_state, int timeout_ms, int policy,
                       struct we_txn_result *result_out);
int we_get_device_health(int wemo_id, struct we_device_health *health_out);
int we_get_device_health_snapshot(struct we_device_health *health_out, int max_items);
int we_get_device_health_snapshot_remote(int wemo_id, struct we_device_health *health_out, int max_items);
int we_get_health_deltas(struct we_health_delta *out, int max_items);
int we_bridge_preflight_device(int wemo_id, struct we_bridge_preflight_result *out);

/* stop IPC and clean up */
int we_end();

#endif /* WEMO_CTRL_H_ */
