/***************************************************************************
*
*
* WemoDB.c
*
* Created by Belkin International, Software Engineering on XX/XX/XX.
* Copyright (c) 2012-2013 Belkin International, Inc. and/or its affiliates. All rights reserved.
*
* Belkin International, Inc. retains all right, title and interest (including all
* intellectual property rights) in and to this computer program, which is
* protected by applicable intellectual property laws.  Unless you have obtained
* a separate written license from Belkin International, Inc., you are not authorized
* to utilize all or a part of this computer program for any purpose (including
* reproduction, distribution, modification, and compilation into object code)
* and you must immediately destroy or return to Belkin International, Inc
* all copies of this computer program.  If you are licensed by Belkin International, Inc., your
* rights to utilize this computer program are limited by the terms of that license.
*
* To obtain a license, please contact Belkin International, Inc.
*
* This computer program contains trade secrets owned by Belkin International, Inc.
* and, unless unauthorized by Belkin International, Inc. in writing, you agree to
* maintain the confidentiality of this computer program and related information
* and to not disclose this computer program and related information to any
* other person or entity.
*
* THIS COMPUTER PROGRAM IS PROVIDED AS IS WITHOUT ANY WARRANTIES, AND BELKIN INTERNATIONAL, INC.
* EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING THE WARRANTIES OF
* MERCHANTIBILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT.
*
*
***************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wemo_device_db.h"
#include "logger.h"

#define WEMO_DEVICE_ENTRIES 10
#define STATE_ENTRIES 4
#define STATE_CACHE_MAX_ENTRIES 512
#define STATE_CACHE_DEFAULT_FLUSH_MS 2000

extern char wemo_device_db[];
extern char wemo_state_db[];

struct cap_state {
    cap_t cap;
    int state;
};

typedef struct {
    int in_use;
    int wemo_id;
    int is_online;
    int is_online_valid;
    int capability[CAP_FUTURE];
    int capability_valid[CAP_FUTURE];
    int dirty_online;
    int dirty_cap[CAP_FUTURE];
} state_cache_entry_t;

static pthread_mutex_t state_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static state_cache_entry_t state_cache[STATE_CACHE_MAX_ENTRIES];
static sqlite3 *state_cache_db = NULL;
static pthread_t state_cache_thread;
static int state_cache_thread_running = 0;
static int state_cache_thread_stop = 0;
static int state_cache_flush_ms = STATE_CACHE_DEFAULT_FLUSH_MS;
static int wemo_dev_db_upsert_capability(sqlite3 *db, int wemo_id, int cap, int value);

static state_cache_entry_t *state_cache_find_locked(int wemo_id)
{
    int i;
    for (i = 0; i < STATE_CACHE_MAX_ENTRIES; i++) {
        if (state_cache[i].in_use && state_cache[i].wemo_id == wemo_id) {
            return &state_cache[i];
        }
    }
    return NULL;
}

static state_cache_entry_t *state_cache_get_locked(int wemo_id, int create)
{
    int i;
    state_cache_entry_t *free_slot = NULL;

    if (wemo_id <= 0) {
        return NULL;
    }
    for (i = 0; i < STATE_CACHE_MAX_ENTRIES; i++) {
        if (state_cache[i].in_use && state_cache[i].wemo_id == wemo_id) {
            return &state_cache[i];
        }
        if (!state_cache[i].in_use && free_slot == NULL) {
            free_slot = &state_cache[i];
        }
    }
    if (!create || free_slot == NULL) {
        return NULL;
    }
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->in_use = 1;
    free_slot->wemo_id = wemo_id;
    return free_slot;
}

static int state_db_get_online(sqlite3 *db, int wemo_id, int *is_online)
{
    sqlite3_stmt *stmt = NULL;
    int rc;

    rc = sqlite3_prepare_v2(db, "SELECT is_online FROM state WHERE wemo_id = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return DB_ERROR;
    }
    if (sqlite3_bind_int(stmt, 1, wemo_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return DB_ERROR;
    }
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        if (is_online != NULL) {
            *is_online = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
        return DB_SUCCESS;
    }
    sqlite3_finalize(stmt);
    return DB_ERROR;
}

static int state_db_upsert_online(sqlite3 *db, int wemo_id, int is_online)
{
    sqlite3_stmt *stmt = NULL;
    int rc;

    rc = sqlite3_prepare_v2(db, "UPDATE state SET is_online = ? WHERE wemo_id = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return DB_ERROR;
    }
    if (sqlite3_bind_int(stmt, 1, is_online) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 2, wemo_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return DB_ERROR;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return DB_ERROR;
    }
    if (sqlite3_changes(db) > 0) {
        return DB_SUCCESS;
    }

    rc = sqlite3_prepare_v2(db,
                            "INSERT OR IGNORE INTO state (wemo_id, is_online, capability) VALUES (?, ?, '1=0')",
                            -1,
                            &stmt,
                            NULL);
    if (rc != SQLITE_OK) {
        return DB_ERROR;
    }
    if (sqlite3_bind_int(stmt, 1, wemo_id) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 2, is_online) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return DB_ERROR;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? DB_SUCCESS : DB_ERROR;
}

static int state_cache_flush_locked(void)
{
    int i;
    int flush_rc = DB_SUCCESS;

    if (state_cache_db == NULL) {
        return DB_ERROR;
    }
    for (i = 0; i < STATE_CACHE_MAX_ENTRIES; i++) {
        int cap;
        state_cache_entry_t *e = &state_cache[i];
        if (!e->in_use) {
            continue;
        }
        if (e->dirty_online) {
            if (state_db_upsert_online(state_cache_db, e->wemo_id, e->is_online) == DB_SUCCESS) {
                e->dirty_online = 0;
            } else {
                flush_rc = DB_ERROR;
            }
        }
        for (cap = 0; cap < CAP_FUTURE; cap++) {
            if (e->dirty_cap[cap]) {
                if (wemo_dev_db_upsert_capability(state_cache_db, e->wemo_id, cap, e->capability[cap]) == DB_SUCCESS) {
                    e->dirty_cap[cap] = 0;
                } else {
                    flush_rc = DB_ERROR;
                }
            }
        }
    }
    return flush_rc;
}

static void *state_cache_flush_thread(void *arg)
{
    (void)arg;
    while (!state_cache_thread_stop) {
        usleep((useconds_t)state_cache_flush_ms * 1000U);
        pthread_mutex_lock(&state_cache_lock);
        (void)state_cache_flush_locked();
        pthread_mutex_unlock(&state_cache_lock);
    }
    return NULL;
}

static void state_cache_runtime_init(sqlite3 *state_db)
{
    const char *flush_env = getenv("WEMO_STATE_FLUSH_MS");
    if (flush_env != NULL && flush_env[0] != '\0') {
        int parsed = atoi(flush_env);
        if (parsed >= 200 && parsed <= 30000) {
            state_cache_flush_ms = parsed;
        }
    }

    pthread_mutex_lock(&state_cache_lock);
    memset(state_cache, 0, sizeof(state_cache));
    state_cache_db = state_db;
    state_cache_thread_stop = 0;
    if (!state_cache_thread_running) {
        if (pthread_create(&state_cache_thread, NULL, state_cache_flush_thread, NULL) == 0) {
            state_cache_thread_running = 1;
        } else {
            LOG_ERROR_MSG("failed to start state cache flush thread");
        }
    }
    pthread_mutex_unlock(&state_cache_lock);
}

static void state_cache_runtime_finish(void)
{
    pthread_mutex_lock(&state_cache_lock);
    state_cache_thread_stop = 1;
    pthread_mutex_unlock(&state_cache_lock);
    if (state_cache_thread_running) {
        pthread_join(state_cache_thread, NULL);
        state_cache_thread_running = 0;
    }
    pthread_mutex_lock(&state_cache_lock);
    (void)state_cache_flush_locked();
    state_cache_db = NULL;
    pthread_mutex_unlock(&state_cache_lock);
}

static void wemo_dev_db_ensure_ipaddr_column(sqlite3 *dev_db)
{
    char *errmsg = NULL;
    int rc;

    rc = sqlite3_exec(dev_db, "ALTER TABLE wemo_device ADD COLUMN ipaddr VARCHAR(64);", NULL, NULL, &errmsg);
    if (rc == SQLITE_OK) {
        LOG_DEBUG_MSG("wemo_device schema updated: added ipaddr column");
        return;
    }

    if (errmsg != NULL && strstr(errmsg, "duplicate column name") != NULL) {
        sqlite3_free(errmsg);
        return;
    }

    LOG_ERROR_MSG("failed to add ipaddr column to wemo_device: %s", errmsg ? errmsg : "unknown error");
    if (errmsg != NULL) {
        sqlite3_free(errmsg);
    }
}

static int wemo_dev_db_ensure_state_capability_table(sqlite3 *state_db)
{
    char *errmsg = NULL;
    int rc = sqlite3_exec(state_db,
                          "CREATE TABLE IF NOT EXISTS state_capability ("
                          "wemo_id INTEGER NOT NULL,"
                          "cap INTEGER NOT NULL,"
                          "value INTEGER NOT NULL,"
                          "updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),"
                          "PRIMARY KEY (wemo_id, cap)"
                          ");",
                          NULL,
                          NULL,
                          &errmsg);
    if (rc != SQLITE_OK) {
        LOG_ERROR_MSG("failed to ensure state_capability table: %s",
                errmsg ? errmsg : "unknown error");
        if (errmsg != NULL) {
            sqlite3_free(errmsg);
        }
        return DB_ERROR;
    }
    return DB_SUCCESS;
}

static int wemo_dev_db_parse_capability_token(const char *token, int *cap, int *value)
{
    char *end = NULL;
    long parsed_cap;
    long parsed_value;

    if (token == NULL || *token == '\0' || cap == NULL || value == NULL) {
        return 0;
    }

    errno = 0;
    parsed_cap = strtol(token, &end, 10);
    if (errno != 0 || end == token || *end != '=') {
        return 0;
    }
    if (parsed_cap < 0 || parsed_cap >= CAP_FUTURE) {
        return 0;
    }

    token = end + 1;
    errno = 0;
    parsed_value = strtol(token, &end, 10);
    if (errno != 0 || end == token || *end != '\0') {
        return 0;
    }
    if (parsed_value < INT_MIN || parsed_value > INT_MAX) {
        return 0;
    }

    *cap = (int)parsed_cap;
    *value = (int)parsed_value;
    return 1;
}

static void wemo_dev_db_strip_capability_quotes(const char *cap, char *out, size_t out_len)
{
    size_t len = 0;

    if (out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (cap == NULL) {
        return;
    }

    len = strlen(cap);
    if (len >= 2 && cap[0] == '\'' && cap[len - 1] == '\'') {
        cap++;
        len -= 2;
    }

    if (len >= out_len) {
        len = out_len - 1;
    }
    memcpy(out, cap, len);
    out[len] = '\0';
}

static int wemo_dev_db_upsert_capability(sqlite3 *db, int wemo_id, int cap, int value)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT OR REPLACE INTO state_capability (wemo_id, cap, value, updated_at) "
                      "VALUES (?, ?, ?, strftime('%s','now'))";
    int rc;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR_MSG("prepare failed for capability upsert: %s", sqlite3_errmsg(db));
        return DB_ERROR;
    }
    if (sqlite3_bind_int(stmt, 1, wemo_id) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 2, cap) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 3, value) != SQLITE_OK) {
        LOG_ERROR_MSG("bind failed for capability upsert: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return DB_ERROR;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR_MSG("step failed for capability upsert: %s", sqlite3_errmsg(db));
        return DB_ERROR;
    }
    return DB_SUCCESS;
}

static int wemo_dev_db_get_capability_value(sqlite3 *db, int wemo_id, int cap, int *value)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT value FROM state_capability WHERE wemo_id = ? AND cap = ?";
    int rc;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR_MSG("prepare failed for capability select: %s", sqlite3_errmsg(db));
        return DB_ERROR;
    }
    if (sqlite3_bind_int(stmt, 1, wemo_id) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 2, cap) != SQLITE_OK) {
        LOG_ERROR_MSG("bind failed for capability select: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return DB_ERROR;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *value = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return DB_SUCCESS;
    }
    sqlite3_finalize(stmt);
    return DB_NOT_OPEN;
}

static void wemo_dev_db_sync_legacy_capabilities(sqlite3 *db, int wemo_id, const char *legacy_capability)
{
    char cap_buffer[512];
    char *saveptr = NULL;
    char *token = NULL;

    wemo_dev_db_strip_capability_quotes(legacy_capability, cap_buffer, sizeof(cap_buffer));
    if (cap_buffer[0] == '\0') {
        return;
    }

    token = strtok_r(cap_buffer, ":", &saveptr);
    while (token != NULL) {
        int cap;
        int value;
        if (!wemo_dev_db_parse_capability_token(token, &cap, &value)) {
            LOG_WARN_MSG("ignoring malformed capability token for wemo_id=%d: %s",
                    wemo_id, token);
        } else {
            wemo_dev_db_upsert_capability(db, wemo_id, cap, value);
        }
        token = strtok_r(NULL, ":", &saveptr);
    }
}

static int wemo_dev_db_migrate_state_capability_callback(void *data, int argc, char **argv, char **colName)
{
    sqlite3 *state_db = (sqlite3 *)data;
    int i;
    int wemo_id = 0;
    const char *capability = NULL;

    (void)colName;

    for (i = 0; i < argc; i++) {
        if (argv[i] == NULL) {
            continue;
        }
        if (i == 0) {
            wemo_id = atoi(argv[i]);
        } else if (i == 1) {
            capability = argv[i];
        }
    }

    if (wemo_id > 0 && capability != NULL) {
        wemo_dev_db_sync_legacy_capabilities(state_db, wemo_id, capability);
    }

    return 0;
}

static int wemo_dev_db_migrate_state_capabilities(sqlite3 *state_db)
{
    char *errmsg = NULL;
    int rc = sqlite3_exec(state_db,
                          "SELECT wemo_id, capability FROM state "
                          "WHERE capability IS NOT NULL AND capability != '';",
                          wemo_dev_db_migrate_state_capability_callback,
                          state_db,
                          &errmsg);
    if (rc != SQLITE_OK) {
        LOG_ERROR_MSG("failed to migrate legacy capabilities: %s",
                errmsg ? errmsg : "unknown error");
        if (errmsg != NULL) {
            sqlite3_free(errmsg);
        }
        return DB_ERROR;
    }
    return DB_SUCCESS;
}

static int wemo_dev_db_mark_all_offline(sqlite3 *state_db)
{
    char *errmsg = NULL;
    int rc = sqlite3_exec(state_db, "UPDATE state SET is_online = 0;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        LOG_ERROR_MSG("failed to mark all devices offline on startup: %s",
                errmsg ? errmsg : "unknown error");
        if (errmsg != NULL) {
            sqlite3_free(errmsg);
        }
        return DB_ERROR;
    }
    return DB_SUCCESS;
}

static int update_state_db_callback(void *data, int argc, char **argv, char **colName)
{
    sqlite3 *state_db;
    int i;
    state_db = (sqlite3 *) data;

    for (i = 0; i < argc; i++) {
        if(!strcmp("wemo_id", colName[i])) {
            wemo_dev_statedb_insert(state_db, atoi(argv[i]), 0, "1=0");
        }
    }
    return 0;
}

int wemo_dev_init_state_db(sqlite3 *dev_db, sqlite3 *state_db)
{
    char *sql = "SELECT wemo_id from wemo_device";
    char *errmsg = NULL;
    int rc;

    rc = sqlite3_exec(dev_db, sql, update_state_db_callback, state_db, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL: %s\n", errmsg);
        return DB_ERROR;
    }
    return DB_SUCCESS;
}

int wemo_dev_db_init(sqlite3 **dev_db, sqlite3 **state_db)
{
	struct stat db_file;

	char *device_table = "wemo_device";
	char *state_table = "state";

	TableDetails wemo_device_info[WEMO_DEVICE_ENTRIES] =
	{
			{"wemo_id", "INTEGER PRIMARY KEY AUTOINCREMENT"},
			{"UDN", "VARCHAR(256)"},
			{"device_type", "TINYINT"},
			{"friendly_name", "VARCHAR(256)"},
			{"firmware_version", "VARCHAR(256)"},
			{"serial_number", "CHAR(14)"},
			{"model_name", "VARCHAR(45)"},
			{"manufacturer", "VARCHAR(45)"},
			{"ipaddr", "VARCHAR(64)"},
			{"UNIQUE", "(UDN)"}
	};

	TableDetails wemo_state_info[STATE_ENTRIES] =
	{
			{"wemo_id", "INTEGER PRIMARY KEY"},
			{"is_online", "BOOL"},
			{"capability", "VARCHAR(256)"},
            {"UNIQUE", "(wemo_id)"}
	};

	if (stat(wemo_device_db, &db_file) != -1) {
		LOG_DEBUG_MSG("wemo device db already exists");
		if (InitDB(wemo_device_db, dev_db)) {
			LOG_ERROR_MSG("device DB initialization failed");
			return DB_ERROR;
		}
	}
	else {
		if (!InitDB(wemo_device_db, dev_db)) {
			if (WeMoDBCreateTable(dev_db, device_table, wemo_device_info, 0, WEMO_DEVICE_ENTRIES)) {
				LOG_ERROR_MSG("wemo_device table creation failed %s", device_table);
				return DB_ERROR;
			}
        }
    }

    wemo_dev_db_ensure_ipaddr_column(*dev_db);

    if(stat(wemo_state_db, &db_file) != -1) {
        LOG_DEBUG_MSG("wemo state db already exists");
        if (InitDB(wemo_state_db, state_db)) {
            LOG_ERROR_MSG("state DB initialization failed");
            return DB_ERROR;
        }
    }
	else {
        if (!InitDB(wemo_state_db, state_db)) {
			if (WeMoDBCreateTable(state_db, state_table, wemo_state_info, 0, STATE_ENTRIES)) {
				LOG_ERROR_MSG("table create failed %s", state_table);
				return DB_ERROR;
			}
            else {
                if (wemo_dev_init_state_db(*dev_db, *state_db) != DB_SUCCESS) {
                    return DB_ERROR;
                }
            }
		}
	}
    if (wemo_dev_db_ensure_state_capability_table(*state_db) != DB_SUCCESS) {
        return DB_ERROR;
    }
    if (wemo_dev_db_migrate_state_capabilities(*state_db) != DB_SUCCESS) {
        return DB_ERROR;
    }
    if (wemo_dev_db_mark_all_offline(*state_db) != DB_SUCCESS) {
        return DB_ERROR;
    }
    state_cache_runtime_init(*state_db);
	LOG_DEBUG_MSG("DB init done");
	return DB_SUCCESS;
}

void wemo_dev_db_finish(sqlite3 *dev_db, sqlite3 *state_db)
{
    state_cache_runtime_finish();
	CloseDB(dev_db);
    CloseDB(state_db);
}

static int wemo_dev_parse_version(char *firmware, char *UDN, char *version, int *type)
{
    int major;
    int minor;
    int fix;

    char firmware_type[10];
    char os[10];
    char dev[10];
    char *substring = NULL;

    if (sscanf(firmware, "WeMo_WW_%d.%d.%d.%[^-]-%[^-]-%[^-]", &major, &minor, &fix, firmware_type, os, dev) != 6) {
        fprintf(stderr, "error parsing firmware version (%s)..\n", firmware);
        fprintf(stderr, "Trying to parse old for old firmware..\n");

        if (sscanf(firmware, "WeMo_US_%d.%d.%d.%[^-]", &major, &minor, &fix, firmware_type) != 4) {
        return 0;
    }
        else {
            if ((substring = strcasestr(UDN, "socket"))) {
                *type = WEMO_SWITCH;
            }
            else if ((substring = strcasestr(UDN, "lightswitch"))) {
                *type = WEMO_LIGHT;
            }
            else {
                *type = WEMO_UNKNOWN;
            }

            sprintf(version, "%d,%d,%d", major, minor, fix);
            return 1;
        }
    }

    sprintf(version, "%d.%d.%d", major, minor, fix);

    if ((substring = strcasestr(UDN, "uuid:socket"))) {
    if (!strcasecmp(dev, "SNS")) {
        *type = WEMO_SWITCH;
    }
        else {
        *type = WEMO_MINI;
    }
    }
    else if ((substring = strcasestr(UDN, "uuid:lightswitch"))) {
        *type = WEMO_LIGHT;
    }
    else if ((substring = strcasestr(UDN, "uuid:dimmer"))) {
        *type = WEMO_DIMMER;
    }
    else if ((substring = strcasestr(UDN, "uuid:insight"))) {
        *type = WEMO_INSIGHT;
    }
    else if ((substring = strcasestr(UDN, "uuid:sensor"))) {
            *type = WEMO_SENSOR;
    }
    else {
        *type = WEMO_UNKNOWN;
        return 0;
    }
    return 1;
}

void wemo_dev_db_insert(sqlite3 *db, struct wemoDevice *dev)
{
    // Add device to DB
    ColDetails devParams[8];
    ColDetails updateParams[7];
    char condition[320];
    int type = 0;
    char version[12];

    memset(version, 0, 12);

    if (wemo_dev_parse_version(dev->firmwareVersion, dev->UDN, version, &type)) {
        sprintf(devParams[0].ColName, "%s","UDN");
        snprintf(devParams[0].ColValue, sizeof(devParams[0].ColValue), "'%.*s'",
                 (int)sizeof(devParams[0].ColValue) - 3, dev->UDN);
        sprintf(devParams[1].ColName, "%s", "device_type");
        sprintf(devParams[1].ColValue, "%d", type);
        sprintf(devParams[2].ColName, "%s", "friendly_name");
        snprintf(devParams[2].ColValue, sizeof(devParams[2].ColValue), "'%.*s'",
                 (int)sizeof(devParams[2].ColValue) - 3, dev->FriendlyName);
        sprintf(devParams[3].ColName, "%s", "firmware_version");
        sprintf(devParams[3].ColValue, "\'%s\'", version);
        sprintf(devParams[4].ColName, "%s", "serial_number");
        snprintf(devParams[4].ColValue, sizeof(devParams[4].ColValue), "'%.*s'",
                 (int)sizeof(devParams[4].ColValue) - 3, dev->serialNumber);
        sprintf(devParams[5].ColName, "%s", "model_name");
        snprintf(devParams[5].ColValue, sizeof(devParams[5].ColValue), "'%.*s'",
                 (int)sizeof(devParams[5].ColValue) - 3, dev->modelName);
        sprintf(devParams[6].ColName, "%s", "manufacturer");
        snprintf(devParams[6].ColValue, sizeof(devParams[6].ColValue), "'%.*s'",
                 (int)sizeof(devParams[6].ColValue) - 3, dev->manufacturer);
        sprintf(devParams[7].ColName, "%s", "ipaddr");
        snprintf(devParams[7].ColValue, sizeof(devParams[7].ColValue), "'%.*s'",
                 (int)sizeof(devParams[7].ColValue) - 3, dev->ipaddr);

        if (WeMoDBInsertInTable(&db, "wemo_device", devParams, 8) == -1) {
            memcpy(updateParams, &devParams[1], sizeof(updateParams));
            snprintf(condition, sizeof(condition), "UDN='%s'", dev->UDN);
            WeMoDBUpdateTable(&db, "wemo_device", updateParams, 7, condition);
        }
    }
}

void wemo_dev_statedb_insert(sqlite3 *db, int id, int is_online, char *cap)
{
    ColDetails stateParams[4];
    char cap_value[512];
    char cap_sql_value[256];

    memset(cap_value, 0, sizeof(cap_value));
    memset(cap_sql_value, 0, sizeof(cap_sql_value));
    wemo_dev_db_strip_capability_quotes(cap, cap_value, sizeof(cap_value));
    sprintf(stateParams[0].ColName, "%s", "wemo_id");
    sprintf(stateParams[0].ColValue, "%d", id);
    sprintf(stateParams[1].ColName, "%s", "is_online");
    sprintf(stateParams[1].ColValue, "%d", is_online);
    sprintf(stateParams[2].ColName, "%s", "capability");
    snprintf(cap_sql_value, sizeof(cap_sql_value), "'%.*s'",
             (int)sizeof(cap_sql_value) - 3, cap_value);
    strcpy(stateParams[2].ColValue, cap_sql_value);

    pthread_mutex_lock(&state_cache_lock);
    {
        state_cache_entry_t *e = state_cache_get_locked(id, 1);
        if (e != NULL) {
            e->is_online = is_online;
            e->is_online_valid = 1;
            e->dirty_online = 1;
        }
        if (state_db_upsert_online(state_cache_db ? state_cache_db : db, id, is_online) != DB_SUCCESS) {
            LOG_WARN_MSG("failed immediate state upsert for wemo_id=%d", id);
        }
        wemo_dev_db_sync_legacy_capabilities(state_cache_db ? state_cache_db : db, id, cap_value);
    }
    pthread_mutex_unlock(&state_cache_lock);
}

void wemo_dev_statedb_update_online(sqlite3 *db, int id, int is_online)
{
    pthread_mutex_lock(&state_cache_lock);
    {
        state_cache_entry_t *e = state_cache_get_locked(id, 1);
        if (e != NULL) {
            e->is_online = is_online;
            e->is_online_valid = 1;
            e->dirty_online = 1;
        }
    }
    pthread_mutex_unlock(&state_cache_lock);
    (void)db;
}

int wemo_dev_db_retrieve_id(sqlite3 *db, char *UDN)
{
    sqlite3_stmt *stmt;
    int rc;
    char *sql;
    int id_value = 0;

    sql = "SELECT wemo_id FROM wemo_device where UDN = ?";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        if (sqlite3_bind_text(stmt, 1, UDN, strlen(UDN), SQLITE_STATIC) != SQLITE_OK) {
            fprintf(stderr, "Could not bind text\n");
            sqlite3_finalize(stmt);
            return 0;
        }
    }
    else {
        fprintf(stderr, "Failed to execute statement %s\n",
                sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 0;
    }

    int step = sqlite3_step(stmt);

    if (step == SQLITE_ROW) {
        id_value = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return id_value;
}

int wemo_dev_db_retrieve_udn(sqlite3 *db, int wemo_id, char *UDN)
{
    sqlite3_stmt *stmt;
    int rc;
    char *sql;

    sql = "SELECT UDN FROM wemo_device where wemo_id = ?";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        if (sqlite3_bind_int(stmt, 1, wemo_id) != SQLITE_OK) {
            fprintf(stderr, "Could not bind int\n");
            sqlite3_finalize(stmt);
            return 0;
        }
    }
    else {
        fprintf(stderr, "Failed to execute statement %s\n",
                sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 0;
    }

    int step = sqlite3_step(stmt);

    if (step == SQLITE_ROW) {
        strcpy(UDN, (const char *)sqlite3_column_text(stmt, 0));
    }

    sqlite3_finalize(stmt);
    return 1;
}

int wemo_dev_db_retrieve_cap(sqlite3 *db, int wemo_id, char *cap)
{
    sqlite3_stmt *stmt;
    int rc;
    char *sql;

    sql = "SELECT capability FROM state where wemo_id = ?";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        if (sqlite3_bind_int(stmt, 1, wemo_id) != SQLITE_OK) {
            fprintf(stderr, "Could not bind int\n");
            sqlite3_finalize(stmt);
            return 0;
        }
    }
    else {
        fprintf(stderr, "Failed to execute statement %s\n",
                sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 0;
    }

    int step = sqlite3_step(stmt);

    if (step == SQLITE_ROW && sqlite3_column_text(stmt, 0) != NULL) {
        strcpy(cap, (const char *)sqlite3_column_text(stmt, 0));
    } else {
        cap[0] = '\0';
    }

    sqlite3_finalize(stmt);
    return 1;
}

int wemo_dev_db_update_capability(sqlite3 *db, int wemo_id, int cap, int value)
{
    if (cap < 0 || cap >= CAP_FUTURE) {
        LOG_WARN_MSG("invalid capability id=%d for wemo_id=%d", cap, wemo_id);
        return 0;
    }
    pthread_mutex_lock(&state_cache_lock);
    {
        state_cache_entry_t *e = state_cache_get_locked(wemo_id, 1);
        if (e != NULL) {
            e->capability[cap] = value;
            e->capability_valid[cap] = 1;
            e->dirty_cap[cap] = 1;
        }
    }
    pthread_mutex_unlock(&state_cache_lock);
    (void)db;
    return 1;
}

int wemo_dev_db_get_capability(sqlite3 *db, int wemo_id, int cap)
{
    char legacy_cap[512];
    int value = -1;

    if (cap < 0 || cap >= CAP_FUTURE) {
        LOG_WARN_MSG("invalid capability id=%d for lookup wemo_id=%d", cap, wemo_id);
        return -1;
    }
    pthread_mutex_lock(&state_cache_lock);
    {
        state_cache_entry_t *e = state_cache_get_locked(wemo_id, 0);
        if (e != NULL && e->capability_valid[cap]) {
            value = e->capability[cap];
            pthread_mutex_unlock(&state_cache_lock);
            return value;
        }
    }
    pthread_mutex_unlock(&state_cache_lock);

    if (wemo_dev_db_get_capability_value(state_cache_db ? state_cache_db : db, wemo_id, cap, &value) == DB_SUCCESS) {
        pthread_mutex_lock(&state_cache_lock);
        {
            state_cache_entry_t *e = state_cache_get_locked(wemo_id, 1);
            if (e != NULL) {
                e->capability[cap] = value;
                e->capability_valid[cap] = 1;
            }
        }
        pthread_mutex_unlock(&state_cache_lock);
        return value;
    }

    memset(legacy_cap, 0, sizeof(legacy_cap));
    if (wemo_dev_db_retrieve_cap(state_cache_db ? state_cache_db : db, wemo_id, legacy_cap) && legacy_cap[0] != '\0') {
        pthread_mutex_lock(&state_cache_lock);
        wemo_dev_db_sync_legacy_capabilities(state_cache_db ? state_cache_db : db, wemo_id, legacy_cap);
        pthread_mutex_unlock(&state_cache_lock);
        if (wemo_dev_db_get_capability_value(state_cache_db ? state_cache_db : db, wemo_id, cap, &value) == DB_SUCCESS) {
            pthread_mutex_lock(&state_cache_lock);
            {
                state_cache_entry_t *e = state_cache_get_locked(wemo_id, 1);
                if (e != NULL) {
                    e->capability[cap] = value;
                    e->capability_valid[cap] = 1;
                }
            }
            pthread_mutex_unlock(&state_cache_lock);
            return value;
        }
    }

    return -1;
}

int wemo_dev_db_delete_row(sqlite3 *db, int wemo_id)
{
    char condition[512];

    sprintf(condition, "wemo_id=%d", wemo_id);

    if (WeMoDBDeleteEntry(&db, "wemo_device", condition)) {
        return 1;
    } else {
        return 0;
    }
}

int wemo_dev_statedb_delete_row(sqlite3 *db, int wemo_id)
{
    char condition[512];
    int ret_state;
    int ret_cap;

    sprintf(condition, "wemo_id=%d", wemo_id);
    ret_cap = WeMoDBDeleteEntry(&db, "state_capability", condition);
    ret_state = WeMoDBDeleteEntry(&db, "state", condition);

    if (ret_state || ret_cap) {
        LOG_ERROR_MSG("failed to delete state rows for wemo_id=%d (state=%d, cap=%d)",
                wemo_id, ret_state, ret_cap);
        return 0;
    }
    pthread_mutex_lock(&state_cache_lock);
    {
        state_cache_entry_t *e = state_cache_find_locked(wemo_id);
        if (e != NULL) {
            memset(e, 0, sizeof(*e));
        }
    }
    pthread_mutex_unlock(&state_cache_lock);
    return 1;
}
