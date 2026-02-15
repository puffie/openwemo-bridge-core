/*******************************************************************************
 *
 * Copyright (c) 2000-2003 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * - Neither name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ctrlpt_util.h"
#include "wemo_ctrl.h"
#include "wemo_event_ctrl.h"
#include "wemo_device_db.h"
#include "wemo_ipc_server.h"
#include "logger.h"

#ifndef HAVE_LIBNVRAM
static inline int NvramInit(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	return 0;
}
#endif

enum cmdloop_cmds {
    PRTHELP = 0,
    PRTFULLHELP,
    POWERON,
    POWEROFF,
    GETPOWER,
    SETLEVEL,
    GETLEVEL,
    PRTDEV,
    LSTDEV,
    REFRESH,
    EXITCMD
};

/*
   Data structure for parsing commands from the command line
 */
struct cmdloop_commands {
    char *str;                  // the string
    int cmdnum;                 // the command
    int numargs;                // the number of arguments
    char *args;                 // the args
} cmdloop_commands;

/*
   Mappings between command text names, command tag,
   and required command arguments for command line
   commands
 */
static struct cmdloop_commands cmdloop_cmdlist[] = {
    {"help", PRTHELP, 1, ""},
    {"helpfull", PRTFULLHELP, 1, ""},
    {"listdev", LSTDEV, 1, ""},
    {"refresh", REFRESH, 1, ""},
    {"printdev", PRTDEV, 2, "<devnum>"},
    {"poweron", POWERON, 2, "<devnum>"},
    {"poweroff", POWEROFF, 2, "<devnum>"},
    {"getpower", GETPOWER, 2, "<devnum>"},
    {"setlevel", SETLEVEL, 3, "<devnum>"},
    {"getlevel", GETLEVEL, 2, "<devnum>"},
    {"exit", EXITCMD, 1, ""}
};

#define CONFIG_FILE_PATH "/etc/wemo_ctrl.conf"
#define DEFAULT_STATE_DIR_ROOT "/var/lib/wemo-matter"
#define DEFAULT_STATE_DIR_HOME ".local/state/wemo-matter"
#define DEFAULT_STATE_DIR_FALLBACK "/var/tmp/wemo-matter"
#define DEFAULT_IFNAME "lo"

char wemo_device_db[128];
char wemo_state_db[128];
char upnp_ifname[16];
static int discover = 0;
static ithread_mutex_t discover_mutex;
static int discover_mutex_ready = 0;
static int ifname_set = 0;
static char ipc_bind_addr[64] = "127.0.0.1";
static int ipc_port = IPC_DEFAULT_PORT;
static int config_loaded = 0;

sqlite3 *ctrlpt_dev_db = NULL;
sqlite3 *ctrlpt_state_db = NULL;

static int run_cmdloop = 1;

enum startup_exit_code {
    STARTUP_OK = 0,
    STARTUP_DB_ERROR = 20,
    STARTUP_IFACE_ERROR = 21,
    STARTUP_IPC_ERROR = 22,
    STARTUP_UPNP_ERROR = 23
};

void wemoRequestDiscover(void)
{
    if (wemoCtrlPointIsStopping()) {
        return;
    }
    if (discover_mutex_ready) {
        ithread_mutex_lock(&discover_mutex);
        discover = 1;
        ithread_mutex_unlock(&discover_mutex);
        return;
    }
    discover = 1;
}

int wemoTakeDiscoverRequest(void)
{
    int requested;
    if (discover_mutex_ready) {
        ithread_mutex_lock(&discover_mutex);
        requested = discover;
        discover = 0;
        ithread_mutex_unlock(&discover_mutex);
        return requested;
    }
    requested = discover;
    discover = 0;
    return requested;
}

int wemoHasDiscoverRequest(void)
{
    int requested;
    if (discover_mutex_ready) {
        ithread_mutex_lock(&discover_mutex);
        requested = discover;
        ithread_mutex_unlock(&discover_mutex);
        return requested;
    }
    return discover;
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

static int ensure_dir_recursive(const char *dir, mode_t mode)
{
    char path[PATH_MAX];
    char *p;

    if (dir == NULL || dir[0] == '\0') {
        return -1;
    }
    if (strlen(dir) >= sizeof(path)) {
        return -1;
    }

    strcpy(path, dir);
    for (p = path + 1; *p; p++) {
        if (*p != '/') {
            continue;
        }
        *p = '\0';
        if (mkdir(path, mode) != 0 && errno != EEXIST) {
            return -1;
        }
        *p = '/';
    }
    if (mkdir(path, mode) != 0 && errno != EEXIST) {
        return -1;
    }
    if (chmod(path, mode) != 0 && errno != EPERM) {
        return -1;
    }
    return 0;
}

static int ensure_parent_dir_for_file(const char *file_path, mode_t mode)
{
    char dir[PATH_MAX];
    char *slash;

    if (file_path == NULL || file_path[0] == '\0') {
        return -1;
    }
    if (strlen(file_path) >= sizeof(dir)) {
        return -1;
    }

    strcpy(dir, file_path);
    slash = strrchr(dir, '/');
    if (slash == NULL || slash == dir) {
        return 0;
    }
    *slash = '\0';
    return ensure_dir_recursive(dir, mode);
}

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

static int ensure_db_storage_ready(void)
{
    if (ensure_parent_dir_for_file(wemo_device_db, 0700) != 0) {
        LOG_ERROR_MSG("failed to prepare DB directory for %s: %s", wemo_device_db, strerror(errno));
        return CTRLPT_ERROR;
    }
    if (ensure_parent_dir_for_file(wemo_state_db, 0700) != 0) {
        LOG_ERROR_MSG("failed to prepare DB directory for %s: %s", wemo_state_db, strerror(errno));
        return CTRLPT_ERROR;
    }
    return CTRLPT_SUCCESS;
}

void
linux_print( const char *string )
{
    char buf[128];
    time_t curtime;
    struct tm *loc_time;
    curtime = time(NULL);
    loc_time = localtime(&curtime);
    strftime(buf, 128, "%D %H:%M:%S : ", loc_time);
    fprintf(stdout, "\x1B[34m");
    fprintf(stdout, "%s", buf);
    puts(string);
    fprintf(stdout, "\x1B[0m");
    fflush(stdout);
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

/********************************************************************************
 * wemoCtrlPointPrintHelp
 *
 * Description:
 *       Print help info for this application.
 ********************************************************************************/
void
wemoCtrlPointPrintShortHelp( void )
{
    LOG_DEBUG_MSG("Commands:" );
    LOG_DEBUG_MSG("  Help" );
    LOG_DEBUG_MSG("  HelpFull" );
    LOG_DEBUG_MSG("  ListDev" );
    LOG_DEBUG_MSG("  Refresh" );
    LOG_DEBUG_MSG("  PrintDev      <devnum>" );
    LOG_DEBUG_MSG("  PowerOn       <devnum>" );
    LOG_DEBUG_MSG("  PowerOff      <devnum>" );
    LOG_DEBUG_MSG("  GetPower      <devnum>" );
    LOG_DEBUG_MSG("  SetLevel      <devnum> <level>" );
    LOG_DEBUG_MSG("  GetLevel      <devnum>" );
    LOG_DEBUG_MSG("  Exit" );
}

void
wemoCtrlPointPrintLongHelp( void )
{
    LOG_DEBUG_MSG(" ");
    LOG_DEBUG_MSG("******************************" );
    LOG_DEBUG_MSG("* WEMO Control Point Help Info *" );
    LOG_DEBUG_MSG("******************************" );
    LOG_DEBUG_MSG(" ");
    LOG_DEBUG_MSG("Commands:" );
    LOG_DEBUG_MSG("  Help" );
    LOG_DEBUG_MSG("       Print this help info." );
    LOG_DEBUG_MSG("  ListDev" );
    LOG_DEBUG_MSG("       Print the current list of TV Device Emulators that this" );
    LOG_DEBUG_MSG("         control point is aware of.  Each device is preceded by a" );
    LOG_DEBUG_MSG("         device number which corresponds to the devnum argument of" );
    LOG_DEBUG_MSG("         commands listed below." );
    LOG_DEBUG_MSG("  Refresh" );
    LOG_DEBUG_MSG("       Delete all of the devices from the device list and issue new" );
    LOG_DEBUG_MSG("         search request to rebuild the list from scratch." );
    LOG_DEBUG_MSG("  PrintDev       <devnum>" );
    LOG_DEBUG_MSG("       Print the state table for the device <devnum>." );
    LOG_DEBUG_MSG("         e.g., 'PrintDev 1' prints the state table for the first" );
    LOG_DEBUG_MSG("         device in the device list." );
    LOG_DEBUG_MSG("  PowerOn        <devnum>" );
    LOG_DEBUG_MSG("       Sends the PowerOn action to the Control Service of" );
    LOG_DEBUG_MSG("         device <devnum>." );
    LOG_DEBUG_MSG("  PowerOff       <devnum>" );
    LOG_DEBUG_MSG("       Sends the PowerOff action to the Control Service of" );
    LOG_DEBUG_MSG("         device <devnum>." );
    LOG_DEBUG_MSG("  GetPower       <devnum>" );
    LOG_DEBUG_MSG("       get current power state of" );
    LOG_DEBUG_MSG("         device <devnum>." );
    LOG_DEBUG_MSG("  SetLevel       <devnum> <level>" );
    LOG_DEBUG_MSG("       Sends power level of" );
    LOG_DEBUG_MSG("         device <devnum> <level>." );
    LOG_DEBUG_MSG("  GetLevel       <devnum>" );
    LOG_DEBUG_MSG("       get current power level of" );
    LOG_DEBUG_MSG("         device <devnum>." );
    LOG_DEBUG_MSG("  Exit" );
    LOG_DEBUG_MSG("       Exits the control point application." );
}

/********************************************************************************
 * wemoCtrlPointPrintCommands
 *
 * Description:
 *       Print the list of valid command line commands to the user
 *
 * Parameters:
 *   None
 *
 ********************************************************************************/
void
wemoCtrlPointPrintCommands()
{
    int i;
    int numofcmds = sizeof( cmdloop_cmdlist ) / sizeof( cmdloop_commands );

    LOG_DEBUG_MSG("Valid Commands:" );
    for( i = 0; i < numofcmds; i++ ) {
        LOG_DEBUG_MSG("  %-14s %s", cmdloop_cmdlist[i].str,
                          cmdloop_cmdlist[i].args );
    }
    LOG_DEBUG_MSG(" ");
}

/********************************************************************************
 * wemoCtrlPointCommandLoop
 *
 * Description:
 *       Function that receives commands from the user at the command prompt
 *       during the lifetime of the control point, and calls the appropriate
 *       functions for those commands.
 *
 * Parameters:
 *    None
 *
 ********************************************************************************/
void *
wemoCtrlPointCommandLoop( void *args )
{
    char cmdline[100];

    while(run_cmdloop) {
        LOG_DEBUG_MSG("\n>> " );
        fgets( cmdline, 100, stdin );
        wemoCtrlPointProcessCommand( cmdline );
    }

    return NULL;
}

int
wemoCtrlPointProcessCommand( char *cmdline )
{
    char cmd[100];
    int arg_val_err = -99999;
    int arg1 = arg_val_err;
    int arg2 = arg_val_err;
    int cmdnum = -1;
    int numofcmds = sizeof( cmdloop_cmdlist ) / sizeof( cmdloop_commands );
    int cmdfound = 0;
    int i;
    int invalidargs = 0;
    int validargs;

    validargs = sscanf( cmdline, "%s %d %d", cmd, &arg1, &arg2 );

    for( i = 0; i < numofcmds; i++ ) {
        if( strcasecmp( cmd, cmdloop_cmdlist[i].str ) == 0 ) {
            cmdnum = cmdloop_cmdlist[i].cmdnum;
            cmdfound++;
            if( validargs != cmdloop_cmdlist[i].numargs )
                invalidargs++;
            break;
        }
    }

    if( !cmdfound ) {
        LOG_DEBUG_MSG("Command not found; try 'Help'" );
        return CTRLPT_SUCCESS;
    }

    if( invalidargs ) {
        LOG_DEBUG_MSG("Invalid arguments; try 'Help'" );
        return CTRLPT_SUCCESS;
    }

    switch ( cmdnum ) {
        case PRTHELP:
            wemoCtrlPointPrintShortHelp();
            break;

        case PRTFULLHELP:
            wemoCtrlPointPrintLongHelp();
            break;

        case POWERON:
            wemoCtrlPointSendPowerOn(arg1, 1);
            break;

        case POWEROFF:
            wemoCtrlPointSendPowerOff(arg1, 1);
            break;

        case GETPOWER:
            wemoCtrlPointGetPower(arg1);
            break;

        case SETLEVEL:
            wemoCtrlPointSetLevel(arg1, arg2, 1);
            break;

        case GETLEVEL:
            wemoCtrlPointGetLevel(arg1);
            break;

        case PRTDEV:
            wemoCtrlPointPrintDevice( arg1 );
            break;

        case LSTDEV:
            wemoCtrlPointPrintList();
            break;

        case REFRESH:
            wemoCtrlPointRefresh();
            break;

        case EXITCMD:
            run_cmdloop = 0;
            break;

        default:
            LOG_DEBUG_MSG("Command not implemented; see 'Help'" );
            break;
    }

    if( invalidargs )
        LOG_DEBUG_MSG("Invalid args in command; see 'Help'" );

    return CTRLPT_SUCCESS;
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

int process_config()
{
    FILE *conf = fopen (CONFIG_FILE_PATH, "r");

    if (conf != NULL) {
        config_loaded = 1;
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
                LOG_DEBUG_MSG("ignoring malformed config line: %s", trimmed);
                continue;
            }

            *eq = '\0';
            key = trim_whitespace(trimmed);
            value = trim_whitespace(eq + 1);
            strip_string(value);

            if (!strcasecmp("wemo_device_db", key)) {
                if (value[0] != '\0') {
                    snprintf(wemo_device_db, sizeof(wemo_device_db), "%s", value);
                    LOG_DEBUG_MSG("wemo_device_db = %s\n", wemo_device_db);
                }
                else {
                    LOG_DEBUG_MSG("error parsing wemo_device_db!\n");
                }
            }
            else if (!strcasecmp("wemo_state_db", key)) {
                if (value[0] != '\0') {
                    snprintf(wemo_state_db, sizeof(wemo_state_db), "%s", value);
                    LOG_DEBUG_MSG("wemo_state_db = %s\n", wemo_state_db);
                }
                else {
                    LOG_DEBUG_MSG("error parsing wemo_state_db!\n");
                }
            }
            else if (!strcasecmp("ifname", key)) {
                if (value[0] != '\0') {
                    snprintf(upnp_ifname, sizeof(upnp_ifname), "%s", value);
                    LOG_DEBUG_MSG("upnp interface name= %s\n", upnp_ifname);
                    ifname_set = 1;
                }
                else {
                    LOG_DEBUG_MSG("error parsing ifname!\n");
                }
            }
            else if (!strcasecmp("ipc_bind", key)) {
                if (value[0] != '\0') {
                    snprintf(ipc_bind_addr, sizeof(ipc_bind_addr), "%s", value);
                    LOG_DEBUG_MSG("ipc bind addr = %s\n", ipc_bind_addr);
                } else {
                    LOG_DEBUG_MSG("error parsing ipc_bind!\n");
                }
            }
            else if (!strcasecmp("ipc_port", key)) {
                if (value[0] != '\0') {
                    ipc_port = atoi(value);
                    LOG_DEBUG_MSG("ipc port = %d\n", ipc_port);
                } else {
                    LOG_DEBUG_MSG("error parsing ipc_port!\n");
                }
            }
            else {
                LOG_DEBUG_MSG("unknown item %s\n", key);
            }
        }
        fclose(conf);
    }
    else {
        config_loaded = 0;
        LOG_DEBUG_MSG("No configuration file (/etc/wemo_ctrl.conf)...\n");
        LOG_DEBUG_MSG("using default DB path %s and %s\n", wemo_device_db, wemo_state_db);
        return CTRLPT_ERROR;
    }

    return CTRLPT_SUCCESS;
 }

static int startup_check_interface(void)
{
    if (upnp_ifname[0] == '\0') {
        LOG_ERROR_MSG("startup self-test: interface not set");
        return STARTUP_IFACE_ERROR;
    }
    if (if_nametoindex(upnp_ifname) == 0) {
        LOG_ERROR_MSG("startup self-test: interface '%s' not found", upnp_ifname);
        return STARTUP_IFACE_ERROR;
    }
    if (!is_up_or_unknown(upnp_ifname)) {
        LOG_ERROR_MSG("startup self-test: interface '%s' not up", upnp_ifname);
        return STARTUP_IFACE_ERROR;
    }
    return STARTUP_OK;
}

static int startup_check_ipc_listener(const char *addr, int port)
{
    int fd;
    struct sockaddr_in sa;
    int i;

    if (addr == NULL || addr[0] == '\0' || port <= 0 || port >= 65536) {
        return STARTUP_IPC_ERROR;
    }
    for (i = 0; i < 20; i++) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return STARTUP_IPC_ERROR;
        }
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
            close(fd);
            return STARTUP_IPC_ERROR;
        }
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            close(fd);
            return STARTUP_OK;
        }
        close(fd);
        usleep(100 * 1000);
    }
    LOG_ERROR_MSG("startup self-test: ipc listener unavailable at %s:%d", addr, port);
    return STARTUP_IPC_ERROR;
}

static int startup_self_test(int upnp_started)
{
    if (ctrlpt_dev_db == NULL || ctrlpt_state_db == NULL) {
        LOG_ERROR_MSG("startup self-test: DB handles are NULL");
        return STARTUP_DB_ERROR;
    }
    if (startup_check_interface() != STARTUP_OK) {
        return STARTUP_IFACE_ERROR;
    }
    if (startup_check_ipc_listener(ipc_bind_addr, ipc_port) != STARTUP_OK) {
        return STARTUP_IPC_ERROR;
    }
    if (upnp_started && ctrlpt_handle < 0) {
        LOG_ERROR_MSG("startup self-test: invalid UPnP handle=%d", ctrlpt_handle);
        return STARTUP_UPNP_ERROR;
    }
    LOG_INFO_MSG("startup self-test: PASS upnp_started=%d ipc=%s:%d ifname=%s",
                 upnp_started, ipc_bind_addr, ipc_port, upnp_ifname);
    return STARTUP_OK;
}

int main( int argc, char **argv )
{
    int rc;
    int sig;
    sigset_t sigs_to_catch;

    printf("Copyright (c) 2000-2003 Intel Corporation\n");
    printf("All rights reserved.\n");

    NvramInit(0, NULL);
    initLogger();
    ithread_mutex_init(&discover_mutex, NULL);
    discover_mutex_ready = 1;

    /* use default values if any one of config item is not found */
    set_default_db_paths();
    strcpy(upnp_ifname, DEFAULT_IFNAME);

    /*
       Catch Ctrl-C and properly shutdown
     */
    sigemptyset(&sigs_to_catch);
    //sigaddset(&sigs_to_catch, SIGINT);
    //    sigaddset(&sigs_to_catch, SIGTERM);
    sigaddset (&sigs_to_catch, SIGQUIT);
    sigaddset (&sigs_to_catch, SIGINT);
    sigaddset (&sigs_to_catch, SIGTERM);
    sigaddset (&sigs_to_catch, SIGUSR1);
    pthread_sigmask (SIG_BLOCK, &sigs_to_catch, NULL);

    if (process_config() != CTRLPT_SUCCESS) {
        LOG_DEBUG_MSG("/etc/wemo_ctrl.conf not found using default DB paths\n");
    }
    if (ensure_db_storage_ready() != CTRLPT_SUCCESS) {
        return STARTUP_DB_ERROR;
    }
    LOG_INFO_MSG("DB path source=%s device_db=%s state_db=%s",
            config_loaded ? "config" : "default",
            wemo_device_db,
            wemo_state_db);
    if (!ifname_set) {
        char selected[IFNAMSIZ] = {0};
        if (choose_preferred_ifname(selected, sizeof(selected)) == 0) {
            strcpy(upnp_ifname, selected);
            LOG_DEBUG_MSG("auto-selected upnp interface name= %s\n", upnp_ifname);
        }
    }
    {
        const char *env_if = getenv("WEMO_UPNP_IFNAME");
        if (env_if != NULL && env_if[0] != '\0') {
            strncpy(upnp_ifname, env_if, sizeof(upnp_ifname) - 1);
            upnp_ifname[sizeof(upnp_ifname) - 1] = '\0';
            ifname_set = 1;
            LOG_INFO_MSG("override upnp interface name from env: %s", upnp_ifname);
        }
    }
    rc = wemo_dev_db_init(&ctrlpt_dev_db, &ctrlpt_state_db);

    if(rc != CTRLPT_SUCCESS) {
    	LOG_DEBUG_MSG("Error initializing sqlite DB");
    	return STARTUP_DB_ERROR;
    }
    wemo_ipc_server_set_bind(ipc_bind_addr, ipc_port);
    wemo_ipc_server_init();
    LOG_INFO_MSG("wemo_ctrl pid=%d ipc=%s:%d", getpid(), ipc_bind_addr, ipc_port);
    rc = startup_self_test(0);
    if (rc != STARTUP_OK) {
        wemo_ipc_server_finish();
        wemo_dev_db_finish(ctrlpt_dev_db, ctrlpt_state_db);
        return rc;
    }

    rc = wemoCtrlPointStart(upnp_ifname, linux_print, NULL );
    if( rc != CTRLPT_SUCCESS ) {
        LOG_ERROR_MSG("Error starting UPnP WEMO Control Point (rc=%d)", rc );
        wemo_ipc_server_finish();
        wemo_dev_db_finish(ctrlpt_dev_db, ctrlpt_state_db);
        return STARTUP_UPNP_ERROR;
    }
    rc = startup_self_test(1);
    if (rc != STARTUP_OK) {
        wemo_ipc_server_finish();
        wemoCtrlPointStop();
        wemo_dev_db_finish(ctrlpt_dev_db, ctrlpt_state_db);
        return rc;
    }

    {
        const char *env_discover = getenv("WEMO_INITIAL_DISCOVER");
        int enable_initial_discover = 1;
        if (env_discover != NULL && env_discover[0] != '\0') {
            enable_initial_discover = atoi(env_discover) != 0;
        }
        if (enable_initial_discover) {
            // Trigger an initial refresh so IPC clients can resolve wemo_id -> live device quickly.
            wemoRequestDiscover();
            LOG_INFO_MSG("Initial discover scheduled");
        } else {
            LOG_INFO_MSG("Initial discover disabled by WEMO_INITIAL_DISCOVER=0");
        }
    }

    /* start a command loop thread */
    //    int code;
    //    pthread_t cmdloop_thread;
    //    code = pthread_create(&cmdloop_thread, NULL, wemoCtrlPointCommandLoop, NULL);
    //    pthread_join(cmdloop_thread, NULL);
    //    wemoCtrlPointCommandLoop(NULL);

    while (1) {
        sigwait(&sigs_to_catch, &sig );
        if (sig == SIGUSR1) {
            LOG_DEBUG_MSG("Received SIGUSR1, calling discover...");
            wemoRequestDiscover();
        } else {
            break;
        }
    }

    LOG_DEBUG_MSG("Shutting down on signal %d...\n", sig );

    wemo_ipc_server_finish();
    rc = wemoCtrlPointStop();
    wemo_dev_db_finish(ctrlpt_dev_db, ctrlpt_state_db);
    if (discover_mutex_ready) {
        ithread_mutex_destroy(&discover_mutex);
        discover_mutex_ready = 0;
    }
    return rc;
}
