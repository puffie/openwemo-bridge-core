#include <sqlite3.h>
#include <time.h>
#include <unistd.h>
#include "wemo_event_ctrl.h"
#include "wemo_device_db.h"
#include "wemo_ipc_server.h"
#include "logger.h"

extern sqlite3 *ctrlpt_state_db;

static void trigger_refresh_if_needed(void)
{
    static time_t sLastRefresh = 0;
    time_t now                 = time(NULL);

    if (now - sLastRefresh >= 15)
    {
        sLastRefresh = now;
        LOG_INFO_MSG("device mapping missing; scheduling refresh");
        wemoRequestDiscover();
    }
}

static int resolve_dev_id_with_retry(int wemo_id)
{
    int dev_id = wemoCtrlPointGetDevID(wemo_id);
    if (dev_id != -1) {
        return dev_id;
    }

    LOG_INFO_MSG("device %d mapping not found; retrying after refresh", wemo_id);
    trigger_refresh_if_needed();
    usleep(250 * 1000);
    return wemoCtrlPointGetDevID(wemo_id);
}

int wemoCtrlPointGetPower( int devnum )
{
    return wemoCtrlPointSendActionEx(WEMO_SERVICE_BASICEVENT, devnum,
                                     "GetBinaryState", NULL, NULL, 0, 0);
}

int wemoCtrlPointGetLevel(int devnum)
{
    return wemoCtrlPointSendActionEx(WEMO_SERVICE_BASICEVENT, devnum,
                                     "GetBinaryState", NULL, NULL, 0, 0);
}

int wemoCtrlPointRetrieveState(int wemo_id, struct we_state *state_data)
{
    struct wemoDeviceNode *devnode;
    IXML_Document *actionNode = NULL;
    int rc = CTRLPT_SUCCESS;
    int dev_id = -1;

    if ((dev_id = wemoCtrlPointGetDevID(wemo_id)) == -1) {
        LOG_INFO_MSG("device %d mapping not found", wemo_id);
        trigger_refresh_if_needed();

        return CTRLPT_ERROR;
    }
    else {
        ithread_mutex_lock( &DeviceListMutex );
        rc = wemoCtrlPointGetDevice( dev_id, &devnode );
        if( CTRLPT_SUCCESS == rc ) {
            actionNode = UpnpMakeAction("GetBinaryState",
                                        wemoServiceType[WEMO_SERVICE_BASICEVENT],
                                        0,
                                        NULL);

            rc = UpnpSendActionAsync(ctrlpt_handle,
                                     devnode->device.wemoService[WEMO_SERVICE_BASICEVENT].ControlURL,
                                     wemoServiceType[WEMO_SERVICE_BASICEVENT],
                                     NULL,
                                     actionNode,
                                     (Upnp_FunPtr) wemoCtrlPointCallbackEventHandler,
                                     NULL);
            if( rc != UPNP_E_SUCCESS ) {
                LOG_DEBUG_MSG("Error in UpnpSendActionAsync -- %d", rc );
                rc = CTRLPT_ERROR;
            }
        }
        ithread_mutex_unlock( &DeviceListMutex );

        if( actionNode )
            ixmlDocument_free( actionNode );
    }
    return rc;
}

int wemoCtrlPointSendPowerOn(int devnum, int async)
{
    char *state[] = { "BinaryState" };
    char *value[] = { "1" };

    return wemoCtrlPointSendActionEx(WEMO_SERVICE_BASICEVENT, devnum,
                                     "SetBinaryState", state, value, 1, async);
}

int wemoCtrlPointSendPowerOff(int devnum, int async)
{
    char *state[] = { "BinaryState" };
    char *value[] = { "0" };

    return wemoCtrlPointSendActionEx(WEMO_SERVICE_BASICEVENT, devnum,
                                     "SetBinaryState", state, value, 1, async);
}

int wemoCtrlPointSetLevel(int devnum, int level, int async)
{
    char *brightness[] = {"brightness"};
    char value[4];
    char *param;

    if ((level < 0) || (level > 100)) {
        return CTRLPT_ERROR;
    }

    sprintf(value, "%d", level);

    param = value;
    return wemoCtrlPointSendActionEx(WEMO_SERVICE_BASICEVENT, devnum,
                                     "SetBinaryState", brightness, &param, 1, async);
}

int wemoCtrlPointSetDimmer(int devnum, int state, int level, int async)
{
    char *set_dimmer[] = {"BinaryState", "brightness"};
    char *value[] = {"", ""};
    char state_str[4];
    char value_str[4];

    snprintf(state_str, 4, "%d", state);
    snprintf(value_str, 4, "%d", level);

    value[0] = state_str;
    value[1] = value_str;
    return wemoCtrlPointSendActionEx(WEMO_SERVICE_BASICEVENT, devnum,
                                     "SetBinaryState", set_dimmer, (char **) value, 2, async);
}

int wemoCtrlPointTriggerAction(int wemo_id, struct we_state *state_data, int async)
{
    int dev_id = -1;
    int rc = CTRLPT_SUCCESS;
    struct we_state state_buffer;

    if ((dev_id = resolve_dev_id_with_retry(wemo_id)) == -1) {
        LOG_INFO_MSG("device %d mapping not found", wemo_id);
        return CTRLPT_ERROR;
    }
    else {
        if (state_data->level != -1) {
            if (wemo_dev_db_get_capability(ctrlpt_state_db, wemo_id, CAP_LEVEL) == state_data->level) {
                if ((wemo_dev_db_get_capability(ctrlpt_state_db, wemo_id, CAP_BINARY) == state_data->state) ||
                    (state_data->state == -1)) {
                    state_buffer.is_online = 1;
                    state_buffer.state = wemo_dev_db_get_capability(ctrlpt_state_db, wemo_id, CAP_BINARY);
                    state_buffer.level = state_data->level;
                    LOG_DEBUG_MSG("sending event wemo_id = %d, is_online = %d, state = %d, level = %d",
                                      wemo_id,
                                      state_buffer.is_online,
                                      state_buffer.state,
                                      state_buffer.level);

                    wemo_ipc_send_event(wemo_id, &state_buffer);
        }
        else {
                    if (state_data->state == 1) {
                        wemoCtrlPointSendPowerOn(dev_id, async);
        }
                    else if (state_data->state == 0) {
                        wemoCtrlPointSendPowerOff(dev_id, async);
    }

                }
    }
    else {
        if (state_data->state != -1) {
                    wemoCtrlPointSetDimmer(dev_id, state_data->state, state_data->level, async);
            }
            else {
                    wemoCtrlPointSetLevel(dev_id, state_data->level, async);
            }
        }
        }
        else if (state_data->state != -1) {
            /*
             * Always forward explicit on/off commands to the device.
             * For dimmers, prefer SetBinaryState with brightness so devices
             * that require level context apply the command reliably.
             */
            int level = wemo_dev_db_get_capability(ctrlpt_state_db, wemo_id, CAP_LEVEL);
            if (level >= 0) {
                int target_level = state_data->state ? (level > 0 ? level : 100) : 0;
                LOG_INFO_MSG("send dimmer state for wemo_id=%d state=%d level=%d",
                        wemo_id, state_data->state, target_level);
                rc = wemoCtrlPointSetDimmer(dev_id, state_data->state, target_level, async);
            } else if (state_data->state) {
                LOG_INFO_MSG("send poweron for wemo_id=%d", wemo_id);
                rc = wemoCtrlPointSendPowerOn(dev_id, async);
            } else {
                LOG_INFO_MSG("send poweroff for wemo_id=%d", wemo_id);
                rc = wemoCtrlPointSendPowerOff(dev_id, async);
            }

            if (rc != CTRLPT_SUCCESS) {
                LOG_ERROR_MSG("failed to send action wemo_id=%d dev_id=%d state=%d level=%d rc=%d",
                        wemo_id, dev_id, state_data->state, level, rc);
            }
        }
    }
    return CTRLPT_SUCCESS;
}

int wemoCtrlPointSetHKSetupState(int wemo_id, struct we_hksetup_state *state)
{
    char *arguments[] = { "HKSetupDone" };
    char *value[1];
    int dev_id;
    int ret = 0;

    if ((dev_id = wemoCtrlPointGetDevID(wemo_id)) == -1) {
        LOG_DEBUG_MSG("device %d not found", wemo_id);

        return CTRLPT_ERROR;
    }

    value[0] = (char *) malloc(sizeof(int));
    sprintf(value[0], "%d", state->hksetup_state);

    ret = wemoCtrlPointSendActionEx(WEMO_SERVICE_BASICEVENT, dev_id,
                                  "setHKSetupState", arguments, (char **) value, 1, 0);
    free(value[0]);
    return ret;
}
