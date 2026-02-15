#include "wemo_net_ctrl.h"
#include "logger.h"

int wemoCtrlPointNetworkSetup(int wemo_id, struct we_conn_data *setup_data)
{
    int dev_id;
    char *arguments[] = { "ssid", "password", "auth", "encrypt", "channel" };
    char* value[5];
    int ret = 0;

    if ((dev_id = wemoCtrlPointGetDevID(wemo_id)) == -1) {
         LOG_DEBUG_MSG("device %d not found", wemo_id);

        return CTRLPT_ERROR;
    }

    value[0] = (char *) malloc(strlen(setup_data->ssid) + 1);
    value[1] = (char *) malloc(strlen(setup_data->passphrase) + 1);
    value[2] = (char *) malloc(strlen(setup_data->auth) + 1);
    value[3] = (char *) malloc(strlen(setup_data->encrypt) + 1);
    value[4] = (char *) malloc(4);
    strcpy(value[0], setup_data->ssid);
    strcpy(value[1], setup_data->passphrase);
    strcpy(value[2], setup_data->auth);
    strcpy(value[3], setup_data->encrypt);
    sprintf(value[4], "%d", setup_data->channel);

    LOG_DEBUG_MSG("ssid=%s, auth=%s, encrypt=%s, channel=%d",
           setup_data->ssid, setup_data->auth, setup_data->encrypt, setup_data->channel);
    ret = wemoCtrlPointSendAction(WEMO_SERVICE_WIFISETUP, dev_id,
                                   "ConnectHomeNetwork", arguments,
                                    (char **) value, 5, 0);

    free(value[0]);
    free(value[1]);
    free(value[2]);
    free(value[3]);
    free(value[4]);
    /* NVRAM provisioning not used in this build */

    return ret;
}

int wemoCtrlPointGetNetworkStatus(int wemo_id, struct we_network_status *net_status)
{
    int dev_id;

    if ((dev_id = wemoCtrlPointGetDevID(wemo_id)) == -1) {
         LOG_DEBUG_MSG("device %d not found", wemo_id);

        return CTRLPT_ERROR;
    }

    return wemoCtrlPointSendAction(WEMO_SERVICE_WIFISETUP, dev_id,
                                   "GetNetworkStatus", NULL, NULL, 0, 0);
}

int wemoCtrlPointCloseSetup(int wemo_id)
{
    int dev_id;

    if ((dev_id = wemoCtrlPointGetDevID(wemo_id)) == -1) {
         LOG_DEBUG_MSG("device %d not found", wemo_id);

        return CTRLPT_ERROR;
    }

    return wemoCtrlPointSendAction(WEMO_SERVICE_WIFISETUP, dev_id,
                                   "CloseSetup", NULL, NULL, 0, 0);
}
