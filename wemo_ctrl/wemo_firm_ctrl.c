#include "wemo_firm_ctrl.h"
#include "logger.h"

#define FIRM_DOWNLOAD_TIME_LEN 16

int wemoCtrlPointFirmwareUpdate(int wemo_id, struct we_firmware_data *firm_data)
{
    char *arguments[] = { "NewFirmware", "ReleaseDate", "URL", "Signature",
                          "DownloadStartTime", "WithUnsignedImage"};

    int count = (int)(sizeof(arguments) / sizeof(arguments[0]));
    int dev_id, ret, i;
    char *value[count];

    if ((dev_id = wemoCtrlPointGetDevID(wemo_id)) == -1) {
        LOG_DEBUG_MSG("device %d not found.", wemo_id);

        return CTRLPT_ERROR;
    }

    /* XXX Need to check that the unused key(arguments) must be allocate memory. */
    value[0] = NULL;
    value[1] = NULL;
    value[2] = (char *)malloc(strlen(firm_data->url) + 1);
    value[3] = NULL;
    value[4] = (char *)malloc(FIRM_DOWNLOAD_TIME_LEN);
    value[5] = (char *)malloc(sizeof(char) + 1);
    strcpy(value[2], firm_data->url);
    snprintf(value[4], FIRM_DOWNLOAD_TIME_LEN, "%ld", firm_data->start_time);
    snprintf(value[5], sizeof(char) + 1, "%d", firm_data->unsign_img);

    LOG_INFO_MSG("firmware download url : %s", firm_data->url);
    ret = wemoCtrlPointSendActionEx(WEMO_SERVICE_FIRMWAREUPDATE,
                                    dev_id,
                                    "UpdateFirmware",
                                    arguments,
                                    (char **)value,
                                    6,
                                    0);

    for (i = 0; i < count; i++)
        if (value[i] != NULL)
            free(value[i]);

    return ret;
}
