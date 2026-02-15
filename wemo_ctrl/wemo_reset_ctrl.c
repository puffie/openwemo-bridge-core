#include "wemo_reset_ctrl.h"
#include "logger.h"

int wemoCtrlPointReset(int wemo_id, struct we_reset *reset_data)
{
    char *arguments[] = { "Reset" };

    int count = (int)(sizeof(arguments) / sizeof(arguments[0]));
    int dev_id, ret, i;
    char *value[count];

    if ((dev_id = wemoCtrlPointGetDevID(wemo_id)) == -1) {
        LOG_DEBUG_MSG("device %d not found", wemo_id);

        return CTRLPT_ERROR;
    }

    value[0] = (char *)malloc(4);
    sprintf(value[0], "%d", reset_data->reset_type);

    LOG_INFO_MSG("Calling ReSetup : %d", reset_data->reset_type);
    ret = wemoCtrlPointSendActionEx(WEMO_SERVICE_BASICEVENT, dev_id,
                                  "ReSetup", arguments, (char **)value, 1, 0);

    for (i = 0; i < count; i++)
        if (value[i] != NULL)
            free(value[i]);

    return ret;
}
