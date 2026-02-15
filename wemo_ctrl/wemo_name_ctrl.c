#include "wemo_name_ctrl.h"
#include "logger.h"

int wemoCtrlPointChangeName(int wemo_id, struct we_name_change *name_data)
{
    char *arguments[] = { "FriendlyName" };

    int count = (int)(sizeof(arguments) / sizeof(arguments[0]));
    int dev_id, ret, i;
    char *value[count];

    if ((dev_id = wemoCtrlPointGetDevID(wemo_id)) == -1) {
        LOG_ERROR_MSG("device %d not found", wemo_id);

        return CTRLPT_ERROR;
    }

    value[0] = (char *)malloc(strlen(name_data->name) + 1);
    strcpy(value[0], name_data->name);

    LOG_INFO_MSG("Calling ChangeFriendlyName : %s", name_data->name);
    ret = wemoCtrlPointSendAction(WEMO_SERVICE_BASICEVENT,
                                    dev_id,
                                    "ChangeFriendlyName",
                                    arguments,
                                    (char **)value,
                                    1,
                                    0);

    for (i = 0; i < count; i++)
        if (value[i] != NULL)
            free(value[i]);

    return ret;
}
