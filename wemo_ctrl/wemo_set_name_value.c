#include "wemo_set_name_value.h"
#include "logger.h"

int wemoCtrlPointSetNameValue(int wemo_id, struct we_name_value *data)
{
    char *argument[1];
    char *value[1];;
    char action[64] = {0,};
    int dev_id, ret = -1;

    if ((dev_id = wemoCtrlPointGetDevID(wemo_id)) == -1) {
        LOG_DEBUG_MSG("device %d not found", wemo_id);

        return CTRLPT_ERROR;
    }

    memset(action, 0, 64);

    argument[0] = NULL;
    value[0] = NULL;
    argument[0] = (char *)malloc(strlen(data->name) + 1);
    strcpy(argument[0], data->name);
    value[0] = (char *)malloc(strlen(data->value) + 1);
    strcpy(value[0], data->value);

    if (strcmp(data->name, "fader") == 0) {
        LOG_INFO_MSG("Calling SetBinaryState for fader : %s", data->value);
        strcpy(action, "SetBinaryState");
    }
    if (strcmp(data->name, "NightModeConfiguration") == 0) {
        LOG_INFO_MSG("Calling NightModeConfiguration : %s", data->value);
        strcpy(action, "ConfigureNightMode");
    }
    if (strcmp(data->name, "hushMode") == 0) {
        LOG_INFO_MSG("Calling configureHushMode : %s", data->value);
        strcpy(action, "ConfigureHushMode");
    }
    if (strcmp(data->name, "IconVersion") == 0) {
        LOG_INFO_MSG("Calling SetIconVersion : %s", data->value);
        strcpy(action, "SetIconVersion");
    }

    if (strlen(action)) {
        LOG_INFO_MSG("Calling wemoCtrlPointSendAction : \n\taction: %s, argument: %s, value: %s",
                action, argument[0], value[0]);

        ret = wemoCtrlPointSendAction(WEMO_SERVICE_BASICEVENT,
                                      dev_id,
                                      action,
                                      (char **)argument,
                                      (char **)value,
                                      1,
                                      0);
    }

    if (argument[0] != NULL)
        free(argument[0]);
    if (value[0] != NULL)
        free(value[0]);

    return ret;
}
