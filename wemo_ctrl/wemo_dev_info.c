#include "wemo_dev_info.h"
#include "logger.h"

int wemoCtrlGetInformation(int wemo_id)
{
    int ret;

    LOG_INFO_MSG("Sending GetInformation...");
    ret = wemoCtrlPointSendAction(WEMO_SERVICE_DEVICEINFO,
                                  wemo_id,
                                  "GetInformation",
                                  NULL,
                                  NULL,
                                  0,
                                  0);
    return ret;
}
