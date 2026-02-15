#include "wemo_insight.h"
#include "logger.h"

int wemoCtrlGetInsightHomeSettings(int wemo_id)
{
    int ret;

    LOG_INFO_MSG("Sending GetInsightHomeSettings...");
    ret = wemoCtrlPointSendAction(WEMO_SERVICE_BASICEVENT,
                                  wemo_id,
                                  "GetInsightHomeSettings",
                                  NULL,
                                  NULL,
                                  0,
                                  0);
    return ret;
}

int wemoCtrlSetInsightHomeSettings(int wemo_id, struct we_insight_home_settings *settings)
{
    int ret;
    char *params[] = {"EnergyPerUnitCost", "Currency"};
    char *value[2];

    value[0] = (char *)malloc(strlen(settings->energyPerUnitCost) + 1);
    if (value[0] == NULL) {
        return -1;
    }
    value[1] = (char *)malloc(strlen(settings->Currency) + 1);
    if (value[1] == NULL) {
        free(value[0]);
        return -1;
    }

    sprintf(value[0], "%s", settings->energyPerUnitCost);
    sprintf(value[1], "%s", settings->Currency);

    LOG_INFO_MSG("Sending SetInsightHomeSettings...");
    ret = wemoCtrlPointSendAction(WEMO_SERVICE_BASICEVENT,
                                  wemo_id,
                                  "setInsightHomeSettings",
                                  (char **) params,
                                  (char **) value,
                                  2,
                                  0);
    if (value[0])
        free(value[0]);
    if (value[1])
        free(value[1]);
    return ret;
}

int wemoCtrlGetInsightParams(int wemo_id)
{
    int ret;

    LOG_INFO_MSG("Sending GetInsightParams...");
    ret = wemoCtrlPointSendAction(WEMO_SERVICE_INSIGHT,
                                  wemo_id,
                                  "GetInsightParams",
                                  NULL,
                                  NULL,
                                  0,
                                  0);
    return ret;
}

int wemoCtrlSetPowerThreshold(int wemo_id, struct we_insight_threshold *threshold)
{
    int ret;
    char *params[] = {"PowerThreshold"};
    char *value[1];

    value[0] = (char *)malloc(sizeof(threshold->threshold));
    if (value[0] == NULL) {
        return -1;
    }
    snprintf(value[0], sizeof(threshold->threshold), "%s", threshold->threshold);

    LOG_INFO_MSG("Sending SetPowerThreshold...");
    ret = wemoCtrlPointSendAction(WEMO_SERVICE_INSIGHT,
                                  wemo_id,
                                  "SetPowerThreshold",
                                  (char **) params,
                                  (char **) value,
                                  1,
                                  0);
    if (value[0]) {
        free(value[0]);
    }
    return ret;
}

int wemoCtrlGetPowerThreshold(int wemo_id)
{
    int ret;

    LOG_INFO_MSG("Sending getPowerThreshold...");
    ret = wemoCtrlPointSendAction(WEMO_SERVICE_INSIGHT,
                                  wemo_id,
                                  "GetPowerThreshold",
                                  NULL,
                                  NULL,
                                  0,
                                  0);
    return ret;
}

int wemoCtrlGetDataExportInfo(int wemo_id)
{
    int ret;

    LOG_INFO_MSG("Sending getDataExportInfo...");
    ret = wemoCtrlPointSendAction(WEMO_SERVICE_INSIGHT,
                                  wemo_id,
                                  "GetDataExportInfo",
                                  NULL,
                                  NULL,
                                  0,
                                  0);
    return ret;
}

int wemoCtrlScheduleDataExport(int wemo_id, struct we_insight_export *export)
{
    int ret;
    char *params[] = {"EmailAddress", "DataExportType"};
    char *value[2];

    value[0] = (char *)malloc(strlen(export->email) + 1);
    if (value[0] == NULL) {
        return -1;
    }
    value[1] = (char *)malloc(strlen(export->export_type) + 1);
    if (value[1] == NULL) {
        free(value[0]);
        return -1;
    }

    sprintf(value[0], "%s", export->email);
    sprintf(value[1], "%s", export->export_type);

    LOG_INFO_MSG("Sending ScheduleDataExport... %s : %s", value[0], value[1]);
    ret = wemoCtrlPointSendAction(WEMO_SERVICE_INSIGHT,
                                  wemo_id,
                                  "ScheduleDataExport",
                                  (char **) params,
                                  (char **) value,
                                  2,
                                  0);

    if (value[0])
        free(value[0]);
    if (value[1])
        free(value[1]);
    return ret;
}
