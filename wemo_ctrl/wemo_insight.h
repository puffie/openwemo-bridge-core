#ifndef WEMO_INSIGHT_HOME_SETTINGS_H
#define WEMO_INSIGHT_HOME_SETTINGS_H

#include "wemo_ctrl.h"

int wemoCtrlGetInsightHomeSettings(int wemo_id);
int wemoCtrlSetInsightHomeSettings(int wemo_id, struct we_insight_home_settings *settings);
int wemoCtrlGetInsightParams(int wemo_id);
int wemoCtrlSetPowerThreshold(int wemo_id, struct we_insight_threshold *threshold);
int wemoCtrlGetPowerThreshold(int wemo_id);
int wemoCtrlGetDataExportInfo(int wemo_id);
int wemoCtrlScheduleDataExport(int wemo_id, struct we_insight_export *export);
#endif
