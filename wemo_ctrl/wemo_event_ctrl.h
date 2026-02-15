#ifndef WEMO_EVENT_CTRL_H_
#define WEMO_EVENT_CTRL_H_

#include "wemo_ctrl.h"

int wemoCtrlPointGetPower( int devnum );
int wemoCtrlPointGetLevel(int devnum);
int wemoCtrlPointRetrieveState(int wemo_id, struct we_state *state_data);
int wemoCtrlPointSendPowerOn(int devnum, int async);
int wemoCtrlPointSendPowerOff(int devnum, int async);
int wemoCtrlPointSetLevel(int devnum, int level, int async);
int wemoCtrlPointSetDimmer(int devnum, int state, int level, int async);
int wemoCtrlPointTriggerAction(int wemo_id, struct we_state *state_data, int async);
int wemoCtrlPointSetHKSetupState(int wemo_id, struct we_hksetup_state *state);

#endif
