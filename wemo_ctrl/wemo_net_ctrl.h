#ifndef _WEMO_NET_CTRL_H_
#define _WEMO_NET_CTRL_H_

#include "wemo_ctrl.h"

int wemoCtrlPointNetworkSetup(int wemo_id, struct we_conn_data *setup_data);
int wemoCtrlPointGetNetworkStatus(int wemo_id, struct we_network_status *net_status);
int wemoCtrlPointCloseSetup(int wemo_id);

#endif
