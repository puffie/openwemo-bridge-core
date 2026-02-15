/*
 * wemo_ipc_server.h
 *
 *  Created on: May 4, 2017
 *      Author: harry
 */

#ifndef WEMO_IPC_SERVER_H_
#define WEMO_IPC_SERVER_H_

#include "ithread.h"
#include "wemo_ctrl.h"
#include "wemo_engine.h"

void wemo_ipc_send_event(int wemo_id, struct we_state *state_buffer);
void wemo_ipc_send_netstate(int wemo_id, struct we_network_status *net_state);
void wemo_ipc_send_name_change(int wemo_id, struct we_name_change *name_change);
void wemo_ipc_send_name_value(int wemo_id, struct we_name_value *name_value);
void wemo_ipc_send_devinfo(int wemo_id, char *data);
void wemo_ipc_send_insight_home_settings(int wemo_id, struct we_insight_home_settings *settings);
void wemo_ipc_server_set_bind(const char *addr, int port);
void wemo_ipc_server_init();
void wemo_ipc_server_finish();

#endif /* WEMO_IPC_SERVER_H_ */
