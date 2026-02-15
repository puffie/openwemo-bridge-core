/**************************************************************************
 *
 * Copyright (c) 2000-2003 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * - Neither name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **************************************************************************/

#ifndef WEMO_CTRL_H_
#define WEMO_CTRL_H_

#ifdef __cplusplus
extern "C" {
#endif


#include "ctrlpt_util.h"


#include "ithread.h"
#include "upnp.h"
#include "upnptools.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wemo_engine.h"

#define WEMO_SERVICE_COUNT	10
#define WEMO_SERVICE_WIFISETUP	0
#define WEMO_SERVICE_TIMESYNC	1
#define WEMO_SERVICE_BASICEVENT	2
#define WEMO_SERVICE_FIRMWAREUPDATE	3
#define WEMO_SERVICE_RULES	4
#define WEMO_SERVICE_METAINFO	5
#define WEMO_SERVICE_DEVICEINFO	6
#define WEMO_SERVICE_SMARTSETUP	7
#define WEMO_SERVICE_MANUFACTURE 8
#define WEMO_SERVICE_INSIGHT 9

#define WEMO_MAX_VAL_LEN 4

#define CTRLPT_SUCCESS			0
#define CTRLPT_ERROR			(-1)
#define CTRLPT_WARNING			1

/* This should be the maximum VARCOUNT from above */
#define CTRLPT_MAXVARS			13

extern char wemoDeviceType[];
extern char *wemoServiceType[];
extern char *wemoServiceName[];
extern char *wemoVarName[WEMO_SERVICE_COUNT][CTRLPT_MAXVARS];
extern char wemoVarCount[];
void wemoRequestDiscover(void);
int wemoTakeDiscoverRequest(void);
int wemoHasDiscoverRequest(void);

struct wemo_service {
    char ServiceId[NAME_SIZE];
    char ServiceType[NAME_SIZE];
    char EventURL[NAME_SIZE];
    char ControlURL[NAME_SIZE];
    char SID[NAME_SIZE];
    char *VariableStrVal[CTRLPT_MAXVARS];
};

extern struct wemoDeviceNode *GlobalDeviceList;

struct wemoDevice {
    char UDN[NAME_SIZE];
    char ipaddr[NAME_SIZE];
    char DescDocURL[NAME_SIZE];
    char FriendlyName[NAME_SIZE];
    char PresURL[NAME_SIZE];
    int  AdvrTimeOut;
    char deviceType[NAME_SIZE];
    char manufacturer[NAME_SIZE];
    char modelName[NAME_SIZE];
    char serialNumber[NAME_SIZE];
    char firmwareVersion[NAME_SIZE];
    struct wemo_service wemoService[WEMO_SERVICE_COUNT];
};

struct wemoDeviceNode {
    struct wemoDevice device;
    struct wemoDeviceNode *next;
};

extern ithread_mutex_t DeviceListMutex;

extern UpnpClient_Handle ctrlpt_handle;

void wemoCtrlPointPrintHelp();
int wemoCtrlPointDeleteNode(struct wemoDeviceNode*);
int wemoCtrlPointRemoveDevice(const char *);
int wemoCtrlPointRemoveAll();
int wemoCtrlPointRefresh();
int wemoCtrlPointRestartRule(int wemo_id);

int wemoCtrlPointDeleteDevice(int wemo_id);
int wemoCtrlPointForgetDevice(int wemo_id);
void wemoCtrlPointHandleBinaryStateResponse(struct wemoDeviceNode *devnode, int service, IXML_Document *action_result, int ack_send);
void wemoCtrlPointHandleActionResponse(struct wemoDeviceNode *devnode, int service, IXML_Document *action_result, int act_send);
int wemoCtrlPointSendAction(int, int, char *, char **, char **, int, int);
int wemoCtrlPointSendActionEx(int, int, char *, char **, char **, int, int);
int wemoCtrlPointSendActionNumericArg(int devnum, int service, char *actionName, char *paramName, int paramValue, int async);

int wemoCtrlPointGetVar(int, int, char*);
int wemoCtrlPointGetDevID(int wemo_id);
int wemoCtrlPointGetDevice(int, struct wemoDeviceNode **);
int wemoCtrlPointPrintList( void );
int wemoCtrlPointPrintDevice(int);
int wemoCtrlPointIsStopping(void);
void wemoCtrlPointAddDevice(IXML_Document *, const char *, int);
void wemoCtrlPointHandleGetVar(const char *, const char *, const DOMString);
void wemoStateUpdate(char*,int, IXML_Document * , char **);
void wemoCtrlPointHandleEvent(const UpnpString *, int, IXML_Document *);
void wemoCtrlPointHandleSubscribeUpdate(const char *, const Upnp_SID, int);
int wemoCtrlPointCallbackEventHandler(Upnp_EventType, void *, void *);
void wemoCtrlPointVerifyTimeouts(int);
void wemoCtrlPointPrintCommands( void );
void* wemoCtrlPointCommandLoop( void* );
int wemoCtrlPointStart(char *ifname, print_string printFunctionPtr, state_update updateFunctionPtr);
int wemoCtrlPointStop( void );
int wemoCtrlPointProcessCommand( char *cmdline );

#ifdef __cplusplus
};

#endif //UPNP_TV_CTRLPT_H


#endif /* WEMO_CTRL_H_ */
