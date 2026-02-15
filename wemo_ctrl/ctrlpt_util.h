/*******************************************************************************
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
 ******************************************************************************/

#ifndef CTRLPT_UTIL_H_
#define CTRLPT_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


#include "ithread.h"
#include "ixml.h" /* for IXML_Document, IXML_Element */
#include "upnp.h" /* for Upnp_EventType */
#include "upnptools.h"


#include <stdlib.h>
#include <string.h>


/* mutex to control displaying of events */
extern ithread_mutex_t display_mutex;


typedef enum {
	STATE_UPDATE = 0,
	DEVICE_ADDED = 1,
	DEVICE_REMOVED = 2,
	GET_VAR_COMPLETE = 3
} eventType;


/********************************************************************************
 * ctrlpt_util_GetElementValue
 *
 * Description:
 *       Given a DOM node such as <Channel>11</Channel>, this routine
 *       extracts the value (e.g., 11) from the node and returns it as
 *       a string. The string must be freed by the caller using
 *       free.
 *
 * Parameters:
 *   node -- The DOM node from which to extract the value
 *
 ********************************************************************************/
char *ctrlpt_util_GetElementValue(IXML_Element *element);

/********************************************************************************
 * ctrlpt_util_GetFirstServiceList
 *
 * Description:
 *       Given a DOM node representing a UPnP Device Description Document,
 *       this routine parses the document and finds the first service list
 *       (i.e., the service list for the root device).  The service list
 *       is returned as a DOM node list. The NodeList must be freed using
 *       NodeList_free.
 *
 * Parameters:
 *   node -- The DOM node from which to extract the service list
 *
 ********************************************************************************/

IXML_NodeList *ctrlpt_util_GetFirstServiceList(IXML_Document *doc);


/********************************************************************************
 * ctrlpt_util_GetFirstDocumentItem
 *
 * Description:
 *       Given a document node, this routine searches for the first element
 *       named by the input string item, and returns its value as a string.
 *       String must be freed by caller using free.
 * Parameters:
 *   doc -- The DOM document from which to extract the value
 *   item -- The item to search for
 *
 ********************************************************************************/
char *ctrlpt_util_GetFirstDocumentItem(IXML_Document *doc, const char *item);



/********************************************************************************
 * ctrlpt_util_GetFirstElementItem
 *
 * Description:
 *       Given a DOM element, this routine searches for the first element
 *       named by the input string item, and returns its value as a string.
 *       The string must be freed using free.
 * Parameters:
 *   node -- The DOM element from which to extract the value
 *   item -- The item to search for
 *
 ********************************************************************************/
char *ctrlpt_util_GetFirstElementItem(IXML_Element *element, const char *item);

/********************************************************************************
 * ctrlpt_util_PrintEventType
 *
 * Description:
 *       Prints a callback event type as a string.
 *
 * Parameters:
 *   S -- The callback event
 *
 ********************************************************************************/
void ctrlpt_util_PrintEventType(Upnp_EventType S);

/********************************************************************************
 * ctrlpt_util_PrintEvent
 *
 * Description:
 *       Prints callback event structure details.
 *
 * Parameters:
 *   EventType -- The type of callback event
 *   Event -- The callback event structure
 *
 ********************************************************************************/
int ctrlpt_util_PrintEvent(Upnp_EventType EventType,
			  void *Event);

/********************************************************************************
 * ctrlpt_util_FindAndParseService
 *
 * Description:
 *       This routine finds the first occurance of a service in a DOM representation
 *       of a description document and parses it.  Note that this function currently
 *       assumes that the eventURL and controlURL values in the service definitions
 *       are full URLs.  Relative URLs are not handled here.
 *
 * Parameters:
 *   DescDoc -- The DOM description document
 *   location -- The location of the description document
 *   serviceSearchType -- The type of service to search for
 *   serviceId -- OUT -- The service ID
 *   eventURL -- OUT -- The event URL for the service
 *   controlURL -- OUT -- The control URL for the service
 *
 ********************************************************************************/
int ctrlpt_util_FindAndParseService (
	IXML_Document *DescDoc,
	const char* location,
	char *serviceType,
	char **serviceId,
	char **eventURL,
	char **controlURL);


/********************************************************************************
 * print_string
 *
 * Description:
 *       Prototype for displaying strings. All printing done by the device,
 *       control point, and sample util, ultimately use this to display strings
 *       to the user.
 *
 * Parameters:
 *   const char * string.
 *
 ********************************************************************************/
typedef void (*print_string)(const char *string);

//global print function used by sample util
extern print_string gPrintFun;

/********************************************************************************
 * state_update
 *
 * Description:
 *     Prototype for passing back state changes
 *
 * Parameters:
 *   const char * varName
 *   const char * varValue
 *   const char * UDN
 *   int          newDevice
 ********************************************************************************/
typedef void (*state_update)(
	const char *varName,
	const char *varValue,
	const char *UDN,
	eventType type);

//global state update function used by smaple util
extern state_update gStateUpdateFun;

/********************************************************************************
 * ctrlpt_util_Initialize
 *
 * Description:
 *     Initializes the sample util. Must be called before any sample util
 *     functions. May be called multiple times.
 *
 * Parameters:
 *   print_function - print function to use in ctrlpt_util_Print
 *
 ********************************************************************************/
int ctrlpt_util_Initialize(print_string print_function);

/********************************************************************************
 * ctrlpt_util_Finish
 *
 * Description:
 *     Releases Resources held by sample util.
 *
 * Parameters:
 *
 ********************************************************************************/
int ctrlpt_util_Finish();

/********************************************************************************
 * ctrlpt_util_RegisterUpdateFunction
 *
 * Description:
 *
 * Parameters:
 *
 ********************************************************************************/
int ctrlpt_util_RegisterUpdateFunction(state_update update_function);

/********************************************************************************
 * ctrlpt_util_StateUpdate
 *
 * Description:
 *
 * Parameters:
 *
 ********************************************************************************/
void ctrlpt_util_StateUpdate(
	const char *varName,
	const char *varValue,
	const char *UDN,
	eventType type);

int ctrlpt_util_retrieve_ip_from_url(const char *url, char *ipaddr);
#ifdef __cplusplus
};
#endif /* __cplusplus */


#ifdef WIN32
	#define snprintf	_snprintf
	#define strcasecmp	stricmp
#endif

#endif /* CTRLPT_UTIL_H_ */
