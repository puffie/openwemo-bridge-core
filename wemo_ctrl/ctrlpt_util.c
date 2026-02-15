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


#include "ctrlpt_util.h"
#include "logger.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>


#if !UPNP_HAVE_TOOLS
#	error "Need upnptools.h to compile samples ; try ./configure --enable-tools"
#endif


int initialize = 1;

/*! Function pointers to use for displaying formatted strings.
 * Set on Initialization of device. */
print_string gPrintFun = NULL;
state_update gStateUpdateFun = NULL;

/*! mutex to control displaying of events */
ithread_mutex_t display_mutex;

/*******************************************************************************
 * ctrlpt_util_Initialize
 *
 * Description:
 *     Initializes the sample util. Must be called before any sample util
 *     functions. May be called multiple times.
 *     But the initialization is done only once.
 *
 * Parameters:
 *   print_function - print function to use in ctrlpt_util_Print
 *
 ******************************************************************************/
int ctrlpt_util_Initialize(print_string print_function)
{
	if (initialize) {
		ithread_mutexattr_t attr;

		ithread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		ithread_mutex_init(&display_mutex, &attr);
		ithread_mutexattr_destroy(&attr);

		/* To shut up valgrind mutex warning. */
		ithread_mutex_lock(&display_mutex);
		gPrintFun = print_function;
		ithread_mutex_unlock(&display_mutex);

		initialize = 0;
	} else {
		LOG_DEBUG_MSG("***** ctrlpt_utilInitialize was called multiple times!");
		abort();
	}

	return UPNP_E_SUCCESS;
}

/*******************************************************************************
 * ctrlpt_util_RegisterUpdateFunction
 *
 * Description:
 *
 * Parameters:
 *
 ******************************************************************************/
int ctrlpt_util_RegisterUpdateFunction(state_update update_function)
{
	/* Intialize only once. */
	static int initialize = 1;

	if (initialize) {
		gStateUpdateFun = update_function;
		initialize = 0;
	}

	return UPNP_E_SUCCESS;
}

/*******************************************************************************
 * ctrlpt_util_Finish
 *
 * Description:
 *     Releases Resources held by sample util.
 *
 * Parameters:
 *
 ******************************************************************************/
int ctrlpt_util_Finish()
{
	ithread_mutex_destroy(&display_mutex);
	gPrintFun = NULL;
	initialize = 1;

	return UPNP_E_SUCCESS;
}

/*******************************************************************************
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
 ******************************************************************************/

char *ctrlpt_util_GetElementValue(IXML_Element *element)
{
	IXML_Node *child = ixmlNode_getFirstChild((IXML_Node *)element);
	char *temp = NULL;

	if (child != 0 && ixmlNode_getNodeType(child) == eTEXT_NODE) {
		temp = strdup(ixmlNode_getNodeValue(child));
	}

	return temp;
}

/*******************************************************************************
 * ctrlpt_util_GetFirstServiceList
 *
 * Description:
 *       Given a DOM node representing a UPnP Device Description Document,
 *       this routine parses the document and finds the first service list
 *       (i.e., the service list for the root device).  The service list
 *       is returned as a DOM node list.
 *
 * Parameters:
 *   node -- The DOM node from which to extract the service list
 *
 ******************************************************************************/
IXML_NodeList *ctrlpt_util_GetFirstServiceList(IXML_Document *doc)
{
	IXML_NodeList *ServiceList = NULL;
	IXML_NodeList *servlistnodelist = NULL;
	IXML_Node *servlistnode = NULL;

	servlistnodelist =
		ixmlDocument_getElementsByTagName( doc, "serviceList" );
	if (servlistnodelist && ixmlNodeList_length(servlistnodelist)) {
		/* we only care about the first service list, from the root
		 * device */
		servlistnode = ixmlNodeList_item(servlistnodelist, 0);

		/* create as list of DOM nodes */
		ServiceList = ixmlElement_getElementsByTagName(
			(IXML_Element *)servlistnode, "service");
	}
	if (servlistnodelist) {
		ixmlNodeList_free(servlistnodelist);
	}

	return ServiceList;
}

/*
 * Obtain the service list
 *    n == 0 the first
 *    n == 1 the next in the device list, etc..
 *
 */
IXML_NodeList *ctrlpt_util_GetNthServiceList(IXML_Document *doc , int n)
{
	IXML_NodeList *ServiceList = NULL;
	IXML_NodeList *servlistnodelist = NULL;
	IXML_Node *servlistnode = NULL;

	/*
	 *  ixmlDocument_getElementsByTagName()
	 *  Returns a NodeList of all Elements that match the given
	 *  tag name in the order in which they were encountered in a preorder
	 *  traversal of the Document tree.
	 *
	 *  return (NodeList*) A pointer to a NodeList containing the
	 *                      matching items or NULL on an error.
	 */
    //	LOG_DEBUG_MSG("ctrlpt_util_GetNthServiceList called : n = %d", n);
	servlistnodelist =
		ixmlDocument_getElementsByTagName(doc, "serviceList");
	if (servlistnodelist &&
	    ixmlNodeList_length(servlistnodelist) &&
	    n < ixmlNodeList_length(servlistnodelist)) {
		/* For the first service list (from the root device),
		 * we pass 0 */
		/*servlistnode = ixmlNodeList_item( servlistnodelist, 0 );*/

		/* Retrieves a Node from a NodeList} specified by a
		 *  numerical index.
		 *
		 *  return (Node*) A pointer to a Node or NULL if there was an
		 *                  error.
		 */
		servlistnode = ixmlNodeList_item(servlistnodelist, n);

		assert(servlistnode != 0);

		/* create as list of DOM nodes */
		ServiceList = ixmlElement_getElementsByTagName(
			(IXML_Element *)servlistnode, "service");
	}

	if (servlistnodelist) {
		ixmlNodeList_free(servlistnodelist);
	}

	return ServiceList;
}

/*******************************************************************************
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
 ******************************************************************************/
char *ctrlpt_util_GetFirstDocumentItem(
	IXML_Document *doc, const char *item)
{
	IXML_NodeList *nodeList = NULL;
	IXML_Node *textNode = NULL;
	IXML_Node *tmpNode = NULL;
	char *ret = NULL;

	nodeList = ixmlDocument_getElementsByTagName(doc, (char *)item);
	if (nodeList) {
		tmpNode = ixmlNodeList_item(nodeList, 0);
		if (tmpNode) {
			textNode = ixmlNode_getFirstChild(tmpNode);
			if (!textNode) {
				ret = strdup("");
				goto epilogue;
			}
			if (!ixmlNode_getNodeValue(textNode)) {
				LOG_ERROR_MSG("ixmlNode_getNodeValue returned NULL");
				ret = strdup("");
				goto epilogue;
			} else {
				ret = strdup(ixmlNode_getNodeValue(textNode));
			}
		} else {
			LOG_ERROR_MSG("ixmlNode_getFirstChild(tmpNode) returned NULL");
			goto epilogue;
		}
	}

epilogue:
	if (nodeList) {
		ixmlNodeList_free(nodeList);
	}

	return ret;
}

/*******************************************************************************
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
 ******************************************************************************/
char *ctrlpt_util_GetFirstElementItem(
	IXML_Element *element, const char *item)
{
	IXML_NodeList *nodeList = NULL;
	IXML_Node *textNode = NULL;
	IXML_Node *tmpNode = NULL;
	char *ret = NULL;

	nodeList = ixmlElement_getElementsByTagName(element, (char *)item);
	if (nodeList == NULL) {
		LOG_ERROR_MSG("Error finding %s in XML Node", item);

		return NULL;
	}
	tmpNode = ixmlNodeList_item(nodeList, 0);
	if (!tmpNode) {
		LOG_ERROR_MSG("Error finding %s value in XML Node", item);
		ixmlNodeList_free(nodeList);

		return NULL;
	}
	textNode = ixmlNode_getFirstChild(tmpNode);
	ret = strdup(ixmlNode_getNodeValue(textNode));
	if (!ret) {
		LOG_ERROR_MSG("Error allocating memory for %s in XML Node", item);
		ixmlNodeList_free(nodeList);

		return NULL;
	}
	ixmlNodeList_free(nodeList);

	return ret;
}

/*******************************************************************************
 * ctrlpt_util_PrintEventType
 *
 * Description:
 *       Prints a callback event type as a string.
 *
 * Parameters:
 *   S -- The callback event
 *
 ******************************************************************************/
void ctrlpt_util_PrintEventType(Upnp_EventType S)
{
	switch (S) {
	/* Discovery */
	case UPNP_DISCOVERY_ADVERTISEMENT_ALIVE:
        LOG_DEBUG_MSG("UPNP_DISCOVERY_ADVERTISEMENT_ALIVE");
		break;
	case UPNP_DISCOVERY_ADVERTISEMENT_BYEBYE:
		LOG_DEBUG_MSG("UPNP_DISCOVERY_ADVERTISEMENT_BYEBYE");
		break;
	case UPNP_DISCOVERY_SEARCH_RESULT:
        LOG_DEBUG_MSG("UPNP_DISCOVERY_SEARCH_RESULT");
		break;
	case UPNP_DISCOVERY_SEARCH_TIMEOUT:
		LOG_DEBUG_MSG("UPNP_DISCOVERY_SEARCH_TIMEOUT");
		break;
	/* SOAP */
	case UPNP_CONTROL_ACTION_REQUEST:
		LOG_DEBUG_MSG("UPNP_CONTROL_ACTION_REQUEST");
		break;
	case UPNP_CONTROL_ACTION_COMPLETE:
		LOG_DEBUG_MSG("UPNP_CONTROL_ACTION_COMPLETE");
		break;
	case UPNP_CONTROL_GET_VAR_REQUEST:
		LOG_DEBUG_MSG("UPNP_CONTROL_GET_VAR_REQUEST");
		break;
	case UPNP_CONTROL_GET_VAR_COMPLETE:
		LOG_DEBUG_MSG("UPNP_CONTROL_GET_VAR_COMPLETE");
		break;
	/* GENA */
	case UPNP_EVENT_SUBSCRIPTION_REQUEST:
		LOG_DEBUG_MSG("UPNP_EVENT_SUBSCRIPTION_REQUEST");
		break;
	case UPNP_EVENT_RECEIVED:
		LOG_DEBUG_MSG("UPNP_EVENT_RECEIVED");
		break;
	case UPNP_EVENT_RENEWAL_COMPLETE:
		LOG_DEBUG_MSG("UPNP_EVENT_RENEWAL_COMPLETE");
		break;
	case UPNP_EVENT_SUBSCRIBE_COMPLETE:
		LOG_DEBUG_MSG("UPNP_EVENT_SUBSCRIBE_COMPLETE");
		break;
	case UPNP_EVENT_UNSUBSCRIBE_COMPLETE:
		LOG_DEBUG_MSG("UPNP_EVENT_UNSUBSCRIBE_COMPLETE");
		break;
	case UPNP_EVENT_AUTORENEWAL_FAILED:
		LOG_DEBUG_MSG("UPNP_EVENT_AUTORENEWAL_FAILED");
		break;
	case UPNP_EVENT_SUBSCRIPTION_EXPIRED:
		LOG_DEBUG_MSG("UPNP_EVENT_SUBSCRIPTION_EXPIRED");
		break;
	}
}

/*******************************************************************************
 * ctrlpt_util_PrintEvent
 *
 * Description:
 *       Prints callback event structure details.
 *
 * Parameters:
 *   EventType -- The type of callback event
 *   Event -- The callback event structure
 *
 ******************************************************************************/
int ctrlpt_util_PrintEvent(Upnp_EventType EventType, void *Event)
{
	ithread_mutex_lock(&display_mutex);

	ctrlpt_util_PrintEventType(EventType);
	switch (EventType) {
	/* SSDP */
	case UPNP_DISCOVERY_ADVERTISEMENT_ALIVE:
	case UPNP_DISCOVERY_ADVERTISEMENT_BYEBYE:
	case UPNP_DISCOVERY_SEARCH_RESULT: {
		UpnpDiscovery *d_event = (UpnpDiscovery *)Event;
		LOG_DEBUG_MSG("ErrCode     =  %d\n"
		"Expires     =  %d\n"
		"DeviceId    =  %s\n"
		"DeviceType  =  %s\n"
		"ServiceType =  %s\n"
		"ServiceVer  =  %s\n"
		"Location    =  %s\n"
		"OS          =  %s\n"
		"Date        =  %s\n"
		"Ext         =  %s\n",
		UpnpDiscovery_get_ErrCode(d_event),
		UpnpDiscovery_get_Expires(d_event),
		UpnpDiscovery_get_DeviceID_cstr(d_event),
		UpnpDiscovery_get_DeviceType_cstr(d_event),
		UpnpDiscovery_get_ServiceType_cstr(d_event),
		UpnpDiscovery_get_ServiceVer_cstr(d_event),
		UpnpDiscovery_get_Location_cstr(d_event),
		UpnpDiscovery_get_Os_cstr(d_event),
		UpnpDiscovery_get_Date_cstr(d_event),
		UpnpDiscovery_get_Ext_cstr(d_event));
		break;
	}
	case UPNP_DISCOVERY_SEARCH_TIMEOUT:
		/* Nothing to print out here */
		break;
	/* SOAP */
	case UPNP_CONTROL_ACTION_REQUEST: {
		UpnpActionRequest *a_event = (UpnpActionRequest *)Event;
		IXML_Document *actionRequestDoc = NULL;
		IXML_Document *actionResultDoc = NULL;
		char *xmlbuff = NULL;

		LOG_DEBUG_MSG("ErrCode     =  %d\n"
			"ErrStr      =  %s\n"
			"ActionName  =  %s\n"
			"UDN         =  %s\n"
			"ServiceID   =  %s\n",
			UpnpActionRequest_get_ErrCode(a_event),
			UpnpActionRequest_get_ErrStr_cstr(a_event),
			UpnpActionRequest_get_ActionName_cstr(a_event),
			UpnpActionRequest_get_DevUDN_cstr(a_event),
			UpnpActionRequest_get_ServiceID_cstr(a_event));
		actionRequestDoc = UpnpActionRequest_get_ActionRequest(a_event);
		if (actionRequestDoc) {
			xmlbuff = ixmlPrintNode((IXML_Node *)actionRequestDoc);
			if (xmlbuff) {
				LOG_DEBUG_MSG("ActRequest  =  %s", xmlbuff);
				ixmlFreeDOMString(xmlbuff);
			}
			xmlbuff = NULL;
		} else {
			LOG_DEBUG_MSG("ActRequest  =  (null)");
		}
		actionResultDoc = UpnpActionRequest_get_ActionResult(a_event);
		if (actionResultDoc) {
			xmlbuff = ixmlPrintNode((IXML_Node *)actionResultDoc);
			if (xmlbuff) {
				LOG_DEBUG_MSG("ActResult   =  %s", xmlbuff);
				ixmlFreeDOMString(xmlbuff);
			}
			xmlbuff = NULL;
		} else {
			LOG_DEBUG_MSG("ActResult   =  (null)");
		}
		break;
	}
	case UPNP_CONTROL_ACTION_COMPLETE: {
		UpnpActionComplete *a_event = (UpnpActionComplete *)Event;
		char *xmlbuff = NULL;
		int errCode = UpnpActionComplete_get_ErrCode(a_event);
		const char *ctrlURL = UpnpActionComplete_get_CtrlUrl_cstr(a_event);
		IXML_Document *actionRequest = UpnpActionComplete_get_ActionRequest(a_event);
		IXML_Document *actionResult = UpnpActionComplete_get_ActionResult(a_event);

		LOG_DEBUG_MSG("ErrCode     =  %d\n"
			"CtrlUrl     =  %s\n",
			errCode, ctrlURL);
		if (actionRequest) {
			xmlbuff = ixmlPrintNode((IXML_Node *)actionRequest);
			if (xmlbuff) {
				LOG_DEBUG_MSG("ActRequest  =  %s\n", xmlbuff);
				ixmlFreeDOMString(xmlbuff);
			}
			xmlbuff = NULL;
		} else {
			LOG_DEBUG_MSG("ActRequest  =  (null)\n");
		}
		if (actionResult) {
			xmlbuff = ixmlPrintNode((IXML_Node *)actionResult);
			if (xmlbuff) {
				LOG_DEBUG_MSG("ActResult   =  %s\n", xmlbuff);
				ixmlFreeDOMString(xmlbuff);
			}
			xmlbuff = NULL;
		} else {
			LOG_DEBUG_MSG("ActResult   =  (null)\n");
		}
		break;
	}
	case UPNP_CONTROL_GET_VAR_REQUEST: {
		UpnpStateVarRequest *sv_event = (UpnpStateVarRequest *)Event;

		LOG_DEBUG_MSG("ErrCode     =  %d\n"
			"ErrStr      =  %s\n"
			"UDN         =  %s\n"
			"ServiceID   =  %s\n"
			"StateVarName=  %s\n"
			"CurrentVal  =  %s\n",
			UpnpStateVarRequest_get_ErrCode(sv_event),
			UpnpStateVarRequest_get_ErrStr_cstr(sv_event),
			UpnpStateVarRequest_get_DevUDN_cstr(sv_event),
			UpnpStateVarRequest_get_ServiceID_cstr(sv_event),
			UpnpStateVarRequest_get_StateVarName_cstr(sv_event),
			UpnpStateVarRequest_get_CurrentVal(sv_event));
		break;
	}
	case UPNP_CONTROL_GET_VAR_COMPLETE: {
		UpnpStateVarComplete *sv_event = (UpnpStateVarComplete *)Event;

		LOG_DEBUG_MSG("ErrCode     =  %d\n"
			"CtrlUrl     =  %s\n"
			"StateVarName=  %s\n"
			"CurrentVal  =  %s\n",
			UpnpStateVarComplete_get_ErrCode(sv_event),
			UpnpStateVarComplete_get_CtrlUrl_cstr(sv_event),
			UpnpStateVarComplete_get_StateVarName_cstr(sv_event),
			UpnpStateVarComplete_get_CurrentVal(sv_event));
		break;
	}

	/* GENA */
	case UPNP_EVENT_SUBSCRIPTION_REQUEST: {
		UpnpSubscriptionRequest *sr_event = (UpnpSubscriptionRequest *)Event;

		LOG_DEBUG_MSG("ServiceID   =  %s\n"
			"UDN         =  %s\n"
			"SID         =  %s\n",
			UpnpSubscriptionRequest_get_ServiceId_cstr(sr_event),
			UpnpSubscriptionRequest_get_UDN_cstr(sr_event),
			UpnpSubscriptionRequest_get_SID_cstr(sr_event));
		break;
	}
	case UPNP_EVENT_RECEIVED: {
		UpnpEvent *e_event = (UpnpEvent *)Event;
		char *xmlbuff = NULL;

		xmlbuff = ixmlPrintNode(
			(IXML_Node *)UpnpEvent_get_ChangedVariables(e_event));
		LOG_DEBUG_MSG("SID         =  %s\n"
			"EventKey    =  %d\n"
			"ChangedVars =  %s\n",
			UpnpEvent_get_SID_cstr(e_event),
			UpnpEvent_get_EventKey(e_event),
			xmlbuff);
		ixmlFreeDOMString(xmlbuff);
		break;
	}
	case UPNP_EVENT_RENEWAL_COMPLETE: {
		UpnpEventSubscribe *es_event = (UpnpEventSubscribe *)Event;

		LOG_DEBUG_MSG("SID         =  %s\n"
			"ErrCode     =  %d\n"
			"TimeOut     =  %d\n",
			UpnpEventSubscribe_get_SID_cstr(es_event),
			UpnpEventSubscribe_get_ErrCode(es_event),
			UpnpEventSubscribe_get_TimeOut(es_event));
		break;
	}
	case UPNP_EVENT_SUBSCRIBE_COMPLETE:
	case UPNP_EVENT_UNSUBSCRIBE_COMPLETE: {
		UpnpEventSubscribe *es_event = (UpnpEventSubscribe *)Event;

		LOG_DEBUG_MSG("SID         =  %s\n"
			"ErrCode     =  %d\n"
			"PublisherURL=  %s\n"
			"TimeOut     =  %d\n",
			UpnpEventSubscribe_get_SID_cstr(es_event),
			UpnpEventSubscribe_get_ErrCode(es_event),
			UpnpEventSubscribe_get_PublisherUrl_cstr(es_event),
			UpnpEventSubscribe_get_TimeOut(es_event));
		break;
	}
	case UPNP_EVENT_AUTORENEWAL_FAILED:
	case UPNP_EVENT_SUBSCRIPTION_EXPIRED: {
		UpnpEventSubscribe *es_event = (UpnpEventSubscribe *)Event;

		LOG_DEBUG_MSG("SID         =  %s\n"
			"ErrCode     =  %d\n"
			"PublisherURL=  %s\n"
			"TimeOut     =  %d\n",
			UpnpEventSubscribe_get_SID_cstr(es_event),
			UpnpEventSubscribe_get_ErrCode(es_event),
			UpnpEventSubscribe_get_PublisherUrl_cstr(es_event),
			UpnpEventSubscribe_get_TimeOut(es_event));
		break;
	}
	}

	ithread_mutex_unlock(&display_mutex);

	return 0;
}

/*******************************************************************************
 * ctrlpt_util_FindAndParseService
 *
 * Description:
 *       This routine finds the first occurance of a service in a DOM representation
 *       of a description document and parses it.
 *
 * Parameters:
 *   DescDoc -- The DOM description document
 *   location -- The location of the description document
 *   serviceSearchType -- The type of service to search for
 *   serviceId -- OUT -- The service ID
 *   eventURL -- OUT -- The event URL for the service
 *   controlURL -- OUT -- The control URL for the service
 *
 ******************************************************************************/
int ctrlpt_util_FindAndParseService(
	IXML_Document *DescDoc, const char *location, char *serviceType,
	char **serviceId, char **eventURL, char **controlURL)
{
	int i;
	int length;
	int found = 0;
	int ret;
	int sindex = 0;
	char *tempServiceType = NULL;
	char *baseURL = NULL;
	const char *base = NULL;
	char *relcontrolURL = NULL;
	char *releventURL = NULL;
	IXML_NodeList *serviceList = NULL;
	IXML_Element *service = NULL;

	baseURL = ctrlpt_util_GetFirstDocumentItem(DescDoc, "URLBase");
	if (baseURL) {
		base = baseURL;
	} else {
		base = location;
	}

	/* Top level */
	for (sindex = 0;
	     (serviceList = ctrlpt_util_GetNthServiceList(DescDoc , sindex)) != NULL;
	     sindex ++) {
		tempServiceType = NULL;
		relcontrolURL = NULL;
		releventURL = NULL;
		service = NULL;

		/* serviceList = ctrlpt_util_GetFirstServiceList( DescDoc ); */
		length = ixmlNodeList_length(serviceList);
		for (i = 0; i < length; i++) {
			service = (IXML_Element *)ixmlNodeList_item(serviceList, i);
			tempServiceType =
				ctrlpt_util_GetFirstElementItem(
					(IXML_Element *)service, "serviceType");
			if (strcmp(tempServiceType, serviceType) == 0) {
                // LOG_DEBUG_MSG("Found service: %s\n", serviceType);
				*serviceId =
					ctrlpt_util_GetFirstElementItem(service, "serviceId");
                // LOG_DEBUG_MSG("serviceId: %s\n", *serviceId);
				relcontrolURL =
					ctrlpt_util_GetFirstElementItem(service, "controlURL");
				releventURL =
					ctrlpt_util_GetFirstElementItem(service, "eventSubURL");
				*controlURL =
					malloc(strlen(base) + strlen(relcontrolURL)+1);
				if (*controlURL) {
					ret = UpnpResolveURL(base, relcontrolURL, *controlURL);
					if (ret != UPNP_E_SUCCESS) {
						LOG_ERROR_MSG("Error generating controlURL from %s + %s",
							base, relcontrolURL);
					}
				}
				*eventURL = malloc(strlen(base) + strlen(releventURL)+1);
				if (*eventURL) {
					ret = UpnpResolveURL(base, releventURL, *eventURL);
					if (ret != UPNP_E_SUCCESS) {
						LOG_ERROR_MSG("Error generating eventURL from %s + %s",
							base, releventURL);
					}
				}
				free(relcontrolURL);
				free(releventURL);
				relcontrolURL = NULL;
				releventURL = NULL;
				found = 1;
				break;
			}
			free(tempServiceType);
			tempServiceType = NULL;
		}
		free(tempServiceType);
		tempServiceType = NULL;
		if (serviceList) {
			ixmlNodeList_free(serviceList);
		}
		serviceList = NULL;
	}
	free(baseURL);

	return found;
}

/*******************************************************************************
 * ctrlpt_util_StateUpdate
 *
 * Description:
 *
 * Parameters:
 *
 ******************************************************************************/
void ctrlpt_util_StateUpdate(const char *varName, const char *varValue,
	const char *UDN, eventType type)
{
	/* TBD: Add mutex here? */
	if (gStateUpdateFun) {
		gStateUpdateFun(varName, varValue, UDN, type);
	}
}

int ctrlpt_util_retrieve_ip_from_url(const char *url, char *ipaddr)
{
    if (url == NULL)
        return 0;
    if (ipaddr == NULL)
        return 0;

    int port = 80;
    char page[100];

    if (sscanf(url, "http://%99[^:]:%99d/%99[^\n]", ipaddr, &port, page) != 3) {
        return 0;
    }
    else {
        return 1;
	}
}
