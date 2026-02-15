/***************************************************************************
*
*
* logger.c
*
* Created by Belkin International, Software Engineering on XX/XX/XX.
* Copyright (c) 2012-2013 Belkin International, Inc. and/or its affiliates. All rights reserved.
*
* Belkin International, Inc. retains all right, title and interest (including all
* intellectual property rights) in and to this computer program, which is
* protected by applicable intellectual property laws.  Unless you have obtained
* a separate written license from Belkin International, Inc., you are not authorized
* to utilize all or a part of this computer program for any purpose (including
* reproduction, distribution, modification, and compilation into object code)
* and you must immediately destroy or return to Belkin International, Inc
* all copies of this computer program.  If you are licensed by Belkin International, Inc., your
* rights to utilize this computer program are limited by the terms of that license.
*
* To obtain a license, please contact Belkin International, Inc.
*
* This computer program contains trade secrets owned by Belkin International, Inc.
* and, unless unauthorized by Belkin International, Inc. in writing, you agree to
* maintain the confidentiality of this computer program and related information
* and to not disclose this computer program and related information to any
* other person or entity.
*
* THIS COMPUTER PROGRAM IS PROVIDED AS IS WITHOUT ANY WARRANTIES, AND BELKIN INTERNATIONAL, INC.
* EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING THE WARRANTIES OF
* MERCHANTIBILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT.
*
*
***************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <malloc.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "logger.h"

extern char *program_invocation_short_name;

pthread_mutex_t logMutex;

int gloggerOptions = 33;
int gloggerLevel = -1;
static int log_mode_quiet = 0;
static int log_format_json = 0;

char g_buffTimeZoneOffset[128] = {0};
int gTimeZoneUpdated = 0;

int lenIndex;
int logCounter;

int loggerSetLogLevel (int lvl, int option)
{
    gloggerLevel = lvl;
    gloggerOptions = option;
    return 0;
}

int loggerGetLogLevel ()
{
    return gloggerLevel;
}

int get_file_size (const char * file_name)
{
    struct stat sb;
    if (stat (file_name, &sb) != 0) {
        return -1;
    }
    return sb.st_size;
}

/*
 *  Function to set g_buffTimeZoneOffset value
 *
 ******************************************/

int setTimeZoneOffset (void)
{

    int DstVal=-2;
    float localTZ=0.0;

    char bufTemp[32];
    char bufTime[32];
    char *pch = NULL;
    int tz = 0;
    int tz1 = 0;

    char *LocalTimeZone = NULL;
    char *LastDstValue = NULL;
    (void)LocalTimeZone;
    (void)LastDstValue;

    if(DstVal == 0)
        localTZ = localTZ + 1.0;

    gTimeZoneUpdated = 0;

    memset(g_buffTimeZoneOffset, 0x00, sizeof(g_buffTimeZoneOffset));
    memset(bufTemp, 0x0, 32);
    memset(bufTime, 0x0, 32);

    snprintf(bufTemp, sizeof(bufTemp), "%f|", localTZ);

    tz = atoi(bufTemp);
    pch = strstr (bufTemp,".");
    strncpy (bufTime,pch+1,2);
    tz1 = atoi(bufTime)*60/100;

    if (bufTemp[0x00] == '-')
        snprintf(g_buffTimeZoneOffset, sizeof(g_buffTimeZoneOffset), "%03d%02d",tz,tz1);
    else
        snprintf(g_buffTimeZoneOffset, sizeof(g_buffTimeZoneOffset), "+%02d%02d",tz,tz1);

    return 0;
}

static const char *level_to_text(int level)
{
    switch (level) {
    case LOG_DEBUG: return "DEBUG";
    case LOG_INFO: return "INFO";
    case LOG_NOTICE: return "NOTICE";
    case LOG_WARNING: return "WARN";
    case LOG_ERR: return "ERROR";
    case LOG_CRIT: return "CRIT";
    case LOG_ALERT: return "ALERT";
    case LOG_EMERG: return "EMERG";
    default: return "LOG";
    }
}

static void json_escape(const char *src, char *dst, size_t dst_len)
{
    size_t i = 0;
    size_t j = 0;
    if (dst_len == 0) {
        return;
    }
    while (src != NULL && src[i] != '\0' && j + 2 < dst_len) {
        char c = src[i++];
        if (c == '"' || c == '\\') {
            if (j + 2 >= dst_len) {
                break;
            }
            dst[j++] = '\\';
            dst[j++] = c;
        } else if (c == '\n') {
            dst[j++] = '\\';
            dst[j++] = 'n';
        } else if ((unsigned char)c < 0x20) {
            continue;
        } else {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
}

void loggerLogMessage(int logLevel,
                      const char *file,
                      const char *function,
                      int line,
                      const char *format, ...)
{
    char message[1024];
    char output[2048];
    char msg_json[900];
    char file_json[128];
    char func_json[128];
    va_list args;
    struct timeval tv;
    struct tm *now;
    const char *level_text;
    const char *prog = program_invocation_short_name ? program_invocation_short_name : "wemo";

    if (gloggerLevel < logLevel) {
        return;
    }
    if (log_mode_quiet && logLevel > LOG_WARNING) {
        return;
    }

    memset(message, 0x0, sizeof(message));
    memset(output, 0x0, sizeof(output));

    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    gettimeofday(&tv, NULL);
    now = localtime(&tv.tv_sec);
    level_text = level_to_text(logLevel);

    if (log_format_json) {
        json_escape(message, msg_json, sizeof(msg_json));
        json_escape(file ? file : "", file_json, sizeof(file_json));
        json_escape(function ? function : "", func_json, sizeof(func_json));
        snprintf(output,
                 sizeof(output),
                 "{\"ts\":\"%04d-%02d-%02dT%02d:%02d:%02d.%06d\",\"level\":\"%s\",\"prog\":\"%s\",\"file\":\"%.120s\",\"line\":%d,\"func\":\"%.120s\",\"msg\":\"%.880s\"}",
                 now->tm_year + 1900, now->tm_mon + 1, now->tm_mday,
                 now->tm_hour, now->tm_min, now->tm_sec, (int)tv.tv_usec,
                 level_text, prog, file_json, line, func_json, msg_json);
    } else {
        snprintf(output,
                 sizeof(output),
                 "%04d-%02d-%02d %02d:%02d:%02d.%06d %-5s %s %s:%d %s: %s",
                 now->tm_year + 1900, now->tm_mon + 1, now->tm_mday,
                 now->tm_hour, now->tm_min, now->tm_sec, (int)tv.tv_usec,
                 level_text, prog, file, line, function, message);
    }
    syslog(logLevel, "%s", output);
}

void setLogLevel(void)
{
    const char *loggerlevel = getenv("WEMO_LOG_LEVEL");
    if (loggerlevel && loggerlevel[0] != '\0') {
        gloggerLevel = atoi(loggerlevel);
    } else {
        gloggerLevel = LOG_ERR;
    }
    if (gloggerLevel < LOG_EMERG) {
        gloggerLevel = LOG_EMERG;
    } else if (gloggerLevel > LOG_DEBUG) {
        gloggerLevel = LOG_DEBUG;
    }
    setlogmask(LOG_UPTO(gloggerLevel));
}

void initLogger(void)
{
    const char *log_mode = getenv("WEMO_LOG_MODE");
    const char *log_format = getenv("WEMO_LOG_FORMAT");
    if (log_mode && strcasecmp(log_mode, "quiet") == 0) {
        log_mode_quiet = 1;
    }
    if (log_format && strcasecmp(log_format, "json") == 0) {
        log_format_json = 1;
    }
    openlog(NULL, LOG_NDELAY | LOG_PERROR, LOG_USER);

    setLogLevel();
    LOG_INFO_MSG("logger initialized level=%d quiet=%d json=%d", gloggerLevel, log_mode_quiet, log_format_json);
}

void deInitLogger(void)
{
    /*Close syslog*/
    closelog();
}
