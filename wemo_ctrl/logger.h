/***************************************************************************
*
*
* logger.h
*
* Copyright (c) 2012-2014 Belkin International, Inc. and/or its affiliates.
* All rights reserved.
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
*
*
* THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT,
* INCIDENTAL, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
* RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
* NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH
* THE USE OR PERFORMANCE OF THIS SOFTWARE.
*
*
***************************************************************************/

#ifndef __PLUGIN_LOGGER_H
#define __PLUGIN_LOGGER_H

#include <syslog.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>

#define LOG_HIDE 111
#define SYSLOGLEVEL	    "SysLogLevel"
#define DEFAULT_LOG_LEVEL   LOG_ERR
extern int gloggerLevel;

/* Structured logger backend. */
void loggerLogMessage(int logLevel,
                      const char *file,
                      const char *function,
                      int line,
                      const char* format, ...)
__attribute__ ((format (printf, 5, 6)));

//Severity
typedef enum {
    CRITICAL=0,
    NORMAL
} severityLevel;

#define FILENAME ( strrchr(__FILE__, '/')?(strrchr(__FILE__, '/') + 1):__FILE__)
#define LOG_DEBUG_MSG(format, ...) \
do { \
    loggerLogMessage(LOG_DEBUG, FILENAME, __FUNCTION__, __LINE__, format, ## __VA_ARGS__); \
} while (0)
#define LOG_INFO_MSG(format, ...) \
do { \
    loggerLogMessage(LOG_INFO, FILENAME, __FUNCTION__, __LINE__, format, ## __VA_ARGS__); \
} while (0)
#define LOG_NOTICE_MSG(format, ...) \
do { \
    loggerLogMessage(LOG_NOTICE, FILENAME, __FUNCTION__, __LINE__, format, ## __VA_ARGS__); \
} while (0)
#define LOG_WARN_MSG(format, ...) \
do { \
    loggerLogMessage(LOG_WARNING, FILENAME, __FUNCTION__, __LINE__, format, ## __VA_ARGS__); \
} while (0)
#define LOG_ERROR_MSG(format, ...) \
do { \
    loggerLogMessage(LOG_ERR, FILENAME, __FUNCTION__, __LINE__, format, ## __VA_ARGS__); \
} while (0)
#define LOG_CRIT_MSG(format, ...) \
do { \
    loggerLogMessage(LOG_CRIT, FILENAME, __FUNCTION__, __LINE__, format, ## __VA_ARGS__); \
} while (0)

#define BUFFSIZE        (4*1024)
#define FILESIZE        (10*1024)
#define MAX_ROLL_OVER 2048
#define FILE_WRITE_TIMER 90
#define CONSOLE_LOGS_TIME   15*8 //15*8 mins
#define CONSOLE_LOGS_SIZE   10*SIZE_1024B  //10KB
#define PLUGIN_LOGS_FILE    "/tmp/PluginLogs"

#ifndef DEBUG_ENABLE
#define PVT_LOGS_ENABLER_FILE  "/tmp/Belkin_settings/enableLog"
#endif

extern pthread_mutex_t logMutex;

//Some functions

int loggerSetLogLevel (int lvl, int option);
int loggerGetLogLevel ();

void initLogger(void);
#ifndef DEBUG_ENABLE
void  onOffPvtUploadLogs(int);
#endif
void deInitLogger(void);

struct console_logs_info {
    int timePeriod;
    int fileSize;
    int timed;
};
typedef struct console_logs_info ConsoleLogsInfo;
#endif
