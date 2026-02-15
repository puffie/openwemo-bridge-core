/*
 * db_utils.h
 *
 *  Created on: May 5, 2017
 *      Author: harry
 */

#ifndef DB_UTILS_H_
#define DB_UTILS_H_

#include <sqlite3.h>

#define DB_SUCCESS	0
#define DB_ERROR	(-1)
#define DB_NOT_OPEN	2
#define MAX_NAME_SIZE	512		//MAX Char 155, Localization Size, One Chinese = 155*3=465

typedef struct {
    char *ParamName,*ParamDataType;
} TableDetails;

typedef struct {
    char ColName[256];
    char ColValue[256];
} ColDetails;

int InitDB(const char *ps8DBURL,sqlite3 **db);
void CloseDB(sqlite3 *db);
int ExecuteStatement(char *ps8Statement,sqlite3 **db);
void DeleteDB(char *ps8DBURL);
int WeMoDBCreateTable(sqlite3 **DBHandle,char *TableName,TableDetails TableParams[],int PrimaryKeyEnable,int ParametersCount);
int WeMoDBUpdateTable(sqlite3 **DBHandle,char *TableName,ColDetails ColParams[],int ParametersCount,char *Condition);
int WeMoDBInsertInTable(sqlite3 **DBHandle,char *TableName,ColDetails ColParams[],int ParametersCount);
int WeMoDBDropTable(sqlite3 **DBHandle,char *TableName);
int WeMoDBGetTableData(sqlite3 **DBHandle,char *s8Query,char ***s8Result,int *s32NumofRows, int *s32NumofCols);
void WeMoDBTableFreeResult(char ***s8Result,int *s32NumofRows,int *s32NumofCols);
int WeMoDBDeleteEntry(sqlite3 **DBHandle,char *TableName,char *Condition);
int WeMoDBDeleteAllEntries(sqlite3 **DBHandle,char *TableName);

#endif /* DB_UTILS_H_ */
