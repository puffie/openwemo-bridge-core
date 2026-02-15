#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "db_utils.h"
#include "ctrlpt_util.h"
#include "logger.h"

static int DBCallback(void *NotUsed, int argc, char **argv, char **azColName);
static void ApplyDBPragmas(sqlite3 *db);
int InitDB(const char *ps8DBURL,sqlite3 **db)
{
    int s32ret=0;
    s32ret = sqlite3_open(ps8DBURL, db);
    if( s32ret ) {
        fprintf(stderr, "Can't open database: %s", sqlite3_errmsg(*db));
        CloseDB(*db);
        return DB_ERROR;
    }
    ApplyDBPragmas(*db);
    return DB_SUCCESS;
}

static void ApplyDBPragmas(sqlite3 *db)
{
    char *err = NULL;
    int rc;

    rc = sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        LOG_WARN_MSG("failed setting journal_mode=WAL: %s", err ? err : "unknown error");
        if (err != NULL) {
            sqlite3_free(err);
        }
        err = NULL;
    } else if (err != NULL) {
        sqlite3_free(err);
        err = NULL;
    }

    rc = sqlite3_exec(db, "PRAGMA synchronous=FULL;", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        LOG_WARN_MSG("failed setting synchronous=FULL: %s", err ? err : "unknown error");
        if (err != NULL) {
            sqlite3_free(err);
        }
        err = NULL;
    } else if (err != NULL) {
        sqlite3_free(err);
        err = NULL;
    }

    rc = sqlite3_busy_timeout(db, 5000);
    if (rc != SQLITE_OK) {
        LOG_WARN_MSG("failed setting busy_timeout: %d", rc);
    }
}

void CloseDB(sqlite3 *db)
{
    int rc = 0;
    rc = sqlite3_close(db);
    if(rc) {
        fprintf(stderr, "close DB error: %d\n", rc);
    } else
        fprintf(stderr, "Closed DB\n");
}

int ExecuteStatement(char *ps8Statement,sqlite3 **db)
{
    int s32DBRet=0;
    char *DBErrMsg = NULL;
    if(*db) {
        s32DBRet = sqlite3_exec(*db,ps8Statement , DBCallback, 0, &DBErrMsg);
        //        fprintf(stderr, "Executed Statement: %s\n", ps8Statement);
    } else {
        //        fprintf(stderr, "DB (%s) Not Open\n", ps8Statement);
        return DB_NOT_OPEN;
    }
    if( s32DBRet !=SQLITE_OK ) {
        //        fprintf(stderr, "SQL error: %s\n", DBErrMsg);
        return DB_ERROR;
    }

    if(DBErrMsg != NULL) {
        sqlite3_free(DBErrMsg);
    }
    return DB_SUCCESS;
}

static int DBCallback(void *NotUsed, int argc, char **argv, char **azColName)
{
    return DB_SUCCESS;
}

void DeleteDB(char *ps8DBURL)
{
    char ps8DelCommand[512];
    snprintf(ps8DelCommand, sizeof(ps8DelCommand),"rm -rf %s",ps8DBURL);
    system(ps8DelCommand);
}

int WeMoDBCreateTable(sqlite3 **DBHandle,char *TableName,TableDetails TableParams[],int PrimaryKeyEnable,int ParametersCount)
{
    char s8TempBuffer[512];
    char s8Statement[512];
    int s32cntr=0,rc=0;
    memset(s8TempBuffer, 0, 512);
    memset(s8Statement, 0, 512);
    snprintf(s8TempBuffer, sizeof(s8TempBuffer), "CREATE TABLE %s (%s %s,",TableName,TableParams[0].ParamName,TableParams[0].ParamDataType);
    strncpy(s8Statement,s8TempBuffer,sizeof(s8Statement)-1);
    for(s32cntr=1; s32cntr<ParametersCount; s32cntr++) {
        if (s32cntr == (ParametersCount -1))
            snprintf(s8TempBuffer, sizeof(s8TempBuffer), "%s %s",TableParams[s32cntr].ParamName,TableParams[s32cntr].ParamDataType);
        else
            snprintf(s8TempBuffer, sizeof(s8TempBuffer), "%s %s,",TableParams[s32cntr].ParamName,TableParams[s32cntr].ParamDataType);

        strncat(s8Statement,s8TempBuffer, sizeof(s8Statement)-strlen(s8Statement)-1);
        memset(s8TempBuffer, 0, 512);
    }
    strncat(s8Statement,");", sizeof(s8Statement)-strlen(s8Statement)-1);

    rc = ExecuteStatement(s8Statement,DBHandle);
    if( rc!=DB_SUCCESS ) {
        LOG_ERROR_MSG("SQL error on executing statement: %s", s8Statement);
        return DB_ERROR;
    }
    return DB_SUCCESS;
}

int WeMoDBInsertInTable(sqlite3 **DBHandle,char *TableName,ColDetails ColParams[],int ParametersCount)
{
    char s8TempBuffer[512];
    char s8Statement[512];
    int s32cntr=0,rc=0;
    memset(s8TempBuffer, 0, 512);
    memset(s8Statement, 0, 512);
    snprintf(s8TempBuffer, sizeof(s8TempBuffer), "INSERT INTO %s (%s",TableName,ColParams[0].ColName);
    strncpy(s8Statement,s8TempBuffer,sizeof(s8Statement)-1);
    for(s32cntr=1; s32cntr<ParametersCount; s32cntr++) {
        snprintf(s8TempBuffer, sizeof(s8TempBuffer), ", %s",ColParams[s32cntr].ColName);
        strncat(s8Statement,s8TempBuffer,  sizeof(s8Statement)-strlen(s8Statement)-1);
        memset(s8TempBuffer, 0, 512);
    }
    strncat(s8Statement,") VALUES(",  sizeof(s8Statement)-strlen(s8Statement)-1);
    for(s32cntr=0; s32cntr<ParametersCount; s32cntr++) {
        if (s32cntr == (ParametersCount-1))
            snprintf(s8TempBuffer, sizeof(s8TempBuffer), "%s",ColParams[s32cntr].ColValue);
        else
            snprintf(s8TempBuffer, sizeof(s8TempBuffer), "%s,",ColParams[s32cntr].ColValue);

        strncat(s8Statement,s8TempBuffer,  sizeof(s8Statement)-strlen(s8Statement)-1);
        memset(s8TempBuffer, 0, 512);
    }
    strncat(s8Statement,");",  sizeof(s8Statement)-strlen(s8Statement)-1);
    //    fprintf(stderr, "SQL  statement: %s\n", s8Statement);
    rc = ExecuteStatement(s8Statement,DBHandle);
    if( rc!=DB_SUCCESS ) {
        //        fprintf(stderr, "SQL error on executing statement: %s\n", s8Statement);
        return -1;
    }
    return 0;
}

int WeMoDBUpdateTable(sqlite3 **DBHandle,char *TableName,ColDetails ColParams[],int ParametersCount,char *Condition)
{
    char s8TempBuffer[1024];
    char s8Statement[1024];
    int s32cntr=0,rc=0;
    memset(s8TempBuffer, 0, sizeof(s8TempBuffer));
    memset(s8Statement, 0, sizeof(s8Statement));
    if(ParametersCount < 2) {
        snprintf(s8TempBuffer, sizeof(s8TempBuffer), "UPDATE %s SET %s=%s",TableName,ColParams[0].ColName,ColParams[0].ColValue);
    } else {
        snprintf(s8TempBuffer, sizeof(s8TempBuffer), "UPDATE %s SET %s=%s,",TableName,ColParams[0].ColName,ColParams[0].ColValue);
    }
    strncpy(s8Statement,s8TempBuffer,sizeof(s8Statement)-1);
    for(s32cntr=1; s32cntr<ParametersCount; s32cntr++) {
        if (s32cntr == (ParametersCount - 1))
            snprintf(s8TempBuffer, sizeof(s8TempBuffer), "%s=%s",ColParams[s32cntr].ColName,ColParams[s32cntr].ColValue);
        else
            snprintf(s8TempBuffer, sizeof(s8TempBuffer), "%s=%s,",ColParams[s32cntr].ColName,ColParams[s32cntr].ColValue);

        strncat(s8Statement,s8TempBuffer,  sizeof(s8Statement)-strlen(s8Statement)-1);
        memset(s8TempBuffer, 0, sizeof(s8TempBuffer));
    }
    if(Condition != NULL) {
        strncat(s8Statement," WHERE ",  sizeof(s8Statement)-strlen(s8Statement)-1);
        strncat(s8Statement,Condition,  sizeof(s8Statement)-strlen(s8Statement)-1);
    }
    strncat(s8Statement,";",  sizeof(s8Statement)-strlen(s8Statement)-1);
    //    fprintf(stderr, "SQL  statement: %s\n", s8Statement);
    rc = ExecuteStatement(s8Statement,DBHandle);
    if( rc!=DB_SUCCESS ) {
        //        fprintf(stderr, "SQL error on executing statement: %s\n", s8Statement);
        return -1;
    }
    return 0;
}

int WeMoDBgetData(sqlite3 **DBHandle,char *TableName, char *field, char *condition)
{
	char sql[512];
	int rc;

	sprintf(sql, "select %s from %s where %s", field, TableName, condition);
	rc = ExecuteStatement(sql, DBHandle);
	if (rc != DB_SUCCESS) {
        //		fprintf(stderr, "SQL error on executing statement: %s\n", sql);
		return -1;
	}
	return 0;
}

int WeMoDBGetTableData(sqlite3 **DBHandle,char *s8Query,char ***s8Result,int *s32NumofRows, int *s32NumofCols)
{
    char **s8result;
    char *s8SQLErr=NULL;
    int RowCount=0,ColCount=0;
    int rc=0,s32RowCntr=0,s32ArraySize=0;
    rc = sqlite3_get_table(*DBHandle, s8Query, &s8result, &RowCount, &ColCount, &s8SQLErr);
    if( rc!=DB_SUCCESS ) {
        //        fprintf(stderr, "SQL error on executing statement: %s\n", s8SQLErr);
        return -1;
    }
    *s32NumofRows = RowCount;
    *s32NumofCols = ColCount;
    s32ArraySize = ((*s32NumofRows) + 1)*(*s32NumofCols);
    //    fprintf(stderr, "\ns32NumofRows: %d s32NumofCols: %d Array Size: %d\n",*s32NumofRows,*s32NumofCols,s32ArraySize);
    if(s32ArraySize == 0) {
        sqlite3_free_table(s8result);
        return 0;
    }

    *s8Result =(char **) malloc(sizeof(char *)*s32ArraySize);

    for(s32RowCntr=0; s32RowCntr < s32ArraySize; s32RowCntr++) {
        (*s8Result)[s32RowCntr] = (char *)malloc(MAX_NAME_SIZE);
        memset((*s8Result)[s32RowCntr],0,MAX_NAME_SIZE);
    }
    for(s32RowCntr=0; s32RowCntr < s32ArraySize; s32RowCntr++) {
        if(s8result[s32RowCntr] != NULL) {
            strncpy((*s8Result)[s32RowCntr],s8result[s32RowCntr],MAX_NAME_SIZE);
        } else {
            //            fprintf(stderr, "s8result[%d] = NULL\n",s32RowCntr);
        }
    }
    sqlite3_free_table(s8result);
    return 0;
}

void WeMoDBTableFreeResult(char ***s8Result,int *s32NumofRows,int *s32NumofCols)
{
    int s32RowCntr=0;
    int s32ArraySize = ((*s32NumofRows) +1)*(*s32NumofCols);

    for(s32RowCntr=0; s32RowCntr < s32ArraySize; s32RowCntr++) {
        if((*s8Result)[s32RowCntr] != NULL)
            free((*s8Result)[s32RowCntr]);
    }
    if(*s8Result != NULL)
        free(*s8Result);
}

int WeMoDBDropTable(sqlite3 **DBHandle,char *TableName)
{
    char s8Statement[512];
    int	 rc=0;
    snprintf(s8Statement, sizeof(s8Statement), "DROP TABLE %s",TableName);
    rc = ExecuteStatement(s8Statement,DBHandle);
    if( rc!=DB_SUCCESS ) {
        //        fprintf(stderr, "\nSQL error\n");
    }
    return 0;

}

int WeMoDBDeleteEntry(sqlite3 **DBHandle,char *TableName,char *Condition)
{
    char s8Statement[512];
    int	 rc=0;
    memset(s8Statement, 0, 512);
    if(Condition != NULL) {
        snprintf(s8Statement, sizeof(s8Statement), "DELETE FROM %s WHERE %s;",TableName,Condition);
        rc = ExecuteStatement(s8Statement,DBHandle);
        if( rc!=DB_SUCCESS ) {
            //            fprintf(stderr, "SQL error on executing statement: %s\n", s8Statement);
        }
        return 0;
    } else {
        //        fprintf(stderr, "No Condition too create Query\n");
        return 1;
    }
}

int WeMoDBDeleteAllEntries(sqlite3 **DBHandle,char *TableName)
{
    char s8Statement[512];
    int	 rc=0;
    memset(s8Statement, 0, 512);

    snprintf(s8Statement, sizeof(s8Statement), "DELETE FROM %s ;",TableName);
    rc = ExecuteStatement(s8Statement,DBHandle);
    if( rc!=DB_SUCCESS ) {
        //        fprintf(stderr, "SQL error on executing statement: %s\n", s8Statement);
    }
    return 0;
}
