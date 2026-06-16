#ifndef CJSON_H
#define CJSON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct cJSON {
    struct cJSON *next;
    struct cJSON *prev;
    struct cJSON *child;
    int type;
    char *valuestring;
    int valueint;
    double valuedouble;
    char *string;
} cJSON;

#define cJSON_False   0
#define cJSON_True    1
#define cJSON_NULL    2
#define cJSON_Number  3
#define cJSON_String  4
#define cJSON_Array   5
#define cJSON_Object  6

cJSON *cJSON_Parse(const char *value);
char *cJSON_Print(const cJSON *item);
void cJSON_Delete(cJSON *c);

cJSON *cJSON_GetObjectItem(const cJSON *object, const char *string);
int cJSON_GetArraySize(const cJSON *array);
cJSON *cJSON_GetArrayItem(const cJSON *array, int index);

cJSON *cJSON_CreateTrue(void);
cJSON *cJSON_CreateFalse(void);
cJSON *cJSON_CreateString(const char *string);
cJSON *cJSON_CreateNumber(double num);
cJSON *cJSON_CreateObject(void);
cJSON *cJSON_CreateArray(void);

void cJSON_AddItemToArray(cJSON *array, cJSON *item);
void cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item);
int cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newitem);

#define cJSON_IsTrue(item)   ((item) && (item)->type == cJSON_True)
#define cJSON_IsFalse(item)  ((item) && (item)->type == cJSON_False)
#define cJSON_IsNull(item)   ((item) && (item)->type == cJSON_NULL)
#define cJSON_IsNumber(item) ((item) && (item)->type == cJSON_Number)
#define cJSON_IsString(item) ((item) && (item)->type == cJSON_String)
#define cJSON_IsArray(item)  ((item) && (item)->type == cJSON_Array)
#define cJSON_IsObject(item) ((item) && (item)->type == cJSON_Object)

const char *cJSON_GetErrorPtr(void);

#endif /* CJSON_H */
