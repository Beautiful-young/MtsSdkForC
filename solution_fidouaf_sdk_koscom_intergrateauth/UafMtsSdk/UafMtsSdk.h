#pragma once
#include "InternalJsonMessage.h"
#ifdef WIN32
#pragma warning(disable:4996)
#pragma warning(disable:4267)
#pragma warning(disable:4133)
#pragma warning(disable:4244)
#pragma warning(disable:4819)
#endif

int Init(const char *path);
size_t registrationRequest(char *targetUrl, char *userid, char *appid, char **outData, size_t *outDataLen);
void retDataFree(char *msg);
char* getCommonErrMsg(char* operation);