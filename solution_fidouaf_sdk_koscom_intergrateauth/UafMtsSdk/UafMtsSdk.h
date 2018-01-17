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
InternalJsonMessage* registrationRequest(char *targetUrl, char *userid, char *appid);

