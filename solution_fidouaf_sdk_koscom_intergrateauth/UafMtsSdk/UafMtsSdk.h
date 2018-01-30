#ifndef __UafMtsSdk_H
#define __UafMtsSdk_H



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libconfig.h>
#include <jansson.h>

#ifdef __cplusplus 
extern "C" {
#endif

static char SSL_PEMCERT_PATH_UAFSDK[128];
static char LOG_USAGE_UAFSDK[4];
static char LOG_PATH_UAFSDK[128];

#ifdef WIN32
#pragma warning(disable:4996)
#pragma warning(disable:4267)
#pragma warning(disable:4133)
#pragma warning(disable:4244)
#pragma warning(disable:4819)
#endif

#include "common.h"
#include "httputill.h"
#include "InternalJsonMessage.h"
#include "authreqmsg.h"
#include "logutill.h"
#include "Base64Decode.h"

int Init(const char *path);
size_t registrationRequest(char *targetUrl, char *userid, char *appid, size_t mobiletype, char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen);
size_t registrationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t registrationResponse(char *targetUrl, char *appid, char *sessionid, char *b64regresp, char* authtype, char **outData, size_t *outDataLen);
size_t registrationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t authenticationRequest(char *targetUrl, char *userid, char *appid, size_t mobiletype, char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen);
size_t authenticationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);

size_t authenticationResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char* authtype, char **outData, size_t *outDataLen);
size_t authenticationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t transactionConfirmationRequest(char *targetUrl, char *userid, char *appid
	, char *contentType, char *contentEncodingType, char *content, size_t mobiletype, char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen);
size_t transactionConfirmationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t transactionConfirmationResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char* authtype, char **outData, size_t *outDataLen);
size_t transactionConfirmationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t simpleAuthRequest(char *targetUrl, char *userid, char *appid, char *b64pubkey, char *b64nonid, size_t mobiletype, char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen);
size_t simpleAuthRequestWithJson(char *targetUrl, char *jsmsg, char *b64nonid, char **outData, size_t *outDataLen);
size_t simpleAuthResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char* authtype, char **outData, size_t *outDataLen);
size_t simpleAuthResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t deregistrationRequest(char *targetUrl, char *userid, char *appid, size_t mobiletype, char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen);

size_t deregistrationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);

void retDataFree(char *msg);
char* getCommonErrMsg(const char* operation);

char* getErrorCode(const char *input);
size_t getPubKey(const char *input, unsigned char **outPubKey, size_t *outPubKeyLen);
size_t getPubKeyFromExtention(const char *input, unsigned char **outPubKey, size_t *outPubKeyLen);

#ifdef __cplusplus
}
#endif 

#endif // !__UafMtsSdk_H