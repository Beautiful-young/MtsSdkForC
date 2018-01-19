#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libconfig.h>
#include <jansson.h>

#ifdef __cplusplus 
extern "C" {
#endif

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


int Init(const char *path);
size_t registrationRequest(char *targetUrl, char *userid, char *appid, char **outData, size_t *outDataLen);
size_t registrationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t registrationResponse(char *targetUrl, char *appid, char *sessionid, char *b64regresp, char **outData, size_t *outDataLen);
size_t registrationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t authenticationRequest(char *targetUrl, char *userid, char *appid, char **outData, size_t *outDataLen);
size_t authenticationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);

size_t authenticationResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char **outData, size_t *outDataLen);
size_t authenticationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t transactionConfirmationRequest(char *targetUrl, char *userid, char *appid
	, char *contentType, char *contentEncodingType, char *content, char **outData, size_t *outDataLen);
size_t transactionConfirmationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t transactionConfirmationResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char **outData, size_t *outDataLen);
size_t transactionConfirmationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t simpleAuthRequest(char *targetUrl, char *userid, char *appid, char *b64pubkey, char *b64nonid, char **outData, size_t *outDataLen);
size_t simpleAuthRequestWithJson(char *targetUrl, char *jsmsg, char *b64nonid, char **outData, size_t *outDataLen);
size_t simpleAuthResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char **outData, size_t *outDataLen);
size_t simpleAuthResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
size_t deregistrationRequest(char *targetUrl, char *userid, char *appid, char **outData, size_t *outDataLen);

size_t deregistrationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);

void retDataFree(char *msg);
char* getCommonErrMsg(const char* operation);


#ifdef __cplusplus
}
#endif 