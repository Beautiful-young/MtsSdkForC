#ifndef __UafMtsSdkPro_H
#define __UafMtsSdkPro_H

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

	size_t p_Init(const char *path);
	size_t p_registrationRequest(char *targetUrl, char *userid, char *appid, size_t mobiletype, char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen);
	size_t p_registrationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
	size_t p_registrationResponse(char *targetUrl, char *appid, char *sessionid, char *b64regresp, char* authtype, char **outData, size_t *outDataLen);
	size_t p_registrationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
	size_t p_authenticationRequest(char *targetUrl, char *userid, char *appid, size_t mobiletype, char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen);
	size_t p_authenticationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);

	size_t p_authenticationResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char* authtype, char **outData, size_t *outDataLen);
	size_t p_authenticationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
	size_t p_transactionConfirmationRequest(char *targetUrl, char *userid, char *appid
		, char *contentType, char *contentEncodingType, char *content, size_t mobiletype, char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen);
	size_t p_transactionConfirmationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
	size_t p_transactionConfirmationResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char* authtype, char **outData, size_t *outDataLen);
	size_t p_transactionConfirmationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
	size_t p_simpleAuthRequest(char *targetUrl, char *userid, char *appid, char *b64pubkey, char *b64nonid, size_t mobiletype, char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen);
	size_t p_simpleAuthRequestWithJson(char *targetUrl, char *jsmsg, char *b64nonid, char **outData, size_t *outDataLen);
	size_t p_simpleAuthResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char* authtype, char **outData, size_t *outDataLen);
	size_t p_simpleAuthResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);
	size_t p_deregistrationRequest(char *targetUrl, char *userid, char *appid, size_t mobiletype, char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen);

	size_t p_deregistrationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen);

	void p_retDataFree(char *msg);
	char* p_getCommonErrMsg(const char* operation);

	char* p_getErrorCode(const char *input);
	size_t p_getPubKey(const char *input, unsigned char **outPubKey, size_t *outPubKeyLen);
	size_t p_getPubKeyFromExtention(const char *input, unsigned char **outPubKey, size_t *outPubKeyLen);

#ifdef __cplusplus
}
#endif 

#endif /* !__UafMtsSdkPro_H*/