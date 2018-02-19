#include "UafMtsSdk.h"


int Init(const char *path) {
	size_t nRet = 0;
	nRet = p_Init(path);
	return nRet;
}

size_t registrationRequest(char *targetUrl, char *userid, char *appid, size_t mobiletype, char* mobileversion
	, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen) 
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;
	
	retVal = p_registrationRequest(targetUrl, userid, appid, mobiletype, mobileversion
		,  mobilemodel, appversion, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}

size_t registrationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_registrationRequestWithJson(targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;

}

size_t registrationResponse(char *targetUrl, char *appid, char *sessionid, char *b64regresp,
	char* authtype, char **outData, size_t *outDataLen) 
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_registrationResponse(targetUrl, appid, sessionid, b64regresp,
		authtype, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}

size_t registrationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_registrationResponseWithJson(targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}
size_t authenticationRequest(char *targetUrl, char *userid, char *appid, size_t mobiletype, char* mobileversion, 
	char* mobilemodel, char* appversion, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_authenticationRequest(targetUrl, userid, appid, mobiletype, mobileversion,
		mobilemodel, appversion, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}
size_t authenticationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen)
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_authenticationRequestWithJson(targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}
size_t authenticationResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp,
	char* authtype, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_authenticationResponse(targetUrl, appid, sessionid, b64authresp,
		authtype, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}
size_t authenticationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen)
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_authenticationResponseWithJson(targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}
size_t transactionConfirmationRequest(char *targetUrl, char *userid, char *appid
	, char *contentType, char *contentEncodingType, char *content, size_t mobiletype, char* mobileversion,
	char* mobilemodel, char* appversion, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_transactionConfirmationRequest(targetUrl, userid, appid
		, contentType, contentEncodingType, content, mobiletype, mobileversion,
		mobilemodel, appversion, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}

size_t transactionConfirmationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen)
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_transactionConfirmationRequestWithJson(targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}

size_t transactionConfirmationResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp,
	char* authtype, char **outData, size_t *outDataLen) 
{

	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_transactionConfirmationResponse(targetUrl, appid, sessionid, b64authresp,
		authtype, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;

}

size_t transactionConfirmationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen) 
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_transactionConfirmationResponseWithJson(targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}
size_t simpleAuthRequest(char *targetUrl, char *userid, char *appid, char *b64pubkey, char *b64nonid,
	size_t mobiletype, char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen) 
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_simpleAuthRequest(targetUrl, userid, appid, b64pubkey, b64nonid,
		mobiletype, mobileversion, mobilemodel, appversion, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}
size_t simpleAuthRequestWithJson(char *targetUrl, char *jsmsg, char *b64nonid, char **outData, size_t *outDataLen)
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_simpleAuthRequestWithJson(targetUrl, jsmsg, b64nonid, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}
size_t simpleAuthResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp,
	char* authtype, char **outData, size_t *outDataLen)
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_simpleAuthResponse(targetUrl, appid, sessionid, b64authresp,
		authtype, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}

size_t simpleAuthResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen)
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_simpleAuthResponseWithJson(targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}
size_t deregistrationRequest(char *targetUrl, char *userid, char *appid, size_t mobiletype,
	char* mobileversion, char* mobilemodel, char* appversion, char **outData, size_t *outDataLen)
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_deregistrationRequest(targetUrl, userid, appid, mobiletype,
		mobileversion, mobilemodel, appversion, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}

size_t deregistrationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen)
{
	size_t retVal = 0;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_deregistrationRequestWithJson(targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);

	*outData = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outDataLen = outDataLenTmp;
	memcpy(*outData, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}

void retDataFree(char *msg) {
	if (msg)
		free(msg);
}

size_t getPubKey(const char *input, unsigned char **outPubKey, size_t *outPubKeyLen) {
	size_t retVal = 0;
	unsigned char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_getPubKey(input, &outDataTmp, &outDataLenTmp);

	*outPubKey = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outPubKeyLen = outDataLenTmp;
	memcpy(*outPubKey, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}
size_t getPubKeyFromExtention(const char *input, unsigned char **outPubKey, size_t *outPubKeyLen) {
	size_t retVal = 0;
	unsigned char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	retVal = p_getPubKeyFromExtention(input, &outDataTmp, &outDataLenTmp);

	*outPubKey = (char*)calloc(outDataLenTmp + 1, sizeof(char));
	*outPubKeyLen = outDataLenTmp;
	memcpy(*outPubKey, outDataTmp, outDataLenTmp);

	p_retDataFree(outDataTmp);

	return retVal;
}

char* getCommonErrMsg(const char* operation) {
	char *retMsg = NULL;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	outDataTmp = p_getCommonErrMsg(operation);

	retMsg = (char*)calloc(strlen(outDataTmp) + 1, sizeof(char));
	memcpy(retMsg, outDataTmp, strlen(outDataTmp));
	
	p_retDataFree(outDataTmp);

	return retMsg;
}

char* getErrorCode(const char *input) {
	char *reterrorcode = NULL;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	outDataTmp = p_getErrorCode(input);

	reterrorcode = (char*)calloc(strlen(outDataTmp) + 1, sizeof(char));
	memcpy(reterrorcode, outDataTmp, strlen(outDataTmp));
	
	p_retDataFree(outDataTmp);

	return reterrorcode;
}