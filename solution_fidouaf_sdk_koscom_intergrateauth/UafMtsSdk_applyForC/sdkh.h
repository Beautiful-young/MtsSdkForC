#ifndef __sdkh_H
#define __sdkh_H

#ifdef __cplusplus 
extern "C" {
#endif

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

#endif /* !__sdkh_H*/