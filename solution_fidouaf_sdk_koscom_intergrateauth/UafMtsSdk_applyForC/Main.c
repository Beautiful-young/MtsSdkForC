#include <stdio.h>
#include "UafMtsSdk.h"

const char* SUCCESS_STR = "00000000";

const char *PATH = "E:\\env_common\\UAF\\koscom_it\\client\\env\\uafsdk\\uafsdk4c.properties";
const char *USERID = "test01";
const char *APPID = "https://211.236.246.77:9024/appid";

const char *SERVERADDR = "https://fido.signkorea.com:9033";
const char *REGISTRATIONREQUESTSUBURL = "/registrationrequestfromfc";
const char *REGISTRATIONRESPONSESUBURL = "/registrationresponsefromfc";
const char *AUTHENTICATIONREQUESTSUBURL = "/authenticationrequestfromfc";
const char *AUTHENTICATIONRESPONSESUBURL = "/authenticationresponsefromfc";
const char *TRANSACTIONREQUESTSUBURL = "/authenticationrequestfromfc";
const char *TRANSACTIONRESPONSESUBURL = "/authenticationresponsefromfc";
const char *SIMPLEAUTHREQUESTSUBURL = "/simpleauthenticationrequestfromfc";
const char *SIMPLEAUTHRESPONSESUBURL = "/simpleauthenticationresponsefromfc";
const char *DEREGISTRATIONREQUESTSUBURL = "/deregistrationrequestfromfc";

const char *TESTSIMREQMSG = "{\"version\":\"1.0\",\"source\":8,\"target\":64,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"test01\",\"sessionid\":\"7f0d2ba098c445edbb457737b80a1d82\",\"errorcode\":\"00000000\",\"operation\":\"auth\",\"authrequestmsg\":\"W3siaGVhZGVyIjp7InVwdiI6eyJtYWpvciI6MSwibWlub3IiOjB9LCJvcCI6IkF1dGgiLCJhcHBJRCI6Imh0dHBzOi8vMjExLjIzNi4yNDYuNzc6OTAyNC9hcHBpZCIsInNlcnZlckRhdGEiOiJlMjNmNjUyMGJjZmU0MjVmOTZjM2YxYTdjMjJmNzg0OSIsImV4dHMiOlt7ImlkIjoic2ltcGxlcHVia2V5IiwiZGF0YSI6ImNIVmliR2xqSUd0bGVRIiwiZmFpbF9pZl91bmtub3duIjpmYWxzZX0seyJpZCI6Im5vbmlkIiwiZGF0YSI6Ilhib00wQ1hOL1g4bGJuL0JSdURKd1dYcWg2aUp6MHdkR3VseDNQUm43Mnc9IiwiZmFpbF9pZl91bmtub3duIjpmYWxzZX1dfSwiY2hhbGxlbmdlIjoiZTRiZGI3OGU1NDQwNDIzYmExODNlMTNhYWM3N2E0NTMiLCJwb2xpY3kiOnt9fV0\",\"authenticationmode\":\"3\"}";

void registration();
void getPubKeyTest();

/*
Fido registratin test.
*/
void registration() {
	size_t ret;
	size_t revChk = FALSE;
	char *outData = NULL;
	size_t outDataLen = 0;
	char targetUrl[128];
	ret = Init(PATH);
	

	//logutill("test");

	//1. Environment file initialization settings.
	fprintf(stdout, "FIDO registration Test. \n");

	if (ret) {
		fprintf(stdout,"Check the UafMtsSdk environment file information. \n");
		return;
	}
	//2. registration request
	//js_regreqmsg 샘플 메시지
	const char *js_regreqmsg = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"test01\",\"operation\":\"reg\"}";

	memset(targetUrl, 0x00, sizeof(targetUrl));
	sprintf(targetUrl,"%s%s", SERVERADDR, REGISTRATIONREQUESTSUBURL);
	revChk = registrationRequestWithJson((char*)targetUrl, (char*)js_regreqmsg, &outData, &outDataLen);

	if (outData)
		free(outData);

	//3. registration response
	const char *js_regrespmsg = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"test01\",\"operation\":\"reg\"}";


}


//
void getPubKeyTest() {
	char targetUrl[128];
	char *outData = NULL;
	size_t outDataLen = 0;

	const char *js_regreqmsg = "{\"version\": \"1.0\", \"source\": 4, \"target\": 8, \"operation\": \"auth\", \"authenticationmode\": \"3\", \"userid\": \"test01\", \"appid\": \"https://211.236.246.77:9024/appid\", \"rpwebsession\": \"0b4e7edd5634486cbb5bd8dd9e4ab43c\"}";
	size_t revChk = FALSE;

	memset(targetUrl, 0x00, sizeof(targetUrl));
	sprintf(targetUrl, "%s%s", SERVERADDR, SIMPLEAUTHREQUESTSUBURL);

	const char *b64nonid = "test nonid";

	revChk = simpleAuthRequestWithJson((char*)targetUrl, (char*)js_regreqmsg, (char*)b64nonid, &outData, &outDataLen);

	size_t ret;

	if (revChk) {
		fprintf(stdout, "success. \n");
	}
	else {
		fprintf(stdout, "fail. \n");
	}
	
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);
	/*
	char tmpResult[4096];
	memset(tmpResult, 0x00, 4096);
	memcpy(tmpResult, outData, outDataLen);
	fprintf(stdout, "tmpResult : %s\n", tmpResult);

	retDataFree(outData);
	*/

	

	//char* chpErrorcode = getErrorCode(tmpResult);
	char* chpErrorcode = getErrorCode(TESTSIMREQMSG);
	
	if (!chpErrorcode) {
		fprintf(stdout, "chpErrorcode is NULL. \n");
		return;
	}
	if (strcmp((char*)SUCCESS_STR, chpErrorcode) != 0){
		//error
		fprintf(stdout, "chpErrorcode : %s \n", chpErrorcode);
		if (chpErrorcode)
			retDataFree(chpErrorcode);

		return;
	}

	unsigned char *outPubKey = NULL;
	size_t outPubKeyLen;
	//ret = getPubKeyFromExtention(tmpResult, &outPubKey, &outPubKeyLen);
	ret = getPubKeyFromExtention(TESTSIMREQMSG, &outPubKey, &outPubKeyLen);
	if (!ret) {
		fprintf(stdout, "outPubKeyLen : %d\n", outPubKeyLen);
	}
	else {
		fprintf(stdout, "Failed to acquire public key.\n");
	}
	
	jsonRetFree(outPubKey);

	/*
	ret = getPubKey((char*)js_regreqmsg, &outPubKey, &outPubKeyLen);

	if (!ret) {
		fprintf(stdout, "outPubKeyLen : %d\n", outPubKeyLen);

	}
	jsonRetFree(outPubKey);
	*/


	


}


int main(void) {
	//registration();
	getPubKeyTest();


	/*
	size_t ret;
	size_t revChk = FALSE;
	char *outData = NULL;
	size_t outDataLen = 0;

	ret = Init(path);
	*/

	/*
	revChk = registrationRequest((char*)targetUrl, (char*)userid, (char*)appid, &outData , &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	retDataFree(outData);
	*/

	/*
	const char *js_regreqmsg = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"test01\",\"operation\":\"reg\"}";

	revChk = registrationRequestWithJson((char*)targetUrl, (char*)js_regreqmsg, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	retDataFree(outData);
	*/


	//registrationResponse 테스트
	/*
	char *sessionid = NULL;
	char *b64regresp = NULL;
	targetUrl = "https://fido.signkorea.com:9033/registrationresponsefromfc";

	char rpwebsession[38];
	size_t rc;
	rc = getSessionID(rpwebsession);
	sessionid = rpwebsession;
	revChk = registrationResponse((char*)targetUrl, (char*)appid, (char*)rpwebsession, (char*)b64regresp, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);
	retDataFree(outData);
	*/

	//registrationResponseWithJson 테스트
	/*
	targetUrl = "https://fido.signkorea.com:9033/registrationresponsefromfc";
	const char *js_regreqmsg = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"operation\":\"reg\",\"regresponsemsg\":\"\"}";

	revChk = registrationResponseWithJson((char*)targetUrl, (char*)js_regreqmsg, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	retDataFree(outData);
	*/
	/*
	public static String AUTHENTICATIONREQUESTSUBURL = "/authenticationrequestfromfc";
	public static String AUTHENTICATIONRESPONSESUBURL = "/authenticationresponsefromfc";
	public static String DEREGISTRATIONREQUESTSUBURL = "/deregistrationrequestfromfc";
	public static String SIMPLEAUTHREQUESTSUBURL = "/simpleauthenticationrequestfromfc";
	public static String SIMPLEAUTHRESPONSESUBURL = "/simpleauthenticationresponsefromfc";
	public static String APPID = "https://211.236.246.77:9024/appid";
	*/

	//authenticationRequest
	/*
	targetUrl = "https://fido.signkorea.com:9033/authenticationrequestfromfc";
	revChk = authenticationRequest((char*)targetUrl, (char*)userid, (char*)appid, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	retDataFree(outData);
	*/


	//authenticationResponseWithJson 
	/*
	const char *js_regreqmsg = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"test01\",\"operation\":\"auth\"}";
	targetUrl = "https://fido.signkorea.com:9033/authenticationrequestfromfc";
	revChk = authenticationRequestWithJson((char*)targetUrl, (char*)js_regreqmsg, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	retDataFree(outData);
	*/

	//authenticationResponse
	/*
	targetUrl = "https://fido.signkorea.com:9033/authenticationresponsefromfc";
	char *sessionid = NULL;
	char *b64authresp = NULL;
	char rpwebsession[38];
	size_t rc;
	rc = getSessionID(rpwebsession);
	sessionid = rpwebsession;
	revChk = authenticationResponse((char*)targetUrl, (char*)appid, (char*)sessionid, (char*)b64authresp, &outData, &outDataLen);
	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);
	retDataFree(outData);
	*/

	//authenticationResponseWithJson
	/*
	targetUrl = "https://fido.signkorea.com:9033/authenticationresponsefromfc";
	const char *js_regreqmsg = "{\"version\": \"1.0\", \"source\": 4, \"target\": 8, \"operation\": \"auth\", \"authenticationmode\": \"1\", \"appid\": \"https://211.236.246.77:9024/appid\", \"sessionid\": \"53e80666f19249fea257904a779b47de\"}";

	authenticationResponseWithJson((char*)targetUrl, (char*)js_regreqmsg, &outData, &outDataLen);
	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);
	retDataFree(outData);
	*/

	//transactionConfirmationRequest
	/*
	targetUrl = "https://fido.signkorea.com:9033/authenticationrequestfromfc";
	char *contentType = NULL;
	char *contentEncodingType = NULL;
	char *content=NULL;

	revChk = transactionConfirmationRequest((char*)targetUrl, (char*)userid, (char*)appid
	, contentType, contentEncodingType, content, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	retDataFree(outData);
	*/

	//transactionConfirmationRequestWithJson
	/*
	const char *js_regreqmsg = "{\"version\": \"1.0\", \"source\": 4, \"target\": 8, \"operation\": \"auth\", \"authenticationmode\": \"2\", \"userid\": \"test01\", \"appid\": \"https://211.236.246.77:9024/appid\", \"rpwebsession\": \"185d418312d1416abf3b1fbac717ef99\"}";
	targetUrl = "https://fido.signkorea.com:9033/authenticationrequestfromfc";
	revChk = transactionConfirmationRequestWithJson((char*)targetUrl, (char*)js_regreqmsg, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	retDataFree(outData);
	*/

	//transactionConfirmationResponse
	/*
	char *sessionid = NULL;
	char *b64regresp = NULL;
	targetUrl = "https://fido.signkorea.com:9033/authenticationresponsefromfc";

	char rpwebsession[38];
	size_t rc;
	rc = getSessionID(rpwebsession);
	sessionid = rpwebsession;
	revChk = transactionConfirmationResponse((char*)targetUrl, (char*)appid, (char*)rpwebsession, (char*)b64regresp, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);
	retDataFree(outData);
	*/


	//transactionConfirmationResponseWithJson
	/*
	targetUrl = "https://fido.signkorea.com:9033/authenticationresponsefromfc";
	const char *js_regreqmsg = "{\"version\": \"1.0\", \"source\": 4, \"target\": 8, \"operation\": \"auth\", \"authenticationmode\": \"2\", \"appid\": \"https://211.236.246.77:9024/appid\", \"sessionid\": \"51d70066cdbd4c0a93bc5bc1adb30d7b\"}";

	revChk = transactionConfirmationResponseWithJson((char*)targetUrl, (char*)js_regreqmsg, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	retDataFree(outData);
	*/

	//simpleAuthRequest
	/*
	char *b64pubkey = NULL;
	char *b64nonid = NULL;
	targetUrl = "https://fido.signkorea.com:9033/simpleauthenticationrequestfromfc";
	revChk = simpleAuthRequest((char*)targetUrl, (char*)userid, (char*)appid, b64pubkey, b64nonid, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	char tmpResult[4096];
	memset(tmpResult, 0x00, 4096);
	memcpy(tmpResult, outData, outDataLen);
	fprintf(stdout, "tmpResult : %s\n", tmpResult);
	retDataFree(outData);
	*/

	//simpleAuthRequestWithJson
	//size_t simpleAuthRequestWithJson(char *targetUrl, char *jsmsg, char *b64nonid, char **outData, size_t *outDataLen);
	/*
	const char *js_regreqmsg = "{\"version\": \"1.0\", \"source\": 4, \"target\": 8, \"operation\": \"auth\", \"authenticationmode\": \"3\", \"userid\": \"test01\", \"appid\": \"https://211.236.246.77:9024/appid\", \"rpwebsession\": \"0b4e7edd5634486cbb5bd8dd9e4ab43c\"}";
	targetUrl = "https://fido.signkorea.com:9033/simpleauthenticationrequestfromfc";
	const char *b64nonid = "test nonid";

	revChk = simpleAuthRequestWithJson((char*)targetUrl, (char*)js_regreqmsg, (char*)b64nonid,&outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	char tmpResult[4096];
	memset(tmpResult, 0x00, 4096);
	memcpy(tmpResult, outData, outDataLen);
	fprintf(stdout, "tmpResult : %s\n", tmpResult);

	retDataFree(outData);
	*/

	//simpleAuthResponse
	//size_t simpleAuthResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char **outData, size_t *outDataLen);
	/*
	targetUrl = "https://fido.signkorea.com:9033/simpleauthenticationresponsefromfc";
	char *sessionid = NULL;
	char *b64authresp = NULL;
	char rpwebsession[38];
	size_t rc;
	rc = getSessionID(rpwebsession);
	sessionid = rpwebsession;
	revChk = simpleAuthResponse((char*)targetUrl, (char*)appid, (char*)sessionid, (char*)b64authresp, &outData, &outDataLen);
	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	char tmpResult[4096];
	memset(tmpResult, 0x00, 4096);
	memcpy(tmpResult, outData, outDataLen);
	fprintf(stdout, "tmpResult : %s\n", tmpResult);
	retDataFree(outData);
	*/

	//simpleAuthResponseWithJson
	/*
	const char *js_regreqmsg = "{\"version\": \"1.0\", \"source\": 4, \"target\": 8, \"operation\": \"auth\", \"authenticationmode\": \"3\", \"appid\": \"https://211.236.246.77:9024/appid\", \"sessionid\": \"3acbf31d8548468eaffa2f06432ca79f\"}";
	targetUrl = "https://fido.signkorea.com:9033/simpleauthenticationresponsefromfc";
	const char *b64nonid = "test nonid";

	revChk = simpleAuthRequestWithJson((char*)targetUrl, (char*)js_regreqmsg, (char*)b64nonid, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	char tmpResult[4096];
	memset(tmpResult, 0x00, 4096);
	memcpy(tmpResult, outData, outDataLen);
	fprintf(stdout, "tmpResult : %s\n", tmpResult);

	retDataFree(outData);
	*/

	//deregistrationRequest	
	//size_t deregistrationRequest(char *targetUrl, char *userid, char *appid, char **outData, size_t *outDataLen);
	/*
	targetUrl = "https://fido.signkorea.com:9033/deregistrationrequestfromfc";
	revChk = deregistrationRequest((char*)targetUrl, (char*)userid, (char*)appid, &outData, &outDataLen);

	if (revChk) {
	fprintf(stdout, "success. \n");
	}
	else {
	fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	char tmpResult[4096];
	memset(tmpResult, 0x00, 4096);
	memcpy(tmpResult, outData, outDataLen);
	fprintf(stdout, "tmpResult : %s\n", tmpResult);

	retDataFree(outData);
	*/

	//deregistrationRequestWithJson
	/*
	const char *js_regreqmsg = "{\"version\":\"1.0\",\"source\":8,\"target\":16,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"test01\",\"sessionid\":\"ea1415d6ee2348ecb3f8741f127b8269\"}";
	targetUrl = "https://fido.signkorea.com:9033/deregistrationrequestfromfc";
	revChk = deregistrationRequestWithJson((char*)targetUrl, (char*)js_regreqmsg, &outData, &outDataLen);

	if (revChk) {
		fprintf(stdout, "success. \n");
	}
	else {
		fprintf(stdout, "fail. \n");
	}
	fprintf(stdout, "outData : %d\n", outDataLen);
	fprintf(stdout, "outData : %s\n", outData);

	char tmpResult[4096];
	memset(tmpResult, 0x00, 4096);
	memcpy(tmpResult, outData, outDataLen);
	fprintf(stdout, "tmpResult : %s\n", tmpResult);

	retDataFree(outData);
	*/
	system("pause");
}