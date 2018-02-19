#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "UafMtsSdk.h"

const char* SUCCESS_STR = "00000000";

const char *PATH = "E:\\env_common\\UAF\\koscom_it\\client\\env\\uafsdk\\uafsdk4c.properties";
const char *USERID = "test01";
const char *APPID = "https://211.236.246.77:9024/appid";

/*const char *SERVERADDR = "https://fido.signkorea.com:9033";*/
const char *SERVERADDR = "https://211.236.246.77:9033";
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

const char *TEST_REG_REQ_JSMSG = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"test01\",\"mobiletype\":1,\"operation\":\"reg\",\"mobileversion\":\"android 7.0\",\"mobilemodel\":\"SM-G950N\",\"appversion\":\"koscom fido 1.0\"}";
const char *TEST_REG_RESP_JSMSG = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"sessionid\":\"22ad89127b7745ab9a6ba681c05bac79\",\"operation\":\"reg\",\"regresponsemsg\":\"\",\"authtype\":\"2\"}";

const char *TEST_AUTH_REQ_JSMSG = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"test01\",\"mobiletype\":1,\"operation\":\"auth\",\"mobileversion\":\"android 7.0\",\"mobilemodel\":\"SM-G950N\",\"appversion\":\"koscom fido 1.0\"}";
const char *TEST_AUTH_RESP_JSMSG = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"sessionid\":\"266f5688081e418489bbf70ae1a6ed2c\",\"operation\":\"auth\",\"authresponsemsg\":\"\",\"authtype\":\"2\"}";

const char *TEST_AUTHTC_REQ_JSMSG = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"test01\",\"mobiletype\":1,\"operation\":\"auth\",\"contentType\":\"text/plain\",\"content\":\"content samile.\",\"contentEncodingType\":\"plaintext\",\"mobileversion\":\"android 7.0\",\"mobilemodel\":\"SM-G950N\",\"appversion\":\"koscom fido 1.0\"}";
const char *TEST_AUTHTC_RESP_JSMSG = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"sessionid\":\"\",\"operation\":\"auth\",\"authresponsemsg\":\"\",\"authtype\":\"2\"}";

const char *TEST_SIMPLE_REQ_JSMSG = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"test01\",\"mobiletype\":1,\"operation\":\"auth\",\"authenticationmode\":\"3\",\"b64pk\":\"cHVibGljIGtleQ\",\"mobileversion\":\"android 7.0\",\"mobilemodel\":\"SM-G950N\",\"appversion\":\"koscom fido 1.0\"}";
const char *TEST_SIMPLE_RESP_JSMSG = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"sessionid\":\"863f0bf9592e4d64ac7760f487441d8c\",\"operation\":\"auth\",\"authresponsemsg\":\"\",\"authenticationmode\":\"3\",\"authtype\":\"2\"}";

const char *TEST_DEREG_REQ_JSMSG = "{\"version\":\"1.0\",\"source\":64,\"target\":8,\"appid\":\"https://211.236.246.77:9024/appid\",\"userid\":\"test01\",\"mobiletype\":1,\"operation\":\"dereg\",\"mobileversion\":\"android 7.0\",\"mobilemodel\":\"SM-G950N\",\"appversion\":\"koscom fido 1.0\"}";


void registration_test();
void authentication_test();
void getPubKeyTest();
void transactionconfirmation_test();
void simpleauthentication_test();
void deregistration_test();

/*
1. Fido registration test.
*/
void registration_test() {
	size_t ret=1;
	size_t revChk = 0;
	char *outData = NULL;
	size_t outDataLen = 0;
	char targetUrl[128];
	fprintf(stdout, "== 1. FIDO registration Test. ==\n");

	/*Environment file initialization settings.*/
	
	ret = Init(PATH);
	if (ret) {
		fprintf(stdout, "Check the UafMtsSdk environment file information. \n");
		return;
	}
	
	/*1-1. registration request*/
	fprintf(stdout, "  -- 1-1. registration request \n");
	memset(targetUrl, 0x00, sizeof(targetUrl));
	sprintf(targetUrl,"%s%s", SERVERADDR, REGISTRATIONREQUESTSUBURL);
	/*js_regreqmsg 샘플 메시지*/
	revChk = registrationRequestWithJson((char*)targetUrl, (char*)TEST_REG_REQ_JSMSG, &outData, &outDataLen);
	/* 리턴값에 0x00이 들어있을수 있어, outDataLen을 같이 리턴됨*/
	if (revChk) {
		fprintf(stdout, "A communication error with the server occurred when calling the registrationRequestWithJson function.");
		if (outData)
			free(outData);
		return;
	}

	if (!outData) {
		fprintf(stdout, "outData is null.");
		return;
	}
	char* tmpIeregregmsg = NULL;
	tmpIeregregmsg = calloc(outDataLen+1, sizeof(char));
	memcpy(tmpIeregregmsg, outData, outDataLen);
	
	if (outData)
		free(outData);
	fprintf(stdout, "-==-\n");
	fprintf(stdout, "reg req receive data : %s \n", tmpIeregregmsg);
	fprintf(stdout, "-==-\n");
	/*tmpIeregregmsg 값은 MTS앱에 전달한다.*/

	if (tmpIeregregmsg)
		free(tmpIeregregmsg);

	fprintf(stdout, "  -- 1-2.  registration response \n");
	memset(targetUrl, 0x00, sizeof(targetUrl));
	sprintf(targetUrl, "%s%s", SERVERADDR, REGISTRATIONRESPONSESUBURL);

	char *outRespData = NULL;
	size_t outRespDataLen = 0;

	revChk = registrationResponseWithJson((char*)targetUrl, (char*)TEST_REG_RESP_JSMSG, &outRespData, &outRespDataLen);
	/* 리턴값에 0x00이 들어있을수 있어, outRespDataLen을 같이 리턴됨*/
	if (revChk) {
		fprintf(stdout, "A communication error with the server occurred when calling the registrationResponseWithJson function.");
		if (outRespData)
			free(outRespData);
		return;
	}

	if (!outRespData) {
		fprintf(stdout, "outRespData is null.");
		return;
	}
	char* tmpIeregrespmsg = NULL;
	tmpIeregrespmsg = calloc(outRespDataLen + 1, sizeof(char));
	memcpy(tmpIeregrespmsg, outRespData, outRespDataLen);

	if (outRespData)
		free(outRespData);

	fprintf(stdout, "-==-\n");
	fprintf(stdout, "reg response receive data : %s \n", tmpIeregrespmsg);
	fprintf(stdout, "-==-\n");
	/*tmpIeregregmsg 값은 MTS앱에 전달한다.*/
	
	if (tmpIeregrespmsg)
		free(tmpIeregrespmsg);
}

/*
2. Fido authentication test.
*/
void authentication_test() {
	size_t ret = 1;
	size_t revChk = 0;
	char *outData = NULL;
	size_t outDataLen = 0;
	char targetUrl[128];
	fprintf(stdout, "== 2. FIDO authentication Test. ==\n");

	/*Environment file initialization settings.*/
	ret = Init(PATH);
	if (ret) {
		fprintf(stdout, "Check the UafMtsSdk environment file information. \n");
		return;
	}

	/*2-1. authentication request*/
	fprintf(stdout, "  -- 2-1. authentication request \n");
	memset(targetUrl, 0x00, sizeof(targetUrl));
	sprintf(targetUrl, "%s%s", SERVERADDR, AUTHENTICATIONREQUESTSUBURL);
	/*TEST_AUTH_REQ_JSMSG 샘플 메시지*/
	revChk = authenticationRequestWithJson((char*)targetUrl, (char*)TEST_AUTH_REQ_JSMSG, &outData, &outDataLen);
	/* 리턴값에 0x00이 들어있을수 있어, outDataLen을 같이 리턴됨*/
	if (revChk) {
		fprintf(stdout, "A communication error with the server occurred when calling the authenticationRequestWithJson function.");
		if (outData)
			free(outData);
		return;
	}

	if (!outData) {
		fprintf(stdout, "outData is null.");
		return;
	}

	char* tmpIeauthregmsg = NULL;
	tmpIeauthregmsg = calloc(outDataLen + 1, sizeof(char));
	memcpy(tmpIeauthregmsg, outData, outDataLen);

	if (outData)
		free(outData);

	fprintf(stdout, "-==-\n");
	fprintf(stdout, "auth req receive data : %s \n", tmpIeauthregmsg);
	fprintf(stdout, "-==-\n");
	/*tmpIeauthregmsg 값은 MTS앱에 전달한다.*/

	if (tmpIeauthregmsg)
		free(tmpIeauthregmsg);

	fprintf(stdout, "  -- 2-2.  authentication response \n");
	memset(targetUrl, 0x00, sizeof(targetUrl));
	sprintf(targetUrl, "%s%s", SERVERADDR, AUTHENTICATIONRESPONSESUBURL);

	char *outRespData = NULL;
	size_t outRespDataLen = 0;

	revChk = registrationResponseWithJson((char*)targetUrl, (char*)TEST_AUTH_RESP_JSMSG, &outRespData, &outRespDataLen);
	/* 리턴값에 0x00이 들어있을수 있어, outRespDataLen을 같이 리턴됨*/
	if (revChk) {
		fprintf(stdout, "A communication error with the server occurred when calling the registrationResponseWithJson function.");
		if (outRespData)
			free(outRespData);
		return;
	}

	if (!outRespData) {
		fprintf(stdout, "outRespData is null.");
		return;
	}
	char* tmpIeauthrespmsg = NULL;
	tmpIeauthrespmsg = calloc(outRespDataLen + 1, sizeof(char));
	memcpy(tmpIeauthrespmsg, outRespData, outRespDataLen);

	if (outRespData)
		free(outRespData);

	fprintf(stdout, "-==-\n");
	fprintf(stdout, "auth response receive data : %s \n", tmpIeauthrespmsg);
	fprintf(stdout, "-==-\n");
	/*tmpIeauthrespmsg 값은 MTS앱에 전달한다.*/

	if (tmpIeauthrespmsg)
		free(tmpIeauthrespmsg);

}

/*
3. Fido transaction confirmation test.
*/
void transactionconfirmation_test() {
	size_t ret = 1;
	size_t revChk = 0;
	char *outData = NULL;
	size_t outDataLen = 0;
	char targetUrl[128];
	fprintf(stdout, "== 3. FIDO transaction confirmation Test. ==\n");

	/*Environment file initialization settings.*/
	ret = Init(PATH);
	if (ret) {
		fprintf(stdout, "Check the UafMtsSdk environment file information. \n");
		return;
	}

	/*3-1. transaction confirmation request*/
	fprintf(stdout, "  -- 3-1. transaction confirmation request \n");
	memset(targetUrl, 0x00, sizeof(targetUrl));
	sprintf(targetUrl, "%s%s", SERVERADDR, TRANSACTIONREQUESTSUBURL);
	/*TEST_AUTHTC_REQ_JSMSG 샘플 메시지*/
	revChk = transactionConfirmationRequestWithJson((char*)targetUrl, (char*)TEST_AUTHTC_REQ_JSMSG, &outData, &outDataLen);
	/* 리턴값에 0x00이 들어있을수 있어, outDataLen을 같이 리턴됨*/
	if (revChk) {
		fprintf(stdout, "A communication error with the server occurred when calling the transactionConfirmationRequestWithJson function.");
		if (outData)
			free(outData);
		return;
	}

	if (!outData) {
		fprintf(stdout, "outData is null.");
		return;
	}

	char* tmpIetcregmsg = NULL;
	tmpIetcregmsg = calloc(outDataLen + 1, sizeof(char));
	memcpy(tmpIetcregmsg, outData, outDataLen);

	if (outData)
		free(outData);

	fprintf(stdout, "-==-\n");
	fprintf(stdout, "transaction confirmation req receive data : %s \n", tmpIetcregmsg);
	fprintf(stdout, "-==-\n");
	/*tmpIeauthregmsg 값은 MTS앱에 전달한다.*/

	if (tmpIetcregmsg)
		free(tmpIetcregmsg);

	fprintf(stdout, "  -- 3-2.  transaction confirmation response \n");
	memset(targetUrl, 0x00, sizeof(targetUrl));
	sprintf(targetUrl, "%s%s", SERVERADDR, TRANSACTIONRESPONSESUBURL);

	char *outRespData = NULL;
	size_t outRespDataLen = 0;

	revChk = transactionConfirmationResponseWithJson((char*)targetUrl, (char*)TEST_AUTHTC_RESP_JSMSG, &outRespData, &outRespDataLen);
	/* 리턴값에 0x00이 들어있을수 있어, outRespDataLen을 같이 리턴됨*/
	if (revChk) {
		fprintf(stdout, "A communication error with the server occurred when calling the transactionconfirmationResponseWithJson function.");
		if (outRespData)
			free(outRespData);
		return;
	}

	if (!outRespData) {
		fprintf(stdout, "outRespData is null.");
		return;
	}
	char* tmpIetcrespmsg = NULL;
	tmpIetcrespmsg = calloc(outRespDataLen + 1, sizeof(char));
	memcpy(tmpIetcrespmsg, outRespData, outRespDataLen);

	if (outRespData)
		free(outRespData);

	fprintf(stdout, "-==-\n");
	fprintf(stdout, "transaction confirmation response receive data : %s \n", tmpIetcrespmsg);
	fprintf(stdout, "-==-\n");
	/*tmpIeauthrespmsg 값은 MTS앱에 전달한다.*/

	if (tmpIetcrespmsg)
		free(tmpIetcrespmsg);

}
/*
4. Fido simple authentication test.
*/
void simpleauthentication_test() {

	size_t ret = 1;
	size_t revChk = 0;
	char *outData = NULL;
	size_t outDataLen = 0;
	char targetUrl[128];
	fprintf(stdout, "== 4. FIDO simple authentication Test. ==\n");

	/*Environment file initialization settings.*/
	ret = Init(PATH);
	if (ret) {
		fprintf(stdout, "Check the UafMtsSdk environment file information. \n");
		return;
	}

	/*4-1. simple authentication request*/
	fprintf(stdout, "  -- 4-1. simple authentication request \n");
	memset(targetUrl, 0x00, sizeof(targetUrl));
	sprintf(targetUrl, "%s%s", SERVERADDR, SIMPLEAUTHREQUESTSUBURL);
	const char* nonid64enc = "bm9uaWR0ZXN0";
	/*TEST_AUTH_REQ_JSMSG 샘플 메시지*/
	revChk = simpleAuthRequestWithJson((char*)targetUrl, (char*)TEST_SIMPLE_REQ_JSMSG, (char*)nonid64enc, &outData, &outDataLen);
	/* 리턴값에 0x00이 들어있을수 있어, outDataLen을 같이 리턴됨*/
	if (revChk) {
		fprintf(stdout, "A communication error with the server occurred when calling the simpleAuthRequestWithJson function.");
		if (outData)
			free(outData);
		return;
	}

	if (!outData) {
		fprintf(stdout, "outData is null.");
		return;
	}

	char* tmpIeauthregmsg = NULL;
	tmpIeauthregmsg = calloc(outDataLen + 1, sizeof(char));
	memcpy(tmpIeauthregmsg, outData, outDataLen);

	if (outData)
		free(outData);

	fprintf(stdout, "-==-\n");
	fprintf(stdout, "simple auth req receive data : %s \n", tmpIeauthregmsg);
	fprintf(stdout, "-==-\n");
	/*tmpIeauthregmsg 값은 MTS앱에 전달한다.*/

	if (tmpIeauthregmsg)
		free(tmpIeauthregmsg);

	fprintf(stdout, "  -- 4-2.  simple authentication response \n");
	memset(targetUrl, 0x00, sizeof(targetUrl));
	sprintf(targetUrl, "%s%s", SERVERADDR, SIMPLEAUTHRESPONSESUBURL);

	char *outRespData = NULL;
	size_t outRespDataLen = 0;

	revChk = simpleAuthResponseWithJson((char*)targetUrl, (char*)TEST_SIMPLE_RESP_JSMSG, &outRespData, &outRespDataLen);
	/* 리턴값에 0x00이 들어있을수 있어, outRespDataLen을 같이 리턴됨*/
	if (revChk) {
		fprintf(stdout, "A communication error with the server occurred when calling the simpleAuthResponseWithJson function.");
		if (outRespData)
			free(outRespData);
		return;
	}

	if (!outRespData) {
		fprintf(stdout, "outRespData is null.");
		return;
	}
	char* tmpIeauthrespmsg = NULL;
	tmpIeauthrespmsg = calloc(outRespDataLen + 1, sizeof(char));
	memcpy(tmpIeauthrespmsg, outRespData, outRespDataLen);

	if (outRespData)
		free(outRespData);

	fprintf(stdout, "-==-\n");
	fprintf(stdout, "simple auth response receive data : %s \n", tmpIeauthrespmsg);
	fprintf(stdout, "-==-\n");
	/*tmpIeauthrespmsg 값은 MTS앱에 전달한다.*/

	if (tmpIeauthrespmsg)
		free(tmpIeauthrespmsg);
}

/*
 5. deregistration test
*/
void deregistration_test() {
	size_t ret = 1;
	size_t revChk = 0;
	char *outData = NULL;
	size_t outDataLen = 0;
	char targetUrl[128];
	fprintf(stdout, "== 1. FIDO deregistration Test. ==\n");

	/*Environment file initialization settings.*/

	ret = Init(PATH);
	if (ret) {
		fprintf(stdout, "Check the UafMtsSdk environment file information. \n");
		return;
	}

	/*1-1. registration request*/
	fprintf(stdout, "  -- 1-1. deregistration request \n");
	memset(targetUrl, 0x00, sizeof(targetUrl));
	sprintf(targetUrl, "%s%s", SERVERADDR, DEREGISTRATIONREQUESTSUBURL);
	/*js_deregreqmsg 샘플 메시지*/
	revChk = deregistrationRequestWithJson((char*)targetUrl, (char*)TEST_DEREG_REQ_JSMSG, &outData, &outDataLen);
	/* 리턴값에 0x00이 들어있을수 있어, outDataLen을 같이 리턴됨*/
	if (revChk) {
		fprintf(stdout, "A communication error with the server occurred when calling the deregistrationRequestWithJson function.");
		if (outData)
			free(outData);
		return;
	}

	if (!outData) {
		fprintf(stdout, "outData is null.");
		return;
	}
	char* tmpIeregregmsg = NULL;
	tmpIeregregmsg = calloc(outDataLen + 1, sizeof(char));
	memcpy(tmpIeregregmsg, outData, outDataLen);

	if (outData)
		free(outData);
	fprintf(stdout, "-==-\n");
	fprintf(stdout, "reg req receive data : %s \n", tmpIeregregmsg);
	fprintf(stdout, "-==-\n");
	/*tmpIeregregmsg 값은 MTS앱에 전달한다.*/

	if (tmpIeregregmsg)
		free(tmpIeregregmsg);
}

void getPubKeyTest() {
	char targetUrl[128];
	char *outData = NULL;
	size_t outDataLen = 0;

	const char *js_regreqmsg = "{\"version\": \"1.0\", \"source\": 4, \"target\": 8, \"operation\": \"auth\", \"authenticationmode\": \"3\", \"userid\": \"test01\", \"appid\": \"https://211.236.246.77:9024/appid\", \"rpwebsession\": \"0b4e7edd5634486cbb5bd8dd9e4ab43c\"}";
	size_t revChk = 0;

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

	

	/*char* chpErrorcode = getErrorCode(tmpResult);*/
	char* chpErrorcode = getErrorCode(TESTSIMREQMSG);
	
	if (!chpErrorcode) {
		fprintf(stdout, "chpErrorcode is NULL. \n");
		return;
	}
	if (strcmp((char*)SUCCESS_STR, chpErrorcode) != 0){
		/*error*/
		fprintf(stdout, "chpErrorcode : %s \n", chpErrorcode);
		if (chpErrorcode)
			retDataFree(chpErrorcode);

		return;
	}

	unsigned char *outPubKey = NULL;
	size_t outPubKeyLen;
	/*ret = getPubKeyFromExtention(tmpResult, &outPubKey, &outPubKeyLen);*/
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
	registration_test();
	/*
	authentication_test();
	transactionconfirmation_test();
	simpleauthentication_test();
	deregistration_test();
	getPubKeyTest();
	*/

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


	/*registrationResponse 테스트*/
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

	/*registrationResponseWithJson 테스트*/
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

	/*authenticationRequest*/
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


	/*authenticationResponseWithJson */
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

	/*authenticationResponse*/
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

	/*authenticationResponseWithJson*/
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

	/*transactionConfirmationRequest*/
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

	/*transactionConfirmationRequestWithJson*/
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

	/*transactionConfirmationResponse*/
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


	/*transactionConfirmationResponseWithJson*/
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

	/*simpleAuthRequest*/
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
	
	/*
	simpleAuthRequestWithJson
	size_t simpleAuthRequestWithJson(char *targetUrl, char *jsmsg, char *b64nonid, char **outData, size_t *outDataLen);
	*/
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
	/*
	simpleAuthResponse
	size_t simpleAuthResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char **outData, size_t *outDataLen);
	*/
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

	/*simpleAuthResponseWithJson*/
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
	/*
	deregistrationRequest	
	size_t deregistrationRequest(char *targetUrl, char *userid, char *appid, char **outData, size_t *outDataLen);
	*/
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

	/*deregistrationRequestWithJson*/
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