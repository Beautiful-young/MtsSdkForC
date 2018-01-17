
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libconfig.h>
#include <jansson.h>
#include "UafMtsSdk.h"
#include "common.h"
#include "commonDef.h"
#include "httputill.h"
#include "InternalJsonMessage.h"

static char SSL_PEMCERT_PATH_UAFSDK[128];
static char LOG_USAGE_UAFSDK[4];
static char LOG_PATH_UAFSDK[128];

int Init(const char *path) {
	static int once = 0; /* 한번만 호출, 지킴이 변수 */
	if (once) return 1;

	config_t cfg;
	config_setting_t *setting;
	const char *str_ssl_pemcert_path_uafsdk;
	const char *str_log_usage_uafsdk;
	const char *str_log_path_uafsdk;

	config_init(&cfg);

	if (!config_read_file(&cfg, path))
	{
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
			config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return 2;
	}

	memset(SSL_PEMCERT_PATH_UAFSDK, 0x00, 128);
	memset(LOG_USAGE_UAFSDK, 0x00, 4);
	memset(LOG_PATH_UAFSDK, 0x00, 128);

	//ssl cert
	if (config_lookup_string(&cfg, "SSL_PEMCERT_PATH_UAFSDK", &str_ssl_pemcert_path_uafsdk)) {
		printf("SSL_PEMCERT_PATH_UAFSDK : %s\n\n", str_ssl_pemcert_path_uafsdk);
		strcpy(SSL_PEMCERT_PATH_UAFSDK, str_ssl_pemcert_path_uafsdk);

	}
	else {
		fprintf(stderr, "No 'SSL_PEMCERT_PATH_UAFSDK' setting in configuration file.\n");
		return 3;
	}

	//log usage 'yes' or 'no'
	if (config_lookup_string(&cfg, "LOG_USAGE_UAFSDK", &str_log_usage_uafsdk)) {
		printf("LOG_USAGE_UAFSDK : %s\n\n", str_log_usage_uafsdk);
		strcpy(LOG_USAGE_UAFSDK, str_log_usage_uafsdk);
	}
	else {
		fprintf(stderr, "No 'LOG_USAGE_UAFSDK' setting in configuration file.\n");
		return 4;
	}

	//log path
	if (config_lookup_string(&cfg, "LOG_PATH_UAFSDK", &str_log_path_uafsdk)) {
		printf("LOG_PATH_UAFSDK : %s\n\n", str_log_path_uafsdk);
		strcpy(LOG_PATH_UAFSDK, str_log_path_uafsdk);
	}
	else {
		fprintf(stderr, "No 'LOG_PATH_UAFSDK' setting in configuration file.\n");
		return 4;
	}
	once = 1;
	config_destroy(&cfg);
	return 0;
}

/*
0. 공통 오류
*/
char* getCommonErrMsg(const char* operation) {
	char *retMsg = NULL;
	char *jsmsg = NULL;
	json_t *root = json_object();

	json_object_set_new(root, "version", json_string(INTERNALVERSION));
	json_object_set_new(root, "source", json_integer(DIRECTION_FIDOSERVERAGENT));
	json_object_set_new(root, "target", json_integer(DIRECTION_FIDOCLIENT));
	json_object_set_new(root, "operation", json_string(operation));
	json_object_set_new(root, "errorcode", json_string("0200F000"));
	json_object_set_new(root, "errormessage", json_string("0x$Communication to agnet server failed."));
	jsmsg = json_dumps(root, 0);
	
	retMsg = (char*)calloc(strlen(jsmsg), sizeof(char));
	memcpy(retMsg, jsmsg, strlen(jsmsg));

	json_decref(root);

	return retMsg;
}

/*
1. registrationRequest
*/
size_t registrationRequest(char *targetUrl, char *userid, char *appid, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	char rpwebsession[38];
	size_t rc;
	rc = getSessionID(rpwebsession);
	char *jsmsg = NULL;
	json_t *root = json_object();

	json_object_set_new(root, "version", json_string(INTERNALVERSION));
	json_object_set_new(root, "source", json_integer(DIRECTION_FIDOSDK));
	json_object_set_new(root, "target", json_integer(DIRECTION_FIDOSERVERAGENT));
	json_object_set_new(root, "operation", json_string(OPERATION_REG));

	json_object_set_new(root, "userid", json_string(userid));
	json_object_set_new(root, "appid", json_string(appid));
	json_object_set_new(root, "rpwebsession", json_string(rpwebsession));

	jsmsg = json_dumps(root, 0);
	fprintf(stdout, "jsmsg : %s\n", jsmsg);
	
	boolean revChk;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	revChk = httpsPost(SSL_PEMCERT_PATH_UAFSDK, targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);
	retVal = revChk;

	if(revChk && outDataTmp && outDataLenTmp > 0){
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);

		retHttpDataFree(outDataTmp);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_REG);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if(temErrMsg)
			free(temErrMsg);
	}
	
	json_decref(root);
	return retVal;
}

void retDataFree(char *msg) {
	if(msg)
		free(msg);
}

int main(void) {
	const char *path = "E:\\env_common\\UAF\\koscom_it\\client\\env\\uafsdk\\uafsdk4c.properties";
	const char *targetUrl = "https://fido.signkorea.com:9033/registrationrequestfromfc";
	const char *userid="test01";
	const char *appid="https://211.236.246.77:9024/appid";

	size_t ret;
	ret = Init(path);

	boolean revChk = false;
	char *outData = NULL;
	size_t outDataLen = 0;


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

	system("pause");
}