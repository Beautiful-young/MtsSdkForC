
#include "UafMtsSdk.h"
#include "commonDef.h"
#include "logutill.h"



int Init(const char *path) {
	static int once = 0; /* 한번만 호출, 지킴이 변수 */
	if (once) return 1;

	config_t cfg;
	//config_setting_t *setting;
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

	initlogutillPath(LOG_PATH_UAFSDK, LOG_USAGE_UAFSDK);

	once = 1;
	config_destroy(&cfg);
	return 0;
}


/*
오류코드 리턴
*/
char* getErrorCode(const char *input) {
	char *reterrorcode = NULL;
	json_t *request = NULL;
	json_error_t error;

	request = json_loads(input, 0, &error);

	if (!request) {
		fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
		return NULL;
	}

	if (!json_is_object(request)) {
		fprintf(stderr, "error : commit data is not an object\n");
		return NULL;
	}

	json_t *errorcode = json_object_get(request, "errorcode");
	if (!json_is_string(errorcode)) {
		fprintf(stderr, "error: request errorcode is null.\n");
	}
	else {
		const char *errorcode_val = (char*)json_string_value(errorcode);
		size_t errorcode_len = strlen(errorcode_val);
		reterrorcode = (char*)calloc(errorcode_len + 1, sizeof(char));
		memcpy(reterrorcode, errorcode_val, errorcode_len);
		fprintf(stdout, "errorcode : %s\n", reterrorcode);
	}

	json_decref(request);

	return reterrorcode;
}

/*
내부 메시지로 부터 공개키 리턴 
*/
size_t getPubKey(const char *input, unsigned char **outPubKey, size_t *outPubKeyLen) {
	size_t nRet = 0;

	json_t *request = NULL;
	json_error_t error;

	request = json_loads(input, 0, &error);

	if (!request) {
		fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
		return 1;
	}

	if (!json_is_object(request)) {
		fprintf(stderr, "error : commit data is not an object\n");
		return 1;
	}

	json_t *b64pk = json_object_get(request, "b64pk");
	if (!json_is_string(b64pk)) {
		fprintf(stderr, "error: request b64pk is null.\n");
		nRet = 1;
	}
	else {
		const char* b64pk_val = json_string_value(b64pk);
		size_t b64pk_len = strlen(b64pk_val);
		size_t ret;
		*outPubKeyLen = b64pk_len;
		*outPubKey = (unsigned char*)calloc(*outPubKeyLen, sizeof(char));

		ret = Base64Url_Decode((const unsigned char*)b64pk_val, b64pk_len, *outPubKey, outPubKeyLen);

		if (ret) {
			fprintf(stderr, "Base64 Decoding Error..");
		}

		/*
		ijmess->b64pk = (char*)calloc(b64pk_len + 1, sizeof(char));
		memcpy(ijmess->b64pk, b64pk_val, b64pk_len);
		fprintf(stdout, "b64pk : %s\n", ijmess->b64pk);
		*/
	}

	json_decref(request);

	return nRet;
}

/*
Extention으로 부터 공개키 리턴 
*/
size_t getPubKeyFromExtention(const char *input, unsigned char **outPubKey, size_t *outPubKeyLen) {
	size_t nRet = 0;

	json_t *request = NULL;
	json_error_t error;

	request = json_loads(input, 0, &error);

	if (!request) {
		fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
		return 1;
	}

	if (!json_is_object(request)) {
		fprintf(stderr, "error : commit data is not an object\n");
		return 1;
	}

	json_t *b64authreqmsg = json_object_get(request, "authrequestmsg");
	if (!json_is_string(b64authreqmsg)) {
		fprintf(stderr, "error: authrequestmsg is null.\n");
		json_decref(request);
		return 1;
	}
	else {
		const char*b64authreqmsg_val = json_string_value(b64authreqmsg);
		size_t b64authreqmsg_len = strlen(b64authreqmsg_val);
		size_t ret;
		char *outauthreqmsg=NULL;
		size_t outauthreqmsg_len;

		ret = Base64Url_Decode((const unsigned char*)b64authreqmsg_val, b64authreqmsg_len, &outauthreqmsg, &outauthreqmsg_len);

		if (ret) {
			fprintf(stderr, "Base64 Decoding Error..");
			json_decref(request);
			return 1;
		}

		json_t *authRequestRead = NULL;
		json_t *authRequest_dec = NULL;

		json_t *header_dec = NULL;//object
		json_t *challenge_dec = NULL;//string
		json_t *transaction_dec = NULL;//array
		json_t *policy_dec = NULL;//object

		json_t *upv_dec = NULL;
		json_t *op_dec = NULL;
		json_t *appID_dec = NULL;
		json_t *serverData_dec = NULL;
		json_t *exts_dec = NULL;

		json_t *authRequestWriter = NULL;
		json_t *authRequest_enc = NULL;

		json_t *header_enc = NULL;//object

								  //extention 설정
		json_t *exts_list_enc = NULL;
		json_t *exts_enc_simplekey = NULL;
		json_t *exts_enc_devid = NULL;
		json_t *exts_enc_nonid = NULL;

		json_error_t error;
		size_t authReqSize;
		// json 
		authRequestRead = json_loads((const char*)outauthreqmsg, 0, &error);

		if (!authRequestRead) {
			fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);

			if (outauthreqmsg)
				free(outauthreqmsg);

			json_decref(request);
			return 1;
		}

		if (!json_is_object(authRequestRead)) {
			fprintf(stderr, "error : commit data is not an object\n");
			
			if (outauthreqmsg)
				free(outauthreqmsg);

			json_decref(authRequestRead);

			json_decref(request);
			return 1;
		}

		authReqSize = json_array_size(authRequestRead);

		fprintf(stdout, "authReqSize : %d", authReqSize);

		if (authReqSize < 1) {
			fprintf(stderr, "error : authRequestRead array size is invalid.");

			if (outauthreqmsg)
				free(outauthreqmsg);
			json_decref(authRequestRead);
			json_decref(request);
			
			return 1;
		}

		authRequest_dec = json_array_get(authRequestRead, 0);

		if (!json_is_object(authRequest_dec)) {
			fprintf(stderr, "error : authRequest_dec is not object.");


			if (outauthreqmsg)
				free(outauthreqmsg);
			json_decref(authRequestRead);
			json_decref(request);

			return 1;
		}

		header_dec = json_object_get(authRequest_dec, "header");

		if (!json_is_object(header_dec)) {
			fprintf(stderr, "header_dec is not an object\n");

			if (outauthreqmsg)
				free(outauthreqmsg);
			
			json_decref(authRequest_dec);
			json_decref(authRequestRead);
			json_decref(request);
			return 1;
		}

		exts_dec = json_object_get(header_dec, "exts");
		
		if (!json_is_object(exts_dec)) {
			fprintf(stderr, "exts_dec is not an object\n");
			if (outauthreqmsg)
				free(outauthreqmsg);

			json_decref(header_dec);
			json_decref(authRequest_dec);
			json_decref(authRequestRead);
			json_decref(request);
			return 1;
		}
		
		size_t exts_dec_arr_len = json_array_size(exts_dec);

		if (exts_dec_arr_len < 1) {
			fprintf(stderr, "error : header_dec array size is invalid.");

			if (outauthreqmsg)
				free(outauthreqmsg);

			json_decref(exts_dec);

			json_decref(header_dec);
			json_decref(authRequest_dec);
			json_decref(authRequestRead);
			json_decref(request);

			return 1;
		}
		
		json_t *exts_list_dec = NULL;

		for (int i = 0; i < exts_dec_arr_len; i++) {
			exts_list_dec = json_array_get(exts_dec, i);
			if (!json_is_object(exts_list_dec)) {
				continue;
			}else {
				json_t *exts_id = json_object_get(exts_list_dec,"id");

				if (!json_is_object(exts_id)) {
					json_decref(exts_list_dec);
					continue;
				}
				else {
					if (!json_is_string(exts_id)) {
						json_decref(exts_id);
						json_decref(exts_list_dec);
						continue;
					}
					else {
						json_t *exts_id_tmp = json_string_value(exts_id);
						if (strcmp(exts_id_tmp, "simplepubkey") == 0) {//공개키 리턴 처리
							json_t *exts_data = json_object_get(exts_list_dec, "data");

							if (!json_is_object(exts_data)) {
								if (exts_id_tmp)
									free(exts_id_tmp);
								json_decref(exts_id);
								json_decref(exts_list_dec);
								continue;
							}

							if (!json_is_string(exts_data)) {
								if (exts_id_tmp)
									free(exts_id_tmp);
								json_decref(exts_data);
								json_decref(exts_id);
								json_decref(exts_list_dec);
								continue;
							}

							const char *exts_data_val = json_string_value(exts_data);
							if (exts_data_val) {
								size_t exts_data_val_len = strlen(exts_data_val);
								size_t ret_tmp;

								*outPubKeyLen = outauthreqmsg_len;
								*outPubKey = (unsigned char*)calloc(outauthreqmsg_len, sizeof(char));

								ret_tmp = Base64Url_Decode((const unsigned char*)exts_data_val, exts_data_val_len, *outPubKey, outPubKeyLen);

								if (ret_tmp) {
									if (exts_id_tmp)
										free(exts_id_tmp);

									json_decref(exts_data_val);

									json_decref(exts_data);
									json_decref(exts_id);
									json_decref(exts_list_dec);

									if (outauthreqmsg)
										free(outauthreqmsg);

									json_decref(exts_dec);

									json_decref(header_dec);
									json_decref(authRequest_dec);
									json_decref(authRequestRead);
									json_decref(request);

									return 1;
								}
								else {
									

									if (exts_id_tmp)
										free(exts_id_tmp);

									json_decref(exts_data_val);

									json_decref(exts_data);
									json_decref(exts_id);
									json_decref(exts_list_dec);

									if (outauthreqmsg)
										free(outauthreqmsg);

									json_decref(exts_dec);

									json_decref(header_dec);
									json_decref(authRequest_dec);
									json_decref(authRequestRead);
									json_decref(request);

									return 0;

								}
							}
							else {
								if (exts_id_tmp)
									free(exts_id_tmp);
								json_decref(exts_data);
								json_decref(exts_id);
								json_decref(exts_list_dec);
								continue;

							}


						}
						else {
							if (exts_id_tmp)
								free(exts_id_tmp);
							json_decref(exts_id);
							json_decref(exts_list_dec);
							continue;
						}
					}
				}



			}



		}

		/*
		*outPubKeyLen = b64pk_len;
		*outPubKey = (unsigned char*)calloc(*outPubKeyLen, sizeof(char));

		ret = Base64Url_Decode((const unsigned char*)b64pk_val, b64pk_len, *outPubKey, outPubKeyLen);

		if (ret) {
			fprintf(stderr, "Base64 Decoding Error..");
		}
		*/
		/*
		ijmess->b64pk = (char*)calloc(b64pk_len + 1, sizeof(char));
		memcpy(ijmess->b64pk, b64pk_val, b64pk_len);
		fprintf(stdout, "b64pk : %s\n", ijmess->b64pk);
		*/
	}

	json_decref(request);

	return nRet;
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
등록요청
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

/*
1-1. registrationRequestWithJson
등록요청 입력 파라미터 json String 
*/
size_t registrationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen) {
	size_t retVal = 0;

	InternalJsonMessage *itjsmsg = parse(jsmsg);

	if (itjsmsg) {
		char *outDataTmp = NULL;
		size_t outDataLenTmp = 0;
		char *userid = itjsmsg->userid;
		char *appid = itjsmsg->appid;
		retVal = registrationRequest(targetUrl, userid, appid, &outDataTmp, &outDataLenTmp);
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);
		retDataFree(outDataTmp);
		internalJsonMessageRelease(itjsmsg);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_REG);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	return retVal;
}



/*
2. registrationResponse
 등록 검증
*/
size_t registrationResponse(char *targetUrl, char *appid, char *sessionid, char *b64regresp, char **outData, size_t *outDataLen) {
	size_t retVal = 0;

	char *jsmsg = NULL;
	json_t *root = json_object();

	json_object_set_new(root, "version", json_string(INTERNALVERSION));
	json_object_set_new(root, "source", json_integer(DIRECTION_FIDOSDK));
	json_object_set_new(root, "target", json_integer(DIRECTION_FIDOSERVERAGENT));
	json_object_set_new(root, "operation", json_string(OPERATION_REG));

	json_object_set_new(root, "appid", json_string(appid));
	json_object_set_new(root, "sessionid", json_string(sessionid));
	json_object_set_new(root, "regresponsemsg", json_string(b64regresp));

	jsmsg = json_dumps(root, 0);
	fprintf(stdout, "jsmsg : %s\n", jsmsg);

	boolean revChk;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	revChk = httpsPost(SSL_PEMCERT_PATH_UAFSDK, targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);
	retVal = revChk;

	if (revChk && outDataTmp && outDataLenTmp > 0) {
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

		if (temErrMsg)
			free(temErrMsg);
	}

	json_decref(root);

	return retVal;
}

/*
2-1. registrationResponseWithJson
등록 검증 입력 파라미터 json String 
*/
size_t registrationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	InternalJsonMessage *itjsmsg = parse(jsmsg);

	if (itjsmsg) {
		char *outDataTmp = NULL;
		size_t outDataLenTmp = 0;
		char *appid = itjsmsg->appid;
		char *sessionid = itjsmsg->sessionid;
		char *regresponsemsg = itjsmsg->regrequestmsg;


		retVal = registrationResponse(targetUrl, appid, sessionid, regresponsemsg, &outDataTmp, &outDataLenTmp);
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);
		retDataFree(outDataTmp);
		internalJsonMessageRelease(itjsmsg);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_REG);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	return retVal;
}


/*
3. authenticationRequest
인증요청
*/
size_t authenticationRequest(char *targetUrl, char *userid, char *appid, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	char rpwebsession[38];
	size_t rc;
	rc = getSessionID(rpwebsession);
	char *jsmsg = NULL;
	json_t *root = json_object();

	json_object_set_new(root, "version", json_string(INTERNALVERSION));
	json_object_set_new(root, "source", json_integer(DIRECTION_FIDOSDK));
	json_object_set_new(root, "target", json_integer(DIRECTION_FIDOSERVERAGENT));
	json_object_set_new(root, "operation", json_string(OPERATION_AUTH));
	json_object_set_new(root, "authenticationmode", json_string(AUTHENTICATIONMODE_AUTH));

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

	if (revChk && outDataTmp && outDataLenTmp > 0) {
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);

		retHttpDataFree(outDataTmp);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	json_decref(root);
	return retVal;
}


/*
3-1. authenticationRequestWithJson
인증요청 입력 파라미터 json String
*/
size_t authenticationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen) {
	size_t retVal = 0;

	InternalJsonMessage *itjsmsg = parse(jsmsg);

	if (itjsmsg) {
		char *outDataTmp = NULL;
		size_t outDataLenTmp = 0;
		char *userid = itjsmsg->userid;
		char *appid = itjsmsg->appid;
		retVal = authenticationRequest(targetUrl, userid, appid, &outDataTmp, &outDataLenTmp);
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);
		retDataFree(outDataTmp);
		internalJsonMessageRelease(itjsmsg);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	return retVal;
}

/*
4. authenticationResponse
인증검증
*/
size_t authenticationResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char **outData, size_t *outDataLen) {
	size_t retVal = 0;

	char *jsmsg = NULL;
	json_t *root = json_object();

	json_object_set_new(root, "version", json_string(INTERNALVERSION));
	json_object_set_new(root, "source", json_integer(DIRECTION_FIDOSDK));
	json_object_set_new(root, "target", json_integer(DIRECTION_FIDOSERVERAGENT));
	json_object_set_new(root, "operation", json_string(OPERATION_AUTH));
	json_object_set_new(root, "authenticationmode", json_string(AUTHENTICATIONMODE_AUTH));

	json_object_set_new(root, "appid", json_string(appid));
	json_object_set_new(root, "sessionid", json_string(sessionid));
	json_object_set_new(root, "authresponsemsg", json_string(b64authresp));

	jsmsg = json_dumps(root, 0);
	fprintf(stdout, "jsmsg : %s\n", jsmsg);

	boolean revChk;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	revChk = httpsPost(SSL_PEMCERT_PATH_UAFSDK, targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);
	retVal = revChk;

	if (revChk && outDataTmp && outDataLenTmp > 0) {
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);

		retHttpDataFree(outDataTmp);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	json_decref(root);

	return retVal;
}

/*
4-1. authenticationResponsWithJson
인증검증 (입력 파라미터 json String)
*/
size_t authenticationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	InternalJsonMessage *itjsmsg = parse(jsmsg);

	if (itjsmsg) {
		char *outDataTmp = NULL;
		size_t outDataLenTmp = 0;
		char *appid = itjsmsg->appid;
		char *sessionid = itjsmsg->sessionid;
		char *authresponsemsg = itjsmsg->authresponsemsg;


		retVal = authenticationResponse(targetUrl, appid, sessionid, authresponsemsg, &outDataTmp, &outDataLenTmp);
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);
		retDataFree(outDataTmp);
		internalJsonMessageRelease(itjsmsg);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	return retVal;
}


/*
5. transactionConfirmationRequest
transaction confirmation 요청
*/
size_t transactionConfirmationRequest(char *targetUrl, char *userid, char *appid
	, char *contentType, char *contentEncodingType, char *content, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	char rpwebsession[38];
	size_t rc;
	rc = getSessionID(rpwebsession);
	char *jsmsg = NULL;
	json_t *root = json_object();

	json_object_set_new(root, "version", json_string(INTERNALVERSION));
	json_object_set_new(root, "source", json_integer(DIRECTION_FIDOSDK));
	json_object_set_new(root, "target", json_integer(DIRECTION_FIDOSERVERAGENT));
	json_object_set_new(root, "operation", json_string(OPERATION_AUTH));
	json_object_set_new(root, "authenticationmode", json_string(AUTHENTICATIONMODE_TC));

	json_object_set_new(root, "userid", json_string(userid));
	json_object_set_new(root, "appid", json_string(appid));
	json_object_set_new(root, "contentType", json_string(contentType));
	json_object_set_new(root, "contentEncodingType", json_string(contentEncodingType));
	json_object_set_new(root, "content", json_string(content));

	json_object_set_new(root, "rpwebsession", json_string(rpwebsession));

	jsmsg = json_dumps(root, 0);
	fprintf(stdout, "jsmsg : %s\n", jsmsg);

	boolean revChk;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	revChk = httpsPost(SSL_PEMCERT_PATH_UAFSDK, targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);
	retVal = revChk;

	if (revChk && outDataTmp && outDataLenTmp > 0) {
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);

		retHttpDataFree(outDataTmp);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	json_decref(root);
	return retVal;

}

/*
5-1. transactionConfirmationRequestWithJson
transaction confirmation 요청 (입력 파라미터 json string)
*/
size_t transactionConfirmationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen) {
	size_t retVal = 0;

	InternalJsonMessage *itjsmsg = parse(jsmsg);

	if (itjsmsg) {
		char *outDataTmp = NULL;
		size_t outDataLenTmp = 0;
		char *userid = itjsmsg->userid;
		char *appid = itjsmsg->appid;
		char *contentType = itjsmsg->contentType;
		char *contentEncodingType = itjsmsg->contentEncodingType;
		char *content = itjsmsg->content;

		retVal = transactionConfirmationRequest(targetUrl, userid, appid, contentType, contentEncodingType, content, &outDataTmp, &outDataLenTmp);

		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);
		retDataFree(outDataTmp);
		internalJsonMessageRelease(itjsmsg);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}
	return retVal;
}


/*
6. transactionConfirmationResponse
transaction confirmation 요청
*/
size_t transactionConfirmationResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char **outData, size_t *outDataLen) {
	size_t retVal = 0;

	char *jsmsg = NULL;
	json_t *root = json_object();

	json_object_set_new(root, "version", json_string(INTERNALVERSION));
	json_object_set_new(root, "source", json_integer(DIRECTION_FIDOSDK));
	json_object_set_new(root, "target", json_integer(DIRECTION_FIDOSERVERAGENT));
	json_object_set_new(root, "operation", json_string(OPERATION_AUTH));
	json_object_set_new(root, "authenticationmode", json_string(AUTHENTICATIONMODE_TC));

	json_object_set_new(root, "appid", json_string(appid));
	json_object_set_new(root, "sessionid", json_string(sessionid));
	json_object_set_new(root, "authresponsemsg", json_string(b64authresp));

	jsmsg = json_dumps(root, 0);
	fprintf(stdout, "jsmsg : %s\n", jsmsg);

	boolean revChk;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	revChk = httpsPost(SSL_PEMCERT_PATH_UAFSDK, targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);
	retVal = revChk;

	if (revChk && outDataTmp && outDataLenTmp > 0) {
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);

		retHttpDataFree(outDataTmp);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	json_decref(root);

	return retVal;
}


/*
6-1. transactionConfirmationResponseWithJson
transaction confirmation 요청 (입력 파라미터 json string)
*/
size_t transactionConfirmationResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	InternalJsonMessage *itjsmsg = parse(jsmsg);

	if (itjsmsg) {
		char *outDataTmp = NULL;
		size_t outDataLenTmp = 0;
		char *appid = itjsmsg->appid;
		char *sessionid = itjsmsg->sessionid;
		char *authresponsemsg = itjsmsg->authresponsemsg;

		retVal = transactionConfirmationResponse(targetUrl, appid, sessionid, authresponsemsg, &outDataTmp, &outDataLenTmp);
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);
		retDataFree(outDataTmp);
		internalJsonMessageRelease(itjsmsg);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	return retVal;
}


/*
7. simpleAuthRequest
단축서명요청
*/
size_t simpleAuthRequest(char *targetUrl, char *userid, char *appid, char *b64pubkey, char *b64nonid, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	char rpwebsession[38];
	size_t rc;
	rc = getSessionID(rpwebsession);
	char *jsmsg = NULL;
	json_t *root = json_object();

	json_object_set_new(root, "version", json_string(INTERNALVERSION));
	json_object_set_new(root, "source", json_integer(DIRECTION_FIDOSDK));
	json_object_set_new(root, "target", json_integer(DIRECTION_FIDOSERVERAGENT));
	json_object_set_new(root, "operation", json_string(OPERATION_AUTH));
	json_object_set_new(root, "authenticationmode", json_string(AUTHENTICATIONMODE_SS));

	json_object_set_new(root, "userid", json_string(userid));
	json_object_set_new(root, "appid", json_string(appid));
	json_object_set_new(root, "rpwebsession", json_string(rpwebsession));
	json_object_set_new(root, "b64pk", json_string(b64pubkey));
	
	jsmsg = json_dumps(root, 0);
	fprintf(stdout, "jsmsg : %s\n", jsmsg);

	boolean revChk;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	revChk = httpsPost(SSL_PEMCERT_PATH_UAFSDK, targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);
	retVal = revChk;

	if (revChk && outDataTmp && outDataLenTmp > 0) {
		
		InternalJsonMessage *itjsmsg = parse(outDataTmp);
		char *errorcodetmp = itjsmsg->errorcode;

		if (errorcodetmp != NULL && strcmp(errorcodetmp, E_TYPE_SUCCESS_STR) == 0) {

			char *authreqmsg = itjsmsg->authrequestmsg;
			char *convertAuthreqmsg = setExtensionAuthReqB64Url(authreqmsg, NULL, NULL, b64nonid);
			itjsmsg->authrequestmsg = convertAuthreqmsg;
			char *converitjsmsg = makeIJMessageToJson(itjsmsg);

			extensionAuthReqB64Url_free(convertAuthreqmsg);
			retHttpDataFree(outDataTmp);

			*outData = (char*)calloc(strlen(converitjsmsg) + 1, sizeof(char));
			*outDataLen = strlen(converitjsmsg);
			memcpy(*outData, converitjsmsg, strlen(converitjsmsg));
			jsonRetFree(converitjsmsg);
		}
		else {
			*outData = (char*)calloc(outDataLenTmp, sizeof(char));
			*outDataLen = outDataLenTmp;
			memcpy(*outData, outDataTmp, outDataLenTmp);

			retHttpDataFree(outDataTmp);
		}
		internalJsonMessageRelease(itjsmsg);
		
		/*
		InternalJsonMessage *itjsmsg = parse(outDataTmp);
		char *errorcodetmp = itjsmsg->errorcode;

		char *authreqmsg = itjsmsg->authrequestmsg;
		char *convertAuthreqmsg = setExtensionAuthReqB64Url(authreqmsg, NULL, NULL, b64nonid);
		itjsmsg->authrequestmsg = convertAuthreqmsg;
		char *converitjsmsg = makeIJMessageToJson(itjsmsg);

		extensionAuthReqB64Url_free(convertAuthreqmsg);
		retHttpDataFree(outDataTmp);

		*outData = (char*)calloc(strlen(converitjsmsg) + 1, sizeof(char));
		*outDataLen = strlen(converitjsmsg);
		memcpy(*outData, converitjsmsg, strlen(converitjsmsg));
		jsonRetFree(converitjsmsg);

		internalJsonMessageRelease(itjsmsg);
		*/
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	json_decref(root);
	return retVal;
}

/*
7-1. simpleAuthRequestWithJson
단축서명요청 (입력 파라미터 json String)
*/
size_t simpleAuthRequestWithJson(char *targetUrl, char *jsmsg, char *b64nonid, char **outData, size_t *outDataLen) {
	size_t retVal = 0;

	InternalJsonMessage *itjsmsg = parse(jsmsg);

	if (itjsmsg) {
		char *outDataTmp = NULL;
		size_t outDataLenTmp = 0;
		char *userid = itjsmsg->userid;
		char *appid = itjsmsg->appid;
		char *b64pubkey = itjsmsg->b64pk;

		retVal = simpleAuthRequest(targetUrl, userid, appid, b64pubkey, b64nonid,  &outDataTmp, &outDataLenTmp);
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);
		retDataFree(outDataTmp);
		internalJsonMessageRelease(itjsmsg);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	return retVal;
}


/*
8. simpleAuthResponse
단축서명 검증요청
*/
size_t simpleAuthResponse(char *targetUrl, char *appid, char *sessionid, char *b64authresp, char **outData, size_t *outDataLen) {
	size_t retVal = 0;

	char *jsmsg = NULL;
	json_t *root = json_object();

	json_object_set_new(root, "version", json_string(INTERNALVERSION));
	json_object_set_new(root, "source", json_integer(DIRECTION_FIDOSDK));
	json_object_set_new(root, "target", json_integer(DIRECTION_FIDOSERVERAGENT));
	json_object_set_new(root, "operation", json_string(OPERATION_AUTH));
	json_object_set_new(root, "authenticationmode", json_string(AUTHENTICATIONMODE_SS));

	json_object_set_new(root, "appid", json_string(appid));
	json_object_set_new(root, "sessionid", json_string(sessionid));
	json_object_set_new(root, "authresponsemsg", json_string(b64authresp));

	jsmsg = json_dumps(root, 0);
	fprintf(stdout, "jsmsg : %s\n", jsmsg);

	boolean revChk;
	char *outDataTmp = NULL;
	size_t outDataLenTmp = 0;

	revChk = httpsPost(SSL_PEMCERT_PATH_UAFSDK, targetUrl, jsmsg, &outDataTmp, &outDataLenTmp);
	retVal = revChk;

	if (revChk && outDataTmp && outDataLenTmp > 0) {
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);

		retHttpDataFree(outDataTmp);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	json_decref(root);

	return retVal;
}


/*
8-1. simpleAuthResponseWithJson
단축서명 검증요청 (입력 파라미터 json String)
*/
size_t simpleAuthResponseWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen) {
	size_t retVal = 0;
	InternalJsonMessage *itjsmsg = parse(jsmsg);

	if (itjsmsg) {
		char *outDataTmp = NULL;
		size_t outDataLenTmp = 0;
		char *appid = itjsmsg->appid;
		char *sessionid = itjsmsg->sessionid;
		char *authresponsemsg = itjsmsg->authresponsemsg;


		retVal = simpleAuthResponse(targetUrl, appid, sessionid, authresponsemsg, &outDataTmp, &outDataLenTmp);
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);
		retDataFree(outDataTmp);
		internalJsonMessageRelease(itjsmsg);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_AUTH);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	return retVal;
}

/*
9. deregistrationRequest
탈퇴요청
*/
size_t deregistrationRequest(char *targetUrl, char *userid, char *appid, char **outData, size_t *outDataLen) {

	size_t retVal = 0;
	char rpwebsession[38];
	size_t rc;
	rc = getSessionID(rpwebsession);
	char *jsmsg = NULL;
	json_t *root = json_object();

	json_object_set_new(root, "version", json_string(INTERNALVERSION));
	json_object_set_new(root, "source", json_integer(DIRECTION_FIDOSDK));
	json_object_set_new(root, "target", json_integer(DIRECTION_FIDOSERVERAGENT));
	json_object_set_new(root, "operation", json_string(OPERATION_DEREG));

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

	if (revChk && outDataTmp && outDataLenTmp > 0) {
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);

		retHttpDataFree(outDataTmp);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_DEREG);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	json_decref(root);
	return retVal;

}


/*
9-1. deregistrationRequestWithJson
탈퇴요청 (입력 파라미터 json String)
*/
size_t deregistrationRequestWithJson(char *targetUrl, char *jsmsg, char **outData, size_t *outDataLen) {
	size_t retVal = 0;

	InternalJsonMessage *itjsmsg = parse(jsmsg);

	if (itjsmsg) {
		char *outDataTmp = NULL;
		size_t outDataLenTmp = 0;
		char *userid = itjsmsg->userid;
		char *appid = itjsmsg->appid;
		retVal = deregistrationRequest(targetUrl, userid, appid, &outDataTmp, &outDataLenTmp);
		*outData = (char*)calloc(outDataLenTmp, sizeof(char));
		*outDataLen = outDataLenTmp;
		memcpy(*outData, outDataTmp, outDataLenTmp);
		retDataFree(outDataTmp);
		internalJsonMessageRelease(itjsmsg);
	}
	else {
		char* temErrMsg = getCommonErrMsg(OPERATION_DEREG);
		*outData = (char*)calloc(strlen(temErrMsg), sizeof(char));
		*outDataLen = strlen(temErrMsg);
		memcpy(*outData, temErrMsg, strlen(temErrMsg));

		if (temErrMsg)
			free(temErrMsg);
	}

	return retVal;
}





void retDataFree(char *msg) {
	if(msg)
		free(msg);
}

int main_88(void) {
	const char *path = "E:\\env_common\\UAF\\koscom_it\\client\\env\\uafsdk\\uafsdk4c.properties";
	const char *targetUrl = "https://fido.signkorea.com:9033/registrationrequestfromfc";
	const char *userid="test01";
	const char *appid="https://211.236.246.77:9024/appid";

	size_t ret;
	ret = Init(path);

	size_t revChk = FALSE;
	char *outData = NULL;
	size_t outDataLen = 0;


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
	
	system("pause");
	return 0;
}