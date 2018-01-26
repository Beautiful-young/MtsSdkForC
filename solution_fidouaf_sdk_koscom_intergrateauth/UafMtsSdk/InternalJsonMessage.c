#include <string.h>
#include <jansson.h>
#include "InternalJsonMessage.h"



char* makeIJMessageToJson(InternalJsonMessage *ijmsg) {
	char *jsmsg = NULL;
	json_t *root = json_object();

	if (ijmsg->version != NULL) {
		json_object_set_new(root, "version", json_string(ijmsg->version));
	}

	if (ijmsg->source >= 0) {
		json_object_set_new(root, "source", json_integer(ijmsg->source));
	}

	if (ijmsg->target >= 0) {
		json_object_set_new(root, "target", json_integer(ijmsg->target));
	}

	if (ijmsg->activecode != NULL) {
		json_object_set_new(root, "activecode", json_string(ijmsg->activecode));
	}

	if (ijmsg->appid != NULL) {
		json_object_set_new(root, "appid", json_string(ijmsg->appid));
	}

	if (ijmsg->userid != NULL) {
		json_object_set_new(root, "userid", json_string(ijmsg->userid));
	}

	if (ijmsg->sessionid) {
		json_object_set_new(root, "sessionid", json_string(ijmsg->sessionid));
	}

	if (ijmsg->mobiletype >= 0) {
		json_object_set_new(root, "mobiletype", json_integer(ijmsg->mobiletype));
	}

	if (ijmsg->mobileno) {
		json_object_set_new(root, "mobileno", json_string(ijmsg->mobileno));
	}

	if (ijmsg->pushid) {
		json_object_set_new(root, "pushid", json_string(ijmsg->pushid));
	}

	if (ijmsg->errorcode) {
		json_object_set_new(root, "errorcode", json_string(ijmsg->errorcode));
	}

	if (ijmsg->errormessage) {
		json_object_set_new(root, "errormessage", json_string(ijmsg->errormessage));
		/*
		size_t strlength = strlen(ijmsg->errormessage);
		//fprintf(stdout, "strlength : %d", strlength);
		char tmperrmsg[256];

		memset(tmperrmsg, 0x00, 256);
		memcpy(tmperrmsg, ijmsg->errormessage, strlength);
		//memcpy(tmperrmsg, ijmsg->errormessage, strlength);
		json_object_set_new(root, "errormessage", json_stringn(tmperrmsg, strlength));
		//json_object_set_new(root, "errormessage", json_string("error messge.."));
		//json_object_set_new(root, "errormessage", json_string("내부메시지 파싱에 실패 하였습니다. FIDO Server로 부터 수신한 RegistRequest 메시지가 올바르지 않습니다."));
		*/
		/*
		const char *tmperrmsg = "내부메시지 파싱에 실패 하였습니다. FIDO Server로 부터 수신한 RegistRequest 메시지가 올바르지 않습니다.";
		size_t tmperrmsglen = strlen("내부메시지 파싱에 실패 하였습니다. FIDO Server로 부터 수신한 RegistRequest 메시지가 올바르지 않습니다.");
		json_object_set_new(root, "errormessage", json_stringn(tmperrmsg, tmperrmsglen));
		*/


	}

	if (ijmsg->rpwebsession) {
		json_object_set_new(root, "rpwebsession", json_string(ijmsg->rpwebsession));
	}

	if (ijmsg->agenturl) {
		json_object_set_new(root, "agenturl", json_string(ijmsg->agenturl));
	}

	if (ijmsg->operation) {
		json_object_set_new(root, "operation", json_string(ijmsg->operation));
	}

	if (ijmsg->regrequestmsg) {
		json_object_set_new(root, "regrequestmsg", json_string(ijmsg->regrequestmsg));
	}

	if (ijmsg->regresponsemsg) {
		json_object_set_new(root, "regresponsemsg", json_string(ijmsg->regresponsemsg));
	}

	if (ijmsg->authrequestmsg) {
		json_object_set_new(root, "authrequestmsg", json_string(ijmsg->authrequestmsg));
	}

	if (ijmsg->authresponsemsg) {
		json_object_set_new(root, "authresponsemsg", json_string(ijmsg->authresponsemsg));
	}

	if (ijmsg->deregrequestmsg) {
		json_object_set_new(root, "deregrequestmsg", json_string(ijmsg->deregrequestmsg));
	}

	if (ijmsg->devmode) {
		json_object_set_new(root, "devmode", json_string(ijmsg->devmode));
	}

	if (ijmsg->authenticationmode) {
		json_object_set_new(root, "authenticationmode", json_string(ijmsg->authenticationmode));
	}

	if (ijmsg->serverEndPoint) {
		json_object_set_new(root, "serverEndPoint", json_string(ijmsg->serverEndPoint));
	}

	if (ijmsg->tlsServerCertificate) {
		json_object_set_new(root, "tlsServerCertificate", json_string(ijmsg->tlsServerCertificate));
	}

	if (ijmsg->tlsUnique) {
		json_object_set_new(root, "tlsUnique", json_string(ijmsg->tlsUnique));
	}

	if (ijmsg->cid_pubkey) {
		json_object_set_new(root, "cid_pubkey", json_string(ijmsg->cid_pubkey));
	}

	if (ijmsg->contentType) {
		json_object_set_new(root, "contentType", json_string(ijmsg->contentType));
	}

	if (ijmsg->content) {
		json_object_set_new(root, "content", json_string(ijmsg->content));
	}

	if (ijmsg->contentEncodingType) {
		json_object_set_new(root, "contentEncodingType", json_string(ijmsg->contentEncodingType));
	}

	if (ijmsg->origin) {
		json_object_set_new(root, "origin", json_string(ijmsg->origin));
	}

	if (ijmsg->u2f_regrequestmsg) {
		json_object_set_new(root, "u2f_regrequestmsg", json_string(ijmsg->u2f_regrequestmsg));
	}

	if (ijmsg->u2f_regresponsemsg) {
		json_object_set_new(root, "u2f_regresponsemsg", json_string(ijmsg->u2f_regresponsemsg));
	}

	if (ijmsg->u2f_authrequestmsg) {
		json_object_set_new(root, "u2f_authrequestmsg", json_string(ijmsg->u2f_authrequestmsg));
	}

	if (ijmsg->u2f_authresponsemsg) {
		json_object_set_new(root, "u2f_authresponsemsg", json_string(ijmsg->u2f_authresponsemsg));
	}

	if (ijmsg->u2f_deleterequestmsg) {
		json_object_set_new(root, "u2f_deleterequestmsg", json_string(ijmsg->u2f_deleterequestmsg));
	}

	if (ijmsg->u2f_clientdata) {
		json_object_set_new(root, "u2f_clientdata", json_string(ijmsg->u2f_clientdata));
	}

	if (ijmsg->sslcert) {
		json_object_set_new(root, "sslcert", json_string(ijmsg->sslcert));
	}

	if (ijmsg->additionalVerifyType) {
		json_object_set_new(root, "additionalVerifyType", json_string(ijmsg->additionalVerifyType));
	}

	if (ijmsg->certficationSignature) {
		json_object_set_new(root, "certficationSignature", json_string(ijmsg->certficationSignature));
	}

	if (ijmsg->plainText) {
		json_object_set_new(root, "plainText", json_string(ijmsg->plainText));
	}

	if (ijmsg->plainTextConvert) {
		json_object_set_new(root, "plainTextConvert", json_string(ijmsg->plainTextConvert));
	}

	if (ijmsg->ptHash) {
		json_object_set_new(root, "ptHash", json_string(ijmsg->ptHash));
	}

	if (ijmsg->ptSign) {
		json_object_set_new(root, "ptSign", json_string(ijmsg->ptSign));
	}

	if (ijmsg->attestationChallenge) {
		json_object_set_new(root, "attestationChallenge", json_string(ijmsg->attestationChallenge));
	}

	if (ijmsg->rpid) {
		json_object_set_new(root, "rpid", json_string(ijmsg->rpid));
	}

	if (ijmsg->rpDisplayName) {
		json_object_set_new(root, "rpDisplayName", json_string(ijmsg->rpDisplayName));
	}

	if (ijmsg->blacklistmsg) {
		json_object_set_new(root, "blacklistmsg", json_string(ijmsg->blacklistmsg));
	}

	if (ijmsg->displayName) {
		json_object_set_new(root, "displayName", json_string(ijmsg->displayName));
	}

	if (ijmsg->aaguid) {
		json_object_set_new(root, "aaguid", json_string(ijmsg->aaguid));
	}

	if (ijmsg->makCredentialInfoMsg) {
		json_object_set_new(root, "makCredentialInfoMsg", json_string(ijmsg->makCredentialInfoMsg));
	}

	if (ijmsg->assertionMsg) {
		json_object_set_new(root, "assertionMsg", json_string(ijmsg->assertionMsg));
	}

	if (ijmsg->whitelistmsg) {
		json_object_set_new(root, "whitelistmsg", json_string(ijmsg->whitelistmsg));
	}

	if (ijmsg->assertionChallenge) {
		json_object_set_new(root, "assertionChallenge", json_string(ijmsg->assertionChallenge));
	}

	if (ijmsg->b64pk) {
		json_object_set_new(root, "b64pk", json_string(ijmsg->b64pk));
	}

	if (ijmsg->mobileversion) {
		json_object_set_new(root, "mobileversion", json_string(ijmsg->mobileversion));
	}

	if (ijmsg->mobilemodel) {
		json_object_set_new(root, "mobilemodel", json_string(ijmsg->mobilemodel));
	}

	if (ijmsg->appversion) {
		json_object_set_new(root, "appversion", json_string(ijmsg->appversion));
	}

	if (ijmsg->authtype) {
		json_object_set_new(root, "authtype", json_string(ijmsg->authtype));
	}

	if (ijmsg->deregflag) {
		json_object_set_new(root, "deregflag", json_string(ijmsg->deregflag));
	}

	jsmsg = json_dumps(root, 0);
	json_decref(root);
	return jsmsg;
}



InternalJsonMessage* parse(const char *input) {

	InternalJsonMessage *ijmess;
	json_t *request = NULL;
	json_error_t error;

	request = json_loads(input, 0, &error);

	if (!request) {
		fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
		return NULL;
	}

	if (!json_is_object(request)) {
		fprintf(stderr, "error : commit data is not an object\n");
		json_decref(request);
		return NULL;
	}
	json_t *version;
	json_t *source;

	ijmess = (InternalJsonMessage *)malloc(sizeof(InternalJsonMessage));
	memset(ijmess, 0x00, sizeof(InternalJsonMessage));

	version = json_object_get(request, "version");
	if (json_is_string(version)) {
		//fprintf(stderr, "error: request verstion is null.\n");
	}
	else {
		const char* version_val;
		size_t version_len;
		version_val = json_string_value(version);
		version_len = strlen(version_val);
		ijmess->version = (char*)calloc(version_len + 1, sizeof(char));
		memcpy(ijmess->version, version_val, version_len);
		//fprintf(stdout, "version : %s\n", ijmess->version);
	}

	source = json_object_get(request, "source");
	if (!json_is_integer(source)) {
		//fprintf(stderr, "error: request source is null.\n");
	}
	else {
		ijmess->source = (size_t)json_integer_value(source);
		//fprintf(stdout, "source : %d\n", ijmess->source);
	}

	json_t *target;
	target = json_object_get(request, "target");
	if (!json_is_integer(target)) {
		//fprintf(stderr, "error: request target is null.\n");
		//return NULL;
	}
	else {
		ijmess->target = (size_t)json_integer_value(target);
		//fprintf(stdout, "target : %d\n", ijmess->target);
	}

	json_t *activecode = json_object_get(request, "activecode");
	if (!json_is_string(activecode)) {
		//fprintf(stderr, "error: request activecode is null.\n");
	}
	else {
		const char* activecode_val = json_string_value(activecode);
		size_t activecode_len = strlen(activecode_val);
		ijmess->activecode = (char*)calloc(activecode_len + 1, sizeof(char));
		memcpy(ijmess->activecode, activecode_val, activecode_len);
		//fprintf(stdout, "activecode : %s\n", ijmess->activecode);
	}

	json_t *appid = json_object_get(request, "appid");
	if (!json_is_string(appid)) {
		//fprintf(stderr, "error: request appid is null.\n");
	}
	else {
		const char* appid_val = json_string_value(appid);
		size_t appid_len = strlen(appid_val);
		ijmess->appid = (char*)calloc(appid_len + 1, sizeof(char));
		memcpy(ijmess->appid, appid_val, appid_len);
		//fprintf(stdout, "appid : %s\n", ijmess->appid);
	}

	json_t *userid = json_object_get(request, "userid");
	if (!json_is_string(userid)) {
		//fprintf(stderr, "error: request userid is null.\n");
	}
	else {
		const char* userid_val = json_string_value(userid);
		size_t userid_len = strlen(userid_val);
		ijmess->userid = (char*)calloc(userid_len + 1, sizeof(char));
		memcpy(ijmess->userid, userid_val, userid_len);
		//fprintf(stdout, "userid : %s\n", ijmess->userid);
	}

	json_t *sessionid = json_object_get(request, "sessionid");
	if (!json_is_string(sessionid)) {
		//fprintf(stderr, "error: request sessionid is null.\n");
	}
	else {
		const char* sessionid_val = json_string_value(sessionid);
		size_t sessionid_len = strlen(sessionid_val);
		ijmess->sessionid = (char*)calloc(sessionid_len + 1, sizeof(char));
		memcpy(ijmess->sessionid, sessionid_val, sessionid_len);
		//fprintf(stdout, "sessionid : %s\n", ijmess->sessionid);
	}

	json_t *mobiletype = json_object_get(request, "mobiletype");
	if (!json_is_integer(mobiletype)) {
		//fprintf(stderr, "error: request mobiletype is null.\n");
	}
	else {
		ijmess->mobiletype = (size_t)json_integer_value(mobiletype);
		//fprintf(stdout, "mobiletype : %d\n", ijmess->mobiletype);
	}

	json_t *mobileno = json_object_get(request, "mobileno");
	if (!json_is_string(mobileno)) {
		//fprintf(stderr, "error: request mobileno is null.\n");
	}
	else {
		const char *mobileno_val = json_string_value(mobileno);
		size_t mobileno_len = strlen(mobileno_val);
		ijmess->mobileno = (char*)calloc(mobileno_len + 1, sizeof(char));
		memcpy(ijmess->mobileno, mobileno_val, mobileno_len);
		//fprintf(stdout, "mobileno : %s\n", ijmess->mobileno);
	}

	json_t *pushid = json_object_get(request, "pushid");
	if (!json_is_string(pushid)) {
		//fprintf(stderr, "error: request pushid is null.\n");
	}
	else {
		const char *pushid_val = (char*)json_string_value(pushid);
		size_t pushid_len = strlen(pushid_val);
		ijmess->pushid = (char*)calloc(pushid_len + 1, sizeof(char));
		memcpy(ijmess->pushid, pushid_val, pushid_len);
		//fprintf(stdout, "pushid : %s\n", ijmess->pushid);
	}

	json_t *errorcode = json_object_get(request, "errorcode");
	if (!json_is_string(errorcode)) {
		//fprintf(stderr, "error: request errorcode is null.\n");
	}
	else {
		const char *errorcode_val = (char*)json_string_value(errorcode);
		size_t errorcode_len = strlen(errorcode_val);
		ijmess->errorcode = (char*)calloc(errorcode_len + 1, sizeof(char));
		memcpy(ijmess->errorcode, errorcode_val, errorcode_len);
		//fprintf(stdout, "errorcode : %s\n", ijmess->errorcode);
	}

	json_t *errormessage = json_object_get(request, "errormessage");
	if (!json_is_string(errormessage)) {
		//fprintf(stderr, "error: request errormessage is null.\n");
	}
	else {
		const char *errormessage_val = json_string_value(errormessage);
		size_t errormessage_len = strlen(errormessage_val);
		ijmess->errormessage = (char*)calloc(errormessage_len, sizeof(char));
		memcpy(ijmess->errormessage, errormessage_val, errormessage_len);
		//fprintf(stdout, "errormessage : %s\n", ijmess->errormessage);
	}

	json_t *rpwebsession = json_object_get(request, "rpwebsession");
	if (!json_is_string(rpwebsession)) {
		//fprintf(stderr, "error: request rpwebsession is null.\n");
	}
	else {
		const char *rpwebsession_val = json_string_value(rpwebsession);
		size_t rpwebsession_len = strlen(rpwebsession_val);
		ijmess->rpwebsession = (char*)calloc(rpwebsession_len + 1, sizeof(char));
		memcpy(ijmess->rpwebsession, rpwebsession_val, rpwebsession_len);
		//fprintf(stdout, "rpwebsession : %s\n", ijmess->rpwebsession);
	}

	json_t *agenturl = json_object_get(request, "agenturl");
	if (!json_is_string(agenturl)) {
		//fprintf(stderr, "error: request agenturl is null.\n");
	}
	else {
		const char *agenturl_val = json_string_value(agenturl);
		size_t agenturl_len = strlen(agenturl_val);
		ijmess->agenturl = (char*)calloc(agenturl_len + 1, sizeof(char));
		memcpy(ijmess->agenturl, agenturl_val, agenturl_len);
		//fprintf(stdout, "agenturl : %s\n", ijmess->agenturl);
	}

	json_t *operation = json_object_get(request, "operation");
	if (!json_is_string(operation)) {
		//fprintf(stderr, "error: request operation is null.\n");
	}
	else {
		const char *operation_val = json_string_value(operation);
		size_t operation_len = strlen(operation_val);
		ijmess->operation = (char*)calloc(operation_len + 1, operation_len);
		memcpy(ijmess->operation, operation_val, operation_len);
		//fprintf(stdout, "operation : %s\n", ijmess->operation);
	}

	json_t *regrequestmsg = json_object_get(request, "regrequestmsg");
	if (!json_is_string(regrequestmsg)) {
		//fprintf(stderr, "error: request  is null.\n");
	}
	else {
		const char *regrequestmsg_val = json_string_value(regrequestmsg);
		size_t regrequestmsg_len = strlen(regrequestmsg_val);
		ijmess->regrequestmsg = (char*)calloc(regrequestmsg_len + 1, sizeof(char));
		memcpy(ijmess->regrequestmsg, regrequestmsg_val, regrequestmsg_len);
		//fprintf(stdout, "regrequestmsg : %s\n", ijmess->regrequestmsg);
	}

	json_t *regresponsemsg = json_object_get(request, "regresponsemsg");
	if (!json_is_string(regresponsemsg)) {
		//fprintf(stderr, "error: request regresponsemsg is null.\n");
	}
	else {
		const char *regresponsemsg_val = json_string_value(regresponsemsg);
		size_t regresponsemsg_len = strlen(regresponsemsg_val);
		ijmess->regresponsemsg = (char*)calloc(regresponsemsg_len + 1, sizeof(char));
		memcpy(ijmess->regresponsemsg, regresponsemsg_val, regresponsemsg_len);
		//fprintf(stdout, "regresponsemsg : %s\n", ijmess->regresponsemsg);
	}

	json_t *authrequestmsg = json_object_get(request, "authrequestmsg");
	if (!json_is_string(authrequestmsg)) {
		//fprintf(stderr, "error: request  is null.\n");
	}
	else {
		const char *authrequestmsg_val = json_string_value(authrequestmsg);
		size_t authrequestmsg_len = strlen(authrequestmsg_val);
		ijmess->authrequestmsg = (char*)calloc(authrequestmsg_len + 1, sizeof(char));
		memcpy(ijmess->authrequestmsg, authrequestmsg_val, authrequestmsg_len);
		//fprintf(stdout, "authrequestmsg : %s\n", ijmess->authrequestmsg);
	}

	json_t *authresponsemsg = json_object_get(request, "authresponsemsg");
	if (!json_is_string(authresponsemsg)) {
		//fprintf(stderr, "error: request  is null.\n");
	}
	else {
		const char *authresponsemsg_val = json_string_value(authresponsemsg);
		size_t authresponsemsg_len = strlen(authresponsemsg_val);
		ijmess->authresponsemsg = (char*)calloc(authresponsemsg_len + 1, sizeof(char));
		memcpy(ijmess->authresponsemsg, authresponsemsg_val, authresponsemsg_len);
		//fprintf(stdout, "authresponsemsg : %s\n", ijmess->authresponsemsg);
	}

	json_t *deregrequestmsg = json_object_get(request, "deregrequestmsg");
	if (!json_is_string(deregrequestmsg)) {
		//fprintf(stderr, "error: request  is null.\n");
	}
	else {
		const char *deregrequestmsg_val = json_string_value(deregrequestmsg);
		size_t deregrequestmsg_len = strlen(deregrequestmsg_val);
		ijmess->deregrequestmsg = (char*)calloc(deregrequestmsg_len + 1, sizeof(char));
		memcpy(ijmess->deregrequestmsg, deregrequestmsg_val, deregrequestmsg_len);
		//fprintf(stdout, "deregrequestmsg : %s\n", ijmess->deregrequestmsg);
	}

	json_t *devmode = json_object_get(request, "devmode");
	if (!json_is_string(devmode)) {
		//fprintf(stderr, "error: request devmode is null.\n");
	}
	else {
		const char *devmode_val = json_string_value(devmode);
		size_t devmode_len = strlen(devmode_val);
		ijmess->devmode = (char*)calloc(devmode_len + 1, sizeof(char));
		memcpy(ijmess->devmode, devmode_val, devmode_len);
		//fprintf(stdout, "devmode : %s\n", ijmess->devmode);
	}

	json_t *authenticationmode = json_object_get(request, "authenticationmode");
	if (!json_is_string(authenticationmode)) {
		//fprintf(stderr, "error: request authenticationmode is null.\n");
	}
	else {
		const char*authenticationmode_val = json_string_value(authenticationmode);
		size_t authenticationmode_len = strlen(authenticationmode_val);
		ijmess->authenticationmode = (char*)calloc(authenticationmode_len + 1, sizeof(char));
		memcpy(ijmess->authenticationmode, authenticationmode_val, authenticationmode_len);
		//fprintf(stdout, "authenticationmode : %s\n", ijmess->authenticationmode);
	}

	json_t *serverEndPoint = json_object_get(request, "serverEndPoint");
	if (!json_is_string(serverEndPoint)) {
		//fprintf(stderr, "error: request serverEndPoint is null.\n");
	}
	else {
		const char *serverEndPoint_val = json_string_value(serverEndPoint);
		size_t serverEndPoint_len = strlen(serverEndPoint_val);
		ijmess->serverEndPoint = (char*)calloc(serverEndPoint_len + 1, serverEndPoint_len);
		memcpy(ijmess->serverEndPoint, serverEndPoint_val, serverEndPoint_len);
		//fprintf(stdout, "serverEndPoint : %s\n", ijmess->serverEndPoint);
	}

	json_t *tlsServerCertificate = json_object_get(request, "tlsServerCertificate");
	if (!json_is_string(tlsServerCertificate)) {
		//fprintf(stderr, "error: request tlsServerCertificate is null.\n");
	}
	else {
		const char *tlsServerCertificate_val = json_string_value(tlsServerCertificate);
		size_t tlsServerCertificate_len = strlen(tlsServerCertificate_val);
		ijmess->tlsServerCertificate = (char*)calloc(tlsServerCertificate_len + 1, sizeof(char));
		memcpy(ijmess->tlsServerCertificate, tlsServerCertificate_val, tlsServerCertificate_len);
		//fprintf(stdout, "tlsServerCertificate : %s\n", ijmess->tlsServerCertificate);
	}

	json_t *tlsUnique = json_object_get(request, "tlsUnique");
	if (!json_is_string(tlsUnique)) {
		//fprintf(stderr, "error: request tlsUnique is null.\n");
	}
	else {
		const char *tlsUnique_val = json_string_value(tlsUnique);
		size_t tlsUnique_len = strlen(tlsUnique_val);
		ijmess->tlsUnique = (char*)calloc(tlsUnique_len + 1, sizeof(char));
		memcpy(ijmess->tlsUnique, tlsUnique_val, tlsUnique_len);
		//fprintf(stdout, "tlsUnique : %s\n", ijmess->tlsUnique);
	}

	json_t *cid_pubkey = json_object_get(request, "cid_pubkey");
	if (!json_is_string(cid_pubkey)) {
		//fprintf(stderr, "error: request cid_pubkey is null.\n");
	}
	else {
		const char *cid_pubkey_val = json_string_value(cid_pubkey);
		size_t cid_pubkey_len = strlen(cid_pubkey_val);
		ijmess->cid_pubkey = (char*)calloc(cid_pubkey_len + 1, sizeof(char));
		memcpy(ijmess->cid_pubkey, cid_pubkey_val, cid_pubkey_len);
		//fprintf(stdout, "cid_pubkey : %s\n", ijmess->cid_pubkey);
	}

	json_t *contentType = json_object_get(request, "contentType");
	if (!json_is_string(contentType)) {
		//fprintf(stderr, "error: request contentType is null.\n");
	}
	else {
		const char *contentType_val = json_string_value(contentType);
		size_t contentType_len = strlen(contentType_val);
		ijmess->contentType = (char*)calloc(contentType_len + 1, sizeof(char));
		memcpy(ijmess->contentType, contentType_val, contentType_len);
		//fprintf(stdout, "contentType : %s\n", ijmess->contentType);
	}

	json_t *content = json_object_get(request, "content");
	if (!json_is_string(content)) {
		//fprintf(stderr, "error: request content is null.\n");
	}
	else {
		const char *content_val = json_string_value(content);
		size_t content_len = strlen(content_val);
		ijmess->content = (char*)calloc(content_len + 1, sizeof(char));
		memcpy(ijmess->content, content_val, content_len);
		//fprintf(stdout, "content : %s\n", ijmess->content);
	}

	json_t *contentEncodingType = json_object_get(request, "contentEncodingType");
	if (!json_is_string(contentEncodingType)) {
		//fprintf(stderr, "error: request contentEncodingType is null.\n");
	}
	else {
		const char *contentEncodingType_val = json_string_value(contentEncodingType);
		size_t contentEncodingType_len = strlen(contentEncodingType_val);
		ijmess->contentEncodingType = (char*)calloc(contentEncodingType_len + 1, sizeof(char));
		memcpy(ijmess->contentEncodingType, contentEncodingType_val, contentEncodingType_len);
		//fprintf(stdout, "contentEncodingType : %s\n", ijmess->contentEncodingType);
	}

	json_t *origin = json_object_get(request, "origin");
	if (!json_is_string(origin)) {
		//fprintf(stderr, "error: request origin is null.\n");
	}
	else {
		const char *origin_val = json_string_value(origin);
		size_t origin_len = strlen(origin_val);
		ijmess->origin = (char*)calloc(origin_len + 1, sizeof(char));
		memcpy(ijmess->origin, origin_val, origin_len);
		//fprintf(stdout, "origin : %s\n", ijmess->origin);
	}

	json_t *u2f_regrequestmsg = json_object_get(request, "u2f_regrequestmsg");
	if (!json_is_string(u2f_regrequestmsg)) {
		//fprintf(stderr, "error: request u2f_regrequestmsg is null.\n");
	}
	else {
		const char *u2f_regrequestmsg_val = json_string_value(u2f_regrequestmsg);
		size_t u2f_regrequestmsg_len = strlen(u2f_regrequestmsg_val);
		ijmess->u2f_regrequestmsg = (char*)calloc(u2f_regrequestmsg_len + 1, sizeof(char));
		memcpy(ijmess->u2f_regrequestmsg, u2f_regrequestmsg_val, u2f_regrequestmsg_len);
		//fprintf(stdout, "u2f_regrequestmsg : %s\n", ijmess->u2f_regrequestmsg);
	}

	json_t *u2f_regresponsemsg = json_object_get(request, "u2f_regresponsemsg");
	if (!json_is_string(u2f_regresponsemsg)) {
		//fprintf(stderr, "error: request u2f_regresponsemsg is null.\n");
	}
	else {
		const char *u2f_regresponsemsg_val = json_string_value(u2f_regresponsemsg);
		size_t u2f_regresponsemsg_len = strlen(u2f_regresponsemsg_val);
		ijmess->u2f_regresponsemsg = (char*)calloc(u2f_regresponsemsg_len + 1, sizeof(char));
		memcpy(ijmess->u2f_regresponsemsg, u2f_regresponsemsg_val, u2f_regresponsemsg_len);
		//fprintf(stdout, "u2f_regresponsemsg : %s\n", ijmess->u2f_regresponsemsg);
	}

	json_t *u2f_authrequestmsg = json_object_get(request, "u2f_authrequestmsg");
	if (!json_is_string(u2f_authrequestmsg)) {
		//fprintf(stderr, "error: request u2f_authrequestmsg is null.\n");
	}
	else {
		const char *u2f_authrequestmsg_val = json_string_value(u2f_authrequestmsg);
		size_t u2f_authrequestmsg_len = strlen(u2f_authrequestmsg_val);
		ijmess->u2f_authrequestmsg = (char*)calloc(u2f_authrequestmsg_len + 1, sizeof(char));
		memcpy(ijmess->u2f_authrequestmsg, u2f_authrequestmsg_val, u2f_authrequestmsg_len);
		//fprintf(stdout, "u2f_authrequestmsg : %s\n", ijmess->u2f_authrequestmsg);
	}

	json_t *u2f_authresponsemsg = json_object_get(request, "u2f_authresponsemsg");
	if (!json_is_string(u2f_authresponsemsg)) {
		//fprintf(stderr, "error: request u2f_authresponsemsg is null.\n");
	}
	else {
		const char *u2f_authresponsemsg_val = json_string_value(u2f_authresponsemsg);
		size_t u2f_authresponsemsg_len = strlen(u2f_authresponsemsg_val);
		ijmess->u2f_authresponsemsg = (char*)calloc(u2f_authresponsemsg_len + 1, sizeof(char));
		memcpy(ijmess->u2f_authresponsemsg, u2f_authresponsemsg_val, u2f_authresponsemsg_len);
		//fprintf(stdout, "u2f_authresponsemsg : %s\n", ijmess->u2f_authresponsemsg);
	}

	json_t *u2f_deleterequestmsg = json_object_get(request, "u2f_deleterequestmsg");
	if (!json_is_string(u2f_deleterequestmsg)) {
		//fprintf(stderr, "error: request u2f_deleterequestmsg is null.\n");
	}
	else {
		const char *u2f_deleterequestmsg_val = json_string_value(u2f_deleterequestmsg);
		size_t u2f_deleterequestmsg_len = strlen(u2f_deleterequestmsg_val);
		ijmess->u2f_deleterequestmsg = (char*)calloc(u2f_deleterequestmsg_len + 1, sizeof(char));
		memcpy(ijmess->u2f_deleterequestmsg, u2f_deleterequestmsg_val, u2f_deleterequestmsg_len);
		//fprintf(stdout, "u2f_deleterequestmsg : %s\n", ijmess->u2f_deleterequestmsg);
	}

	json_t *u2f_clientdata = json_object_get(request, "u2f_clientdata");
	if (!json_is_string(u2f_clientdata)) {
		//fprintf(stderr, "error: request u2f_clientdata is null.\n");
	}
	else {
		const char *u2f_clientdata_val = json_string_value(u2f_clientdata);
		size_t u2f_clientdata_len = strlen(u2f_clientdata_val);
		ijmess->u2f_clientdata = (char*)calloc(u2f_clientdata_len + 1, sizeof(char));
		memcpy(ijmess->u2f_clientdata, u2f_clientdata_val, u2f_clientdata_len);
		//fprintf(stdout, "u2f_clientdata : %s\n", ijmess->u2f_clientdata);
	}

	json_t *sslcert = json_object_get(request, "sslcert");
	if (!json_is_string(sslcert)) {
		//fprintf(stderr, "error: request sslcert is null.\n");
	}
	else {
		const char *sslcert_val = json_string_value(sslcert);
		size_t sslcert_len = strlen(sslcert_val);
		ijmess->sslcert = (char*)calloc(sslcert_len + 1, sizeof(char));
		memcpy(ijmess->sslcert, sslcert_val, sslcert_len);
		//fprintf(stdout, "sslcert : %s\n", ijmess->sslcert);
	}

	json_t *additionalVerifyType = json_object_get(request, "additionalVerifyType");
	if (!json_is_string(additionalVerifyType)) {
		//fprintf(stderr, "error: request additionalVerifyType is null.\n");
	}
	else {
		const char * additionalVerifyType_val = json_string_value(additionalVerifyType);
		size_t additionalVerifyType_len = strlen(additionalVerifyType_val);
		ijmess->additionalVerifyType = (char*)calloc(additionalVerifyType_len + 1, sizeof(char));
		memcpy(ijmess->additionalVerifyType, additionalVerifyType_val, additionalVerifyType_len);
		//fprintf(stdout, "additionalVerifyType : %s\n", ijmess->additionalVerifyType);
	}

	json_t *certficationSignature = json_object_get(request, "certficationSignature");
	if (!json_is_string(certficationSignature)) {
		//fprintf(stderr, "error: request certficationSignature is null.\n");
	}
	else {
		const char* certficationSignature_val = json_string_value(certficationSignature);
		size_t certficationSignature_len = strlen(certficationSignature_val);
		ijmess->certficationSignature = (char*)calloc(certficationSignature_len + 1, sizeof(char));
		memcpy(ijmess->certficationSignature, certficationSignature_val, certficationSignature_len);
		//fprintf(stdout, "certficationSignature : %s\n", ijmess->certficationSignature);
	}

	json_t *plainText = json_object_get(request, "plainText");
	if (!json_is_string(plainText)) {
		//fprintf(stderr, "error: request plainText is null.\n");
	}
	else {
		const char* plainText_val = json_string_value(plainText);
		size_t plainText_len = strlen(plainText_val);
		ijmess->plainText = (char*)calloc(plainText_len + 1, sizeof(char));
		memcpy(ijmess->plainText, plainText_val, plainText_len);
		//fprintf(stdout, "plainText : %s\n", ijmess->plainText);
	}

	json_t *plainTextConvert = json_object_get(request, "plainTextConvert");
	if (!json_is_string(plainTextConvert)) {
		//fprintf(stderr, "error: request plainTextConvert is null.\n");
	}
	else {
		const char* plainTextConvert_val = json_string_value(plainTextConvert);
		size_t plainTextConvert_len = strlen(plainTextConvert_val);
		ijmess->plainTextConvert = (char*)calloc(plainTextConvert_len + 1, sizeof(char));
		memcpy(ijmess->plainTextConvert, plainTextConvert_val, plainTextConvert_len);
		//fprintf(stdout, "plainTextConvert : %s\n", ijmess->plainTextConvert);
	}

	json_t *ptHash = json_object_get(request, "ptHash");
	if (!json_is_string(ptHash)) {
		//fprintf(stderr, "error: request ptHash is null.\n");
	}
	else {
		const char* ptHash_val = json_string_value(ptHash);
		size_t ptHash_len = strlen(ptHash_val);
		ijmess->ptHash = (char*)calloc(ptHash_len + 1, sizeof(char));
		memcpy(ijmess->ptHash, ptHash_val, ptHash_len);
		//fprintf(stdout, "ptHash : %s\n", ijmess->ptHash);
	}

	json_t *ptSign = json_object_get(request, "ptSign");
	if (!json_is_string(ptSign)) {
		//fprintf(stderr, "error: request ptSign is null.\n");
	}
	else {
		const char* ptSign_val = json_string_value(ptSign);
		size_t ptSign_len = strlen(ptSign_val);
		ijmess->ptSign = (char*)calloc(ptSign_len + 1, sizeof(char));
		memcpy(ijmess->ptSign, ptSign_val, ptSign_len);
		//fprintf(stdout, "ptSign : %s\n", ijmess->ptSign);
	}

	json_t *attestationChallenge = json_object_get(request, "attestationChallenge");
	if (!json_is_string(attestationChallenge)) {
		//fprintf(stderr, "error: request attestationChallenge is null.\n");
	}
	else {
		const char* attestationChallenge_val = json_string_value(attestationChallenge);
		size_t attestationChallenge_len = strlen(attestationChallenge_val);
		ijmess->attestationChallenge = (char*)calloc(attestationChallenge_len + 1, sizeof(char));
		memcpy(ijmess->attestationChallenge, attestationChallenge_val, attestationChallenge_len);
		//fprintf(stdout, "attestationChallenge : %s\n", ijmess->attestationChallenge);
	}

	json_t *rpid = json_object_get(request, "rpid");
	if (!json_is_string(rpid)) {
		//fprintf(stderr, "error: request rpid is null.\n");
	}
	else {
		const char* rpid_val = json_string_value(rpid);
		size_t rpid_len = strlen(rpid_val);
		ijmess->rpid = (char*)calloc(rpid_len + 1, sizeof(char));
		memcpy(ijmess->rpid, rpid_val, rpid_len);
		//fprintf(stdout, "rpid : %s\n", ijmess->rpid);
	}

	json_t *rpDisplayName = json_object_get(request, "rpDisplayName");
	if (!json_is_string(rpDisplayName)) {
		//fprintf(stderr, "error: request rpDisplayName is null.\n");
	}
	else {
		const char* rpDisplayName_val = json_string_value(rpDisplayName);
		size_t rpDisplayName_len = strlen(rpDisplayName_val);
		ijmess->rpDisplayName = (char*)calloc(rpDisplayName_len + 1, sizeof(char));
		memcpy(ijmess->rpDisplayName, rpDisplayName_val, rpDisplayName_len);
		//fprintf(stdout, "rpDisplayName : %s\n", ijmess->rpDisplayName);
	}

	json_t *blacklistmsg = json_object_get(request, "blacklistmsg");
	if (!json_is_string(blacklistmsg)) {
		//fprintf(stderr, "error: request blacklistmsg is null.\n");
	}
	else {
		const char* blacklistmsg_val = json_string_value(blacklistmsg);
		size_t blacklistmsg_len = strlen(blacklistmsg_val);
		ijmess->blacklistmsg = (char*)calloc(blacklistmsg_len + 1, sizeof(char));
		memcpy(ijmess->blacklistmsg, blacklistmsg_val, blacklistmsg_len);
		//fprintf(stdout, "blacklistmsg : %s\n", ijmess->blacklistmsg);
	}

	json_t *displayName = json_object_get(request, "displayName");
	if (!json_is_string(displayName)) {
		//fprintf(stderr, "error: request displayName is null.\n");
	}
	else {
		const char* displayName_val = json_string_value(displayName);
		size_t displayName_len = strlen(displayName_val);
		ijmess->displayName = (char*)calloc(displayName_len + 1, sizeof(char));
		memcpy(ijmess->displayName, displayName_val, displayName_len);
		//fprintf(stdout, "displayName : %s\n", ijmess->displayName);
	}

	json_t *aaguid = json_object_get(request, "aaguid");
	if (!json_is_string(aaguid)) {
		//fprintf(stderr, "error: request aaguid is null.\n");
	}
	else {
		const char* aaguid_val = json_string_value(aaguid);
		size_t aaguid_len = strlen(aaguid_val);
		ijmess->aaguid = (char*)calloc(aaguid_len + 1, sizeof(char));
		memcpy(ijmess->aaguid, aaguid_val, aaguid_len);
		//fprintf(stdout, "aaguid : %s\n", ijmess->aaguid);
	}

	json_t *makCredentialInfoMsg = json_object_get(request, "makCredentialInfoMsg");
	if (!json_is_string(makCredentialInfoMsg)) {
		//fprintf(stderr, "error: request makCredentialInfoMsg is null.\n");
	}
	else {
		const char* makCredentialInfoMsg_val = json_string_value(makCredentialInfoMsg);
		size_t makCredentialInfoMsg_len = strlen(makCredentialInfoMsg_val);
		ijmess->makCredentialInfoMsg = (char*)calloc(makCredentialInfoMsg_len + 1, sizeof(char));
		memcpy(ijmess->makCredentialInfoMsg, makCredentialInfoMsg_val, makCredentialInfoMsg_len);
		//fprintf(stdout, "makCredentialInfoMsg : %s\n", ijmess->makCredentialInfoMsg);
	}

	json_t *assertionMsg = json_object_get(request, "assertionMsg");
	if (!json_is_string(assertionMsg)) {
		//fprintf(stderr, "error: request assertionMsg is null.\n");
	}
	else {
		const char* assertionMsg_val = json_string_value(assertionMsg);
		size_t assertionMsg_len = strlen(assertionMsg_val);
		ijmess->assertionMsg = (char*)calloc(assertionMsg_len + 1, sizeof(char));
		memcpy(ijmess->assertionMsg, assertionMsg_val, assertionMsg_len);
		//fprintf(stdout, "assertionMsg : %s\n", ijmess->assertionMsg);
	}

	json_t *whitelistmsg = json_object_get(request, "whitelistmsg");
	if (!json_is_string(whitelistmsg)) {
		//fprintf(stderr, "error: request whitelistmsg is null.\n");
	}
	else {
		const char* whitelistmsg_val = json_string_value(whitelistmsg);
		size_t whitelistmsg_len = strlen(whitelistmsg_val);
		ijmess->whitelistmsg = (char*)calloc(whitelistmsg_len + 1, sizeof(char));
		memcpy(ijmess->whitelistmsg, whitelistmsg_val, whitelistmsg_len);
		//fprintf(stdout, "whitelistmsg : %s\n", ijmess->whitelistmsg);
	}

	json_t *assertionChallenge = json_object_get(request, "assertionChallenge");
	if (!json_is_string(assertionChallenge)) {
		//fprintf(stderr, "error: request assertionChallenge is null.\n");
	}
	else {
		const char *assertionChallenge_val = json_string_value(assertionChallenge);
		size_t assertionChallenge_len = strlen(assertionChallenge_val);
		ijmess->assertionChallenge = (char*)calloc(assertionChallenge_len + 1, sizeof(char));
		memcpy(ijmess->assertionChallenge, assertionChallenge_val, assertionChallenge_len);
		//fprintf(stdout, "assertionChallenge : %s\n", ijmess->assertionChallenge);
	}

	json_t *b64pk = json_object_get(request, "b64pk");
	if (!json_is_string(b64pk)) {
		//fprintf(stderr, "error: request b64pk is null.\n");
	}
	else {
		const char* b64pk_val = json_string_value(b64pk);
		size_t b64pk_len = strlen(b64pk_val);
		ijmess->b64pk = (char*)calloc(b64pk_len + 1, sizeof(char));
		memcpy(ijmess->b64pk, b64pk_val, b64pk_len);
		//fprintf(stdout, "b64pk : %s\n", ijmess->b64pk);
	}

	json_t *mobileversion = json_object_get(request, "mobileversion");
	if (!json_is_string(mobileversion)) {
		//fprintf(stderr, "error: request mobileversion is null.\n");
	}
	else {
		const char* mobileversion_val = json_string_value(mobileversion);
		size_t mobileversion_len = strlen(mobileversion_val);
		ijmess->mobileversion = (char*)calloc(mobileversion_len + 1, sizeof(char));
		memcpy(ijmess->mobileversion, mobileversion_val, mobileversion_len);
		//fprintf(stdout, "mobileversion : %s\n", ijmess->mobileversion);
	}

	json_t *mobilemodel = json_object_get(request, "mobilemodel");
	if (!json_is_string(mobilemodel)) {
		//fprintf(stderr, "error: request mobilemodel is null.\n");
	}
	else {
		const char* mobilemodel_val = json_string_value(mobilemodel);
		size_t mobilemodel_len = strlen(mobilemodel_val);
		ijmess->mobilemodel = (char*)calloc(mobilemodel_len + 1, sizeof(char));
		memcpy(ijmess->mobilemodel, mobilemodel_val, mobilemodel_len);
		//fprintf(stdout, "mobilemodel : %s\n", ijmess->mobilemodel);
	}

	json_t *appversion = json_object_get(request, "appversion");
	if (!json_is_string(appversion)) {
		//fprintf(stderr, "error: request appversion is null.\n");
	}
	else {
		const char *appversion_val = json_string_value(appversion);
		size_t appversion_len = strlen(appversion_val);
		ijmess->appversion = (char*)calloc(appversion_len + 1, sizeof(char));
		memcpy(ijmess->appversion, appversion_val, appversion_len);
		//fprintf(stdout, "appversion : %s\n", ijmess->appversion);
	}

	json_t *authtype = json_object_get(request, "authtype");
	if (!json_is_string(authtype)) {
		//fprintf(stderr, "error: request authtype is null.\n");
	}
	else {
		const char *authtype_val = json_string_value(authtype);
		size_t authtype_len = strlen(authtype_val);
		ijmess->authtype = (char*)calloc(authtype_len + 1, sizeof(char));
		memcpy(ijmess->authtype, authtype_val, authtype_len);
		//fprintf(stdout, "authtype : %s\n", ijmess->authtype);
	}

	json_t *deregflag = json_object_get(request, "deregflag");
	if (!json_is_string(deregflag)) {
		//fprintf(stderr, "error: request deregflag is null.\n");
	}
	else {
		const char *deregflag_val = json_string_value(deregflag);
		size_t deregflag_len = strlen(deregflag_val);
		ijmess->deregflag = (char*)calloc(deregflag_len + 1, sizeof(char));
		memcpy(ijmess->deregflag, deregflag_val, deregflag_len);
		//fprintf(stdout, "deregflag : %s\n", ijmess->deregflag);
	}

	json_decref(request);
	return ijmess;
}

void internalJsonMessageRelease(InternalJsonMessage* msgstruct) {

	if (msgstruct->version != NULL) {
		free(msgstruct->version);
	}

	if (msgstruct->activecode != NULL) {
		free(msgstruct->activecode);
	}

	if (msgstruct->appid != NULL) {
		free(msgstruct->appid);
	}
	if (msgstruct->userid != NULL) {
		free(msgstruct->userid);
	}

	if (msgstruct->sessionid != NULL) {
		free(msgstruct->sessionid);
	}

	if (msgstruct->mobileno != NULL) {
		free(msgstruct->mobileno);
	}

	if (msgstruct->pushid != NULL) {
		free(msgstruct->pushid);
	}
	if (msgstruct->errorcode != NULL) {
		free(msgstruct->errorcode);
	}

	if (msgstruct->errormessage != NULL) {
		free(msgstruct->errormessage);
	}
	if (msgstruct->rpwebsession != NULL) {
		free(msgstruct->rpwebsession);
	}

	if (msgstruct->agenturl != NULL) {
		free(msgstruct->agenturl);
	}

	if (msgstruct->operation != NULL) {
		free(msgstruct->operation);
	}

	if (msgstruct->regrequestmsg != NULL) {
		free(msgstruct->regrequestmsg);
	}
	if (msgstruct->regresponsemsg != NULL) {
		free(msgstruct->regresponsemsg);
	}

	if (msgstruct->authrequestmsg != NULL) {
		free(msgstruct->authrequestmsg);
	}
	if (msgstruct->authresponsemsg != NULL) {
		free(msgstruct->authresponsemsg);
	}

	if (msgstruct->deregrequestmsg != NULL) {
		free(msgstruct->deregrequestmsg);
	}

	if (msgstruct->devmode != NULL) {
		free(msgstruct->devmode);
	}

	if (msgstruct->authenticationmode != NULL) {
		free(msgstruct->authenticationmode);
	}
	if (msgstruct->serverEndPoint != NULL) {
		free(msgstruct->serverEndPoint);
	}

	if (msgstruct->tlsServerCertificate != NULL) {
		free(msgstruct->tlsServerCertificate);
	}
	if (msgstruct->tlsUnique != NULL) {
		free(msgstruct->tlsUnique);
	}

	if (msgstruct->cid_pubkey != NULL) {
		free(msgstruct->cid_pubkey);
	}

	if (msgstruct->contentType != NULL) {
		free(msgstruct->contentType);
	}

	if (msgstruct->content != NULL) {
		free(msgstruct->content);
	}
	if (msgstruct->contentEncodingType != NULL) {
		free(msgstruct->contentEncodingType);
	}

	if (msgstruct->origin != NULL) {
		free(msgstruct->origin);
	}
	if (msgstruct->u2f_regrequestmsg != NULL) {
		free(msgstruct->u2f_regrequestmsg);
	}

	if (msgstruct->u2f_regresponsemsg != NULL) {
		free(msgstruct->u2f_regresponsemsg);
	}

	if (msgstruct->u2f_authrequestmsg != NULL) {
		free(msgstruct->u2f_authrequestmsg);
	}

	if (msgstruct->u2f_authresponsemsg != NULL) {
		free(msgstruct->u2f_authresponsemsg);
	}
	if (msgstruct->u2f_deleterequestmsg != NULL) {
		free(msgstruct->u2f_deleterequestmsg);
	}

	if (msgstruct->u2f_clientdata != NULL) {
		free(msgstruct->u2f_clientdata);
	}
	if (msgstruct->sslcert != NULL) {
		free(msgstruct->sslcert);
	}

	if (msgstruct->additionalVerifyType != NULL) {
		free(msgstruct->additionalVerifyType);
	}

	if (msgstruct->certficationSignature != NULL) {
		free(msgstruct->certficationSignature);
	}

	if (msgstruct->plainText != NULL) {
		free(msgstruct->plainText);
	}
	if (msgstruct->plainTextConvert != NULL) {
		free(msgstruct->plainTextConvert);
	}

	if (msgstruct->ptHash != NULL) {
		free(msgstruct->ptHash);
	}
	if (msgstruct->ptSign != NULL) {
		free(msgstruct->ptSign);
	}

	if (msgstruct->attestationChallenge != NULL) {
		free(msgstruct->attestationChallenge);
	}

	if (msgstruct->rpid != NULL) {
		free(msgstruct->rpid);
	}

	if (msgstruct->rpDisplayName != NULL) {
		free(msgstruct->rpDisplayName);
	}
	if (msgstruct->blacklistmsg != NULL) {
		free(msgstruct->blacklistmsg);
	}

	if (msgstruct->displayName != NULL) {
		free(msgstruct->displayName);
	}
	if (msgstruct->aaguid != NULL) {
		free(msgstruct->aaguid);
	}

	if (msgstruct->makCredentialInfoMsg != NULL) {
		free(msgstruct->makCredentialInfoMsg);
	}

 	if (msgstruct->assertionMsg != NULL) {
		free(msgstruct->assertionMsg);
	}

	if (msgstruct->whitelistmsg != NULL) {
		free(msgstruct->whitelistmsg);
	}
	if (msgstruct->assertionChallenge != NULL) {
		free(msgstruct->assertionChallenge);
	}

	if (msgstruct->b64pk != NULL) {
		free(msgstruct->b64pk);
	}
	if (msgstruct->mobileversion != NULL) {
		free(msgstruct->mobileversion);
	}

	if (msgstruct->mobilemodel != NULL) {
		free(msgstruct->mobilemodel);
	}

	if (msgstruct->appversion != NULL) {
		free(msgstruct->appversion);
	}

	if (msgstruct->authtype != NULL) {
		free(msgstruct->authtype);
	}

	if (msgstruct->deregflag != NULL) {
		free(msgstruct->deregflag);
	}

	if (msgstruct != NULL) {
		free(msgstruct);
	}

}


void msgSturctFree(InternalJsonMessage *msg){
	if(msg)
		free(msg);
}

void jsonRetFree(void *data) {
	if(data)
		free(data);
}