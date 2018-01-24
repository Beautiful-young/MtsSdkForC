#ifndef __authreqmsg_h
#define __authreqmsg_h



void extensionAuthReqB64Url_free(char *ptr);
char* setExtensionAuthReqB64Url(char* p_b64authReq, char* p_simplekey, char* p_devid, char* p_nonid);

#endif // !__authreqmsg_h