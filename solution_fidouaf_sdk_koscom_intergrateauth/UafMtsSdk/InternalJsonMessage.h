#pragma once

typedef struct InternalJsonMessage {
	char* version;			//	string	
	size_t source = -99;			//	integer	
	size_t target = -99;			//	integer	
	char* activecode;		//	string	
	char* appid;			//	string	
	char* userid;			//	string	
	char* sessionid;		//	string	
	size_t mobiletype = -99;		//	integer	
	char* mobileno;		//	stirng
	char* pushid;			//	string	
	char* errorcode;		//	string	
	char* errormessage;	//	string	
	char* rpwebsession;	//	string	
	char* agenturl;		//	string	
	char* operation;		//	string	
	char* regrequestmsg;	//	string	
	char* regresponsemsg;	//	string	
	char* authrequestmsg;	//	string	
	char* authresponsemsg;	//	string	
	char* deregrequestmsg;	//	string
	char* devmode;			//	string

	char* authenticationmode; //string

	char* serverEndPoint;
	char* tlsServerCertificate;
	char* tlsUnique;
	char* cid_pubkey;

	char* contentType;
	char* content;
	char* contentEncodingType;

	char* origin;
	char* u2f_regrequestmsg;
	char* u2f_regresponsemsg;
	char* u2f_authrequestmsg;
	char* u2f_authresponsemsg;
	char* u2f_deleterequestmsg;

	char* u2f_clientdata;

	char* sslcert;

	char* additionalVerifyType;
	char* certficationSignature;

	char* plainText;
	char* plainTextConvert;
	char* ptHash;
	char* ptSign;

	char* attestationChallenge;
	char* rpid;
	char* rpDisplayName;
	char* blacklistmsg;
	char* displayName;
	char* aaguid;
	char* makCredentialInfoMsg;
	char* assertionMsg;
	char* whitelistmsg;
	char* assertionChallenge;
	char* b64pk;

	char* mobileversion;
	char* mobilemodel;
	char* appversion;
	char* authtype;
	char* deregflag;
}InternalJsonMessage;

InternalJsonMessage* parse(const char *input);
void msgSturctFree(InternalJsonMessage *msg);