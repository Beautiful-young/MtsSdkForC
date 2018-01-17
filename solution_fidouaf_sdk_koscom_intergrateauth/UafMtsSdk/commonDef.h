#pragma once

const char *E_TYPE_SUCCESS_STR = "00000000";

const char *INTERNALVERSION = "1.0";

const size_t DIRECTION_BROWSER = 1;
const size_t DIRECTION_RPWEBAPP = 2;
const size_t DIRECTION_FIDOSDK = 4;
const size_t DIRECTION_FIDOSERVERAGENT = 8;
const size_t DIRECTION_FIDOSERVER = 16;
const size_t DIRECTION_PUSHSERVER = 32;
const size_t DIRECTION_FIDOCLIENT = 64;

const size_t DIRECTION_FIDOU2FSERVERAGENT = 128;
const size_t DIRECTION_FIDOU2FSERVER = 256;
const size_t DIRECTION_FIDOU2FCLIENT = 512;

const char *OPERATION_DSIGN = "dsign";
const char *OPERATION_ACTIVECODE = "activecode";

const char *OPERATION_U2F_REG = "u2f_reg";
const char *OPERATION_U2F_AUTH = "u2f_auth";


const char* CURVER_ASSERTIONSCHEME = "UAFV1TLV";

const char* OPERATION_REG = "reg";
const char* OPERATION_AUTH = "auth";
const char* OPERATION_DEREG = "dereg";

const char* CONTEXTTYPE_TEXTPLAIN = "text/plain";
const char* CONTEXTTYPE_IMAGEPNG = "image/png";

const char* CONTENTENCODINGTYPE_PLAINTEST = "plaintext";
const char* CONTENTENCODINGTYPE_BASE64URL = "base64url";
const char* CONTENTENCODINGTYPE_HEXSTRING = "hexstring";
const char*AUTHENTICATIONMODE_REG = "1";
const char*AUTHENTICATIONMODE_AUTH = "1";
const char*AUTHENTICATIONMODE_TC = "2";
const char*AUTHENTICATIONMODE_SS = "3";