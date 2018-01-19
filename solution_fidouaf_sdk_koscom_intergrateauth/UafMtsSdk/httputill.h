#pragma once
void saimplehttps(char* url, char* data);
int httpsPost(char *pemcert, char* url, char* data, char** outData, size_t *outDataLen);
void retHttpDataFree(char *data);