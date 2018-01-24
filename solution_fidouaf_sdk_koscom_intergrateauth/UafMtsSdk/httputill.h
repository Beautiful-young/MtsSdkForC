#ifndef __httputill_H
#define __httputill_H



void saimplehttps(char* url, char* data);
int httpsPost(char *pemcert, char* url, char* data, char** outData, size_t *outDataLen);
void retHttpDataFree(char *data);

#endif // !__httputill_H