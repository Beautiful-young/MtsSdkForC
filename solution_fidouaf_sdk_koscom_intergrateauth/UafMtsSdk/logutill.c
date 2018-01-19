#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "logutill.h"

char* LOGPATH = NULL;
char* LOGCREATE = NULL;

int logutill(char *fmt, ...)
{
	va_list ap;
	FILE *fp;
	int i;

	time_t timer;
	struct tm *t;
	char tempLogPath[160];
	/* gets time of day */
	timer = time(NULL);
	/* converts date/time to a structure */
	if (strcmp(LOGCREATE, "yes") == 0)
	{
		t = localtime(&timer);
		sprintf(tempLogPath, "%s_%04d%02d%02d.log", LOGPATH, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
		fp = fopen(tempLogPath, "a");
		if (fp == NULL) return 0;
		i = fprintf(fp, "%04d/%02d/%02d %02d:%02d:%02d : ", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
		va_start(ap, fmt);
		i = vfprintf(fp, fmt, ap);
		va_end(ap);
		fclose(fp);
	}

	return i;
}

int initlogutillPath(char *path, char *used)
{
	LOGPATH = path;
	LOGCREATE = used;
	return 0;
}

/** 바이너리 숫자를 hex 문자열 변환
*
*/
void bin2hex(unsigned char *bin, int len, char *hex)
{
	register char *dst;
	register unsigned char *src;

	if (len < 1 || bin == NULL || hex == NULL) return;

	dst = hex;
	src = bin;
	while (len-- > 0) {
		*dst++ = tbl_b2h[(*src >> 4) & 0x0F];
		*dst++ = tbl_b2h[*src & 0x0F];
		src++;
	}

	*dst = 0;
#ifdef DUMP
	{
		FILE *fp;
		fp = fopen(".hex", "wb");
		fwrite(hex, 1, strlen(hex), fp);
		fclose(fp);
	}
#endif
}