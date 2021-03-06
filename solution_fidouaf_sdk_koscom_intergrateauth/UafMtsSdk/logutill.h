#ifndef __logutill_H
#define __logutill_H




#ifdef WIN32
#pragma warning(disable:4996)
#pragma warning(disable:4267)
#pragma warning(disable:4133)
#pragma warning(disable:4244)
#pragma warning(disable:4819)
#endif

#ifdef __cplusplus 
extern "C" {
#endif

int initlogutillPath(char *path, char *used);
int logutill(char *fmt, ...);
void bin2hex(unsigned char *bin, int len, char *hex);

static char tbl_b2h[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

/* tbl_h2b 접근 안전을 위해 할당한 공간 */
static unsigned char tbl_h2b_pre['0'] = { 0, };

static unsigned char tbl_h2b[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* 숫자 영역 */
	0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, /* 대문자 영역 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
}; /* 소문자 영역 */

   /* tbl_h2b 접근 안전을 위해 할당한 공간 */
static unsigned char tbl_h2b_post[255 - 'f'] = { 0, };

#ifdef __cplusplus
}
#endif 


#endif /* !__logutill_H*/