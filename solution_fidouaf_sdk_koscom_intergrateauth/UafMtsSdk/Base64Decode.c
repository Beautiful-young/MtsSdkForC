#include "common.h"

/* The size of the output buffer must not be less than
* 3/4 the size of the input buffer.
*/
int Base64Url_Decode(const unsigned char *szDecoding, size_t nSize, unsigned char *szOutput, size_t *pnOutSize)
{
	Base64Context bContext;

	int c;
	size_t index, lp = 0; /* lp : pointer to input, index : pointer to output */
	int nDigit;

	if (!szDecoding || !nSize || !szOutput || !pnOutSize) {
		return -1;
	}

	bContext.m_szInput = (unsigned char*)szDecoding;
	bContext.m_nInputSize = nSize;
	bContext.m_nBitsRemaining = 0;
	bContext.m_lBitStorage = 0;

	/* Clear the output buffer
	MEMSET(szOutput, 0, bContext.m_nInputSize + 1);
	kang : 위험소지가 많아서 삭제 */

	/* Decode the Input
	*/
	for (lp = 0, index = 0; lp < bContext.m_nInputSize; lp++) {
		c = bContext.m_szInput[lp];
		nDigit = nDecodeUrl[c & 0x7F];

		if (nDigit < -1) {		/* kang : illegal char */
			return -1;
		}
		else if (nDigit == -1)	/* kang : padding ('=') */
			;
		else if (nDigit >= 0)
			/* index (index into output) is incremented by write_bits() */
			Base64_write_bits(&bContext, nDigit & 0x3F, 6, szOutput, &index);
		else					/* kang : not occur */
			;
	}

	*pnOutSize = index;
	return 0;
}