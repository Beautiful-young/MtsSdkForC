#include "common.h"

int Base64Url_Encode(const unsigned char *szEncoding, size_t nSize, unsigned char *sOutput, size_t *pnOutSize)
{
	Base64Context bContext;

	size_t nDigit;
	int nNumBits = 6;
	size_t index = 0, lp = 0, tmpoutlen = 0; /* lp : pointer to input, index : pointer to output */

	if (!szEncoding || !nSize || !sOutput || !pnOutSize) {
		return -1;
	}

	bContext.m_szInput = szEncoding;
	bContext.m_nInputSize = nSize;
	bContext.m_nBitsRemaining = 0;
	bContext.m_lBitStorage = 0;

	nDigit = Base64_read_bits(&bContext, nNumBits, &nNumBits, &lp);

	while (nNumBits > 0)
	{
		sOutput[index] = m_sBase64UrlAlphabet[nDigit]; sOutput[++index] = '\0';
		nDigit = Base64_read_bits(&bContext, nNumBits, &nNumBits, &lp);
	}

	/* Pad with '=' as per RFC 1521 */
	tmpoutlen = strlen((char*)sOutput);
	while (tmpoutlen % 4 != 0)
	{
		sOutput[index] = '='; sOutput[++index] = '\0';
		tmpoutlen++;
	}

	*pnOutSize = index;
	return 0;
}