#include "common.h"

/* read as number of bits (nNumBits) as wanted from input */
size_t Base64_read_bits(Base64Context *pbContext, int nNumBits, int *pBitsRead, size_t *lp)
{
	long lScratch;
	int c;

	/* if remain bits number of lBitStorage is less than 'nNumBits' and it is not end of input,
	* one byte (eight bits) is readed to buffer (lBitStorage) from input */
	while ((pbContext->m_nBitsRemaining < nNumBits) && ((*lp) < pbContext->m_nInputSize))
	{
		c = pbContext->m_szInput[(*lp)++];
		pbContext->m_lBitStorage <<= 8;
		pbContext->m_lBitStorage |= (c & 0xff);
		pbContext->m_nBitsRemaining += 8;
	}

	if (pbContext->m_nBitsRemaining < nNumBits) /* if end of input */
	{
		lScratch = pbContext->m_lBitStorage << (nNumBits - pbContext->m_nBitsRemaining);
		/* 모자라는 비트는 shift 연산으로 인해 남은 비트의 오른쪽에 0으로 채워짐 */
		*pBitsRead = pbContext->m_nBitsRemaining;
		pbContext->m_nBitsRemaining = 0;
	}
	else /* if number of bits in lBitStorage is greater than or equal to nNumBits */
	{
		lScratch = pbContext->m_lBitStorage >> (pbContext->m_nBitsRemaining - nNumBits);
		*pBitsRead = nNumBits;
		pbContext->m_nBitsRemaining -= nNumBits;
	}

	return (size_t)lScratch & m_nMask[nNumBits]; /* Base64의 경우 입력의 끝을 제외하고 항상 6비트 출력 */
}

/* nBits : bits to output , nNumBits : number of bits to output */
void Base64_write_bits(Base64Context *pbContext, size_t nBits, int nNumBits, unsigned char *szOutput, size_t *index)
{
	unsigned char nScratch;

	pbContext->m_lBitStorage = (pbContext->m_lBitStorage << nNumBits) | nBits;
	pbContext->m_nBitsRemaining += nNumBits;

	while (pbContext->m_nBitsRemaining > 7)
	{
		nScratch = (unsigned char)(pbContext->m_lBitStorage >> (pbContext->m_nBitsRemaining - 8));
		szOutput[(*index)++] = (unsigned char)(nScratch & 0xFF);
		pbContext->m_nBitsRemaining -= 8;
	}
}

size_t Base64_GetEncodeLength(size_t nInputLen)
{
	size_t nInputBitLen = 0, nB64UnitLen = 0,
		nPaddingLen = 0, nRetVal = 0;

	if (nInputLen == 0)
		return nRetVal;

	nInputBitLen = nInputLen * 8;				/* 비트수 계산.  1byte = 8bit. */
	nB64UnitLen = (nInputBitLen + 5) / 6;		/* B64 char 갯수 계산. 6:8로 늘어남. */
	nPaddingLen = (nB64UnitLen + 1) % 4;			/* 패딩 길이 계산.  아웃풋의 길이는 항상 4의 배수이어야 하기 때문에. */
	nPaddingLen = nPaddingLen ^ 0x00000001;
	nRetVal = nB64UnitLen + nPaddingLen;	/* 전체 결과 길이 계산 */

	return nRetVal;
}

size_t uuid_v4_gen(char *buffer)
{
	union
	{
		struct
		{
			uint32_t time_low;
			uint16_t time_mid;
			uint16_t time_hi_and_version;
			uint8_t  clk_seq_hi_res;
			uint8_t  clk_seq_low;
			uint8_t  node[6];
		};
		uint8_t __rnd[16];
	} uuid;

	int rc = RAND_bytes(uuid.__rnd, sizeof(uuid));

	uuid.clk_seq_hi_res = (uint8_t)((uuid.clk_seq_hi_res & 0x3F) | 0x80);
	uuid.time_hi_and_version = (uint16_t)((uuid.time_hi_and_version & 0x0FFF) | 0x4000);

	snprintf(buffer, 38, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
		uuid.clk_seq_hi_res, uuid.clk_seq_low,
		uuid.node[0], uuid.node[1], uuid.node[2],
		uuid.node[3], uuid.node[4], uuid.node[5]);

	return rc;
}

size_t getSessionID(char *buffer)
{
	union
	{
		struct
		{
			uint32_t time_low;
			uint16_t time_mid;
			uint16_t time_hi_and_version;
			uint8_t  clk_seq_hi_res;
			uint8_t  clk_seq_low;
			uint8_t  node[6];
		};
		uint8_t __rnd[16];
	} uuid;

	int rc = RAND_bytes(uuid.__rnd, sizeof(uuid));

	uuid.clk_seq_hi_res = (uint8_t)((uuid.clk_seq_hi_res & 0x3F) | 0x80);
	uuid.time_hi_and_version = (uint16_t)((uuid.time_hi_and_version & 0x0FFF) | 0x4000);

	snprintf(buffer, 38, "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
		uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
		uuid.clk_seq_hi_res, uuid.clk_seq_low,
		uuid.node[0], uuid.node[1], uuid.node[2],
		uuid.node[3], uuid.node[4], uuid.node[5]);

	return rc;
}