// bit.c: Get or set a specific bit in a byte

// Get bit #1-8 from a byte
int getBit(const char *byte, const int bit) {
	const unsigned char tmp = *(byte + ((bit - 1) / 8));
	const unsigned char mask = 1 << (8 - bit);
	return (tmp & mask) > 0;
}

// Set bit #1-8 on a byte
void setBit(char *byte, const int bit, const int value) {
	unsigned char *pTmp = (unsigned char*)byte + (bit - 1) / 8;
	const unsigned char mask = 1 << (8 - bit);

	if (value > 0)
		*pTmp |= mask;
	else
		*pTmp &= ~mask;
}
