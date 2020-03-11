// bit.c: Get or set a specific bit in a byte

// Get bit #1-8 from a byte
int getBit(const char* byte, const int pos) {
	const unsigned char tmp = *(byte + ((pos - 1) / 8));
	const unsigned char mask = 1 << (8 - pos);
	return (tmp & mask) > 0;
}

// Set bit #1-8 on a byte
void setBit(char* byte, const int pos, const int value) {
	unsigned char* pTmp = (unsigned char*)byte + (pos - 1) / 8;
	const unsigned char mask = 1 << (8 - pos);

	if (value > 0)
		*pTmp |= mask;
	else
		*pTmp &= ~mask;
}
