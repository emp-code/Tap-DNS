#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "Includes/bit.h"

#include "protocol.h"

int dnsCreateRequest(char rq[100], const char* domain, const size_t domainLen) {
	memset(rq, 0, 99);

	// Bytes 1-2: Transaction ID.
	FILE* fp = fopen("/dev/random", "rb");
	if (fp != NULL) {
		rq[2] = fgetc(fp);
		rq[3] = fgetc(fp);
		fclose(fp);
	}

	setBit(rq + 4, 1, 0); // Byte 3, Bit 1: QR (Query/Response). 0 = Query, 1 = Response.

	// Byte 3, Bits 2-5 (4 bits): OPCODE (kind of query). 0000 = Standard query.
	setBit(rq + 4, 2, 0);
	setBit(rq + 4, 3, 0);
	setBit(rq + 4, 4, 0);
	setBit(rq + 4, 5, 0);

	// Byte 3: Bits 6-8; Byte 4, Bits 1-4
	setBit(rq + 4, 6, 0); // Byte 3, Bit 6: Authoritative answer. N/A.
	setBit(rq + 4, 7, 0); // Byte 3, Bit 7: Truncated message.
	setBit(rq + 4, 8, 1); // Byte 3, Bit 8: Recursion desired.
	setBit(rq + 5, 1, 0); // Byte 4, Bit 1: Recursion available. N/A.
	setBit(rq + 5, 2, 0); // Byte 4. Bit 2: Reserved. Must be 0.
	setBit(rq + 5, 3, 0); // Byte 4. Bit 3: Reserved. Must be 0.
	setBit(rq + 5, 4, 0); // Byte 4. Bit 4: Reserved. Must be 0.

	// Response code. N/A.
	setBit(rq + 5, 5, 0); // Byte 4. Bit 5.
	setBit(rq + 5, 6, 0); // Byte 4. Bit 6.
	setBit(rq + 5, 7, 0); // Byte 4. Bit 7.
	setBit(rq + 5, 8, 0); // Byte 4. Bit 8.

	// Bytes 5-6: QDCOUNT: Number of entries in the question section.
	rq[6] = 0;
	rq[7] = 1;

	memset(rq +  8, 0, 2); // Bytes 7-8: ANCOUNT: Number of resource records in the answer section. N/A.
	memset(rq + 10, 0, 2); // Bytes 9-10: NSCOUNT: Number of name server resource records in the authority records section. N/A.
	memset(rq + 12, 0, 2); // Bytes 11-12: ARCOUNT: Number of resource records in the additional records section. N/A.

	// Bytes 13+: Question section

	// Convert domain name to question format
	char *dom = domain;
	size_t offset = 0;
	while(1) {
		int b = 0;

		char *dot = strchr(dom, '.');
		if (dot == NULL) {
			dot = domain + strlen(domain);
			b = 1;
		}

		size_t sz = dot - dom;

		rq[14 + offset] = sz;
		memcpy(rq + 14 + offset + 1, dom, sz);
		offset += sz + 1;

		dom += sz + 1;
		dot = strchr(dom, '.');

		if (b == 1) break;
	}

	memcpy(rq + 14 + offset, "\0\0\1\0\1", 5); // 0: end of question; 01: Host (A) record; 01: Internet question class

	size_t rqLen = 17 + offset;

	// TCP DNS messages start with a 16 bit integer containing the length of the message (not counting the integer itself)
	rq[0] = 0;
	rq[1] = rqLen;

	return rqLen + 2;
}

int dnsCreateAnswer(char* answer, const char* req, const int ip) {
	memset(answer, 0, 99);

	memcpy(answer + 2, req + 2, 2); // Bytes 1-2: Transaction ID. Copy from Request.

	setBit(answer + 4, 1, 1); // Byte 3, Bit 1: QR (Query/Response). 0 = Query, 1 = Response.

	// Byte 3: Bits 2-5 (4 bits): OPCODE (kind of query). 0000 = Standard query.
	setBit(answer + 4, 2, 0);
	setBit(answer + 4, 3, 0);
	setBit(answer + 4, 4, 0);
	setBit(answer + 4, 5, 0);

	// Byte 3: Bits 6-8; Byte 4, Bits 1-4
	setBit(answer + 4, 6, 1); // Byte 3, Bit 6: Authoritative answer.
	setBit(answer + 4, 7, 0); // Byte 3, Bit 7: Truncated message.
	setBit(answer + 4, 8, 1); // Byte 3, Bit 8: Recursion desired.
	setBit(answer + 5, 1, 1); // Byte 4, Bit 1: Recursion available.
	setBit(answer + 5, 2, 0); // Byte 4. Bit 2: Reserved. Must be 0.
	setBit(answer + 5, 3, 0); // Byte 4. Bit 3: Reserved. Must be 0.
	setBit(answer + 5, 4, 0); // Byte 4. Bit 4: Reserved. Must be 0.

/* Response code (4 bits)
	0000 NoError
	0001 FormErr
	0010 ServFail
	0011 NXDomain
	0100 NotImp
	0101 Refused
	0110 YXDomain
	0111 YXRRSet
	1000 NXRRSet
	1001 NotAuth
	1010 NotZone
	1011 RESERVED11
	1100 RESERVED12
	1101 RESERVED13
	1110 RESERVED14
	1111 RESERVED15
*/

	if (ip == 0) { // IP 0.0.0.0: 0101 Refused
		setBit(answer + 5, 5, 0); // Byte 4. Bit 5.
		setBit(answer + 5, 6, 1); // Byte 4. Bit 6.
		setBit(answer + 5, 7, 0); // Byte 4. Bit 7.
		setBit(answer + 5, 8, 1); // Byte 4. Bit 8.
	} else { // Any other IP: 0000 NoError
		setBit(answer + 5, 5, 0); // Byte 4. Bit 5.
		setBit(answer + 5, 6, 0); // Byte 4. Bit 6.
		setBit(answer + 5, 7, 0); // Byte 4. Bit 7.
		setBit(answer + 5, 8, 0); // Byte 4. Bit 8.
	}

	// Bytes   5-6: QDCOUNT: Number of entries in the question section.
	answer[6] = 0;
	answer[7] = 1;

	// Bytes 7-8: ANCOUNT: Number of resource records in the answer section.
	answer[8] = 0;
	if (ip == 0)
		answer[9] = 0;
	else 
		answer[9] = 1;

	// Bytes 9-10: NSCOUNT: Number of name server resource records in the authority records section.
	answer[10] = 0;
	answer[11] = 0;

	// Bytes 11-12: ARCOUNT: Number of resource records in the additional records section.
	answer[12] = 0;
	answer[13] = 0;

	// Bytes 13+ Question. Copy from Request.
	const size_t questionLen = strlen(req + 14) + 5;
	if (questionLen + 30 > 99) return -8;
	memcpy(answer + 14, req + 14, questionLen);

	size_t totalLen = 14 + questionLen;

	if (ip != 0) {
		char rr[] = {
			'\xc0', '\x0c', // Name (pointer)
			'\0', '\1', // Type A
			'\0', '\1', // Class Internet
			'\0', '\0', '\0', '\0', // TTL: 0
			'\0', '\4', // 4 Bytes (IP Address)
		'\0'};

		memcpy(answer + totalLen, rr, 12);
		memcpy(answer + totalLen + 12, &ip, 4);
		totalLen += 16;
	}

	// TCP DNS messages start with a 16 bit integer containing the length of the message (not counting the integer itself)
	answer[0] = 0;
	answer[1] = totalLen - 2;

	return totalLen;
}

// Get the requested domain in the request
size_t dnsRequest_GetDomain(const char* req, char* holder) {
	// Values 'should' be 12/13 instead of 14/15, but with TCP there's 2 extra bytes in the beginning
	size_t domainLen = req[14];

	// Convert domain to lowercase
	for (size_t i = 0; i < domainLen; i++)
		holder[i] = tolower(req[15 + i]);

	size_t startLen = 15 + domainLen;
	while(1) {
		const size_t addLen = req[startLen];
		if (addLen == 0) break;

		holder[domainLen] = '.';

		for (size_t leftLen = addLen; leftLen > 0; leftLen--)
			holder[domainLen + 1 + addLen - leftLen] = tolower(req[startLen + 1 + addLen - leftLen]);

		domainLen += addLen + 1;
		startLen += addLen + 1;
	}

	holder[domainLen] = '\0';
	return domainLen;
}

int dnsResponse_GetIp_get(const char* res, const int resLen) {
	for (int i = 0; i < (resLen - 4); i++) {
		if (memcmp(res + i, "\0\1\0\1\xc0\x0c\0\1\0\1", 10) == 0)
			return *((int*)(res + i + 16));
	}

	return 0;
}

// offset: TAPDNS_OFFSET_TCP or TAPDNS_OFFSET_UDP
int dnsResponse_GetIp(const int offset, const char* res, const int resLen) {
	// Get response code
	char code[5];
	sprintf(code, "%d%d%d%d",
		getBit(res + 3 + offset, 5), // Byte 4. Bit 5.
		getBit(res + 3 + offset, 6), // Byte 4. Bit 6.
		getBit(res + 3 + offset, 7), // Byte 4. Bit 7.
		getBit(res + 3 + offset, 8)  // Byte 4. Bit 8.
	);

	if (memcmp(code, "0000", 4) != 0) return 1; // 0000 = no error

	uint16_t answerCount;
	memcpy(&answerCount, res + 6 + offset, 2);
	if (answerCount == 0) return 1; // Must have at least 1 answer.

	return dnsResponse_GetIp_get(res, resLen);
}
