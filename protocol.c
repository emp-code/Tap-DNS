#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

#include "Includes/bit.h"

#include "protocol.h"

static unsigned char id[2];
unsigned char question[256];
size_t lenQuestion;

int dnsCreateRequest(unsigned char * const rq, const char * const domain, const size_t lenDomain) {
	lenQuestion = 0;

	// Bytes 1-2: Transaction ID.
	getrandom(id, 2, 0);
	memcpy(rq + 2, id, 2);

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
	const char *dom = domain;

	while(1) {
		bool final = false;

		const char *dot = memchr(dom, '.', (domain + lenDomain) - dom);
		if (dot == NULL) {
			dot = domain + lenDomain;
			final = true;
		}

		size_t sz = dot - dom;

		question[lenQuestion] = sz;
		memcpy(question + lenQuestion + 1, dom, sz);

		lenQuestion += sz + 1;
		dom += sz + 1;

		if (final) break;
	}

	memcpy(question + lenQuestion, "\0\0\1\0\1", 5); // 0: end of question; 01: Host (A) record; 01: Internet question class
	lenQuestion += 5;

	memcpy(rq + 14, question, lenQuestion);

	// TCP DNS messages start with a 16 bit integer containing the length of the message (not counting the integer itself)
	rq[0] = 0;
	rq[1] = 17 + lenQuestion;

	return 19 + lenQuestion;
}

int dnsCreateAnswer(unsigned char * const answer, const unsigned char * const req, const uint32_t ip, const size_t offset) {
	memcpy(answer + 2, req + offset, 2); // Bytes 1-2: Transaction ID. Copy from Request.

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
	const size_t questionLen = strlen((char*)req + 12 + offset) + 5;
	if (questionLen + 30 > 99) return -8;
	memcpy(answer + 14, req + 12 + offset, questionLen);

	size_t totalLen = 14 + questionLen;

	if (ip != 0) {
		const char rr[] = {
			192, 12, // Name (pointer)
			0, 1, // Type A
			0, 1, // Class Internet
			0, 0, 0, 0, // TTL: 0
			0, 4, // 4 Bytes (IP Address)
		0};

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
size_t dnsRequest_GetDomain(const unsigned char * const req, char * const holder, const size_t offset) {
	size_t domainLen = req[12 + offset];

	// Convert domain to lowercase
	for (size_t i = 0; i < domainLen; i++)
		holder[i] = tolower(req[13 + offset + i]);

	size_t startLen = 13 + offset + domainLen;
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

int dnsRequest_GetOpcode(const unsigned char * const req) {
	return (req[4] >> 3) & 16;
}

int dnsResponse_GetResponseCode(const unsigned char * const res) {
	return res[3] & 16;
}

uint32_t dnsResponse_GetIp_get(const unsigned char * const rr, const int rrLen, uint32_t * const ttl) {
	int offset = 0;
	bool pointer = false;

	while (offset < rrLen) {
		uint8_t lenLabel = rr[offset];

		if (pointer || lenLabel == 0) {
			if (!pointer) offset++;
			pointer = false;

			uint16_t lenRecord;
			memcpy((unsigned char*)&lenRecord + 0, rr + offset + 9, 1);
			memcpy((unsigned char*)&lenRecord + 1, rr + offset + 8, 1);

			if (memcmp(rr + offset, "\0\1\0\1", 4) == 0 && lenRecord == 4) { // A Record
				memcpy((unsigned char*)ttl + 0, rr + offset + 7, 1);
				memcpy((unsigned char*)ttl + 1, rr + offset + 6, 1);
				memcpy((unsigned char*)ttl + 2, rr + offset + 5, 1);
				memcpy((unsigned char*)ttl + 3, rr + offset + 4, 1);

				uint32_t ip;
				memcpy(&ip, rr + offset + 10, 4);

				return ip;
			} else {
				offset += 10 + lenRecord;
				continue;
			}
		} else if ((lenLabel & 192) == 192) {
			offset += 2;
			pointer = true;
			continue;
		}

		offset += 1 + lenLabel;
	}

	return 0;
}

static uint32_t validIp(const uint32_t ip) {
	const uint8_t b1 = ip & 0xFF;
	const uint8_t b2 = (ip >>  8) & 0xFF;
	const uint8_t b3 = (ip >> 16) & 0xFF;
//	const uint8_t b4 = (ip >> 24) & 0xFF;

	return (
	   (b1 == 0)
	|| (b1 == 10)
	|| (b1 == 100 && b2 >= 64 && b2 <= 127)
	|| (b1 == 127)
	|| (b1 == 169 && b2 == 254)
	|| (b1 == 172 && b2 >= 16 && b2 <= 31)
	|| (b1 == 192 && b2 == 0  && b3 == 0)
	|| (b1 == 192 && b2 == 0  && b3 == 2)
	|| (b1 == 192 && b2 == 88 && b3 == 99)
	|| (b1 == 192 && b2 == 168)
	|| (b1 == 198 && b2 >= 18 && b2 <= 19)
	|| (b1 == 198 && b2 == 51 && b3 == 100)
	|| (b1 == 203 && b2 == 0  && b3 == 113)
	|| (b1 >= 224 && b1 <= 239)
	|| (b1 >= 240)
	) ? 0 : ip;
}

// offset: TAPDNS_OFFSET_TCP or TAPDNS_OFFSET_UDP
uint32_t dnsResponse_GetIp(const unsigned char * const res, const int resLen, uint32_t * const ttl) {
	if (memcmp(id, res + 2, 2) != 0) puts("WARNING: ID mismatch");
	if (memcmp(res + 14, question, lenQuestion) != 0) puts("WARNING: Question section does not match");

	if (dnsResponse_GetResponseCode(res + 4) != 0) return 0;

	if (res[6] != 0 || res[7] != 1) puts("WARNING: Invalid question count");

	uint16_t answerCount;
	memcpy((unsigned char*)&answerCount + 0, res + 9, 1);
	memcpy((unsigned char*)&answerCount + 1, res + 8, 1);
	if (answerCount < 1) return 0;

	uint32_t ttl32;
	const uint32_t ip = dnsResponse_GetIp_get(res + 14 + lenQuestion, resLen - 14 - lenQuestion, &ttl32);
	if (ip == 0) return 1;

	*ttl = ttl32;
	return validIp(ip);
}
