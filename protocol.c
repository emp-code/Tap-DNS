#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

#include "protocol.h"

int dnsCreateRequest(const uint16_t id, unsigned char * const rq, unsigned char * const question, size_t * const lenQuestion, const unsigned char * const domain, const size_t lenDomain) {
	memcpy(rq + 2, &id, 2);

	// 16-bit flags field, entry counts
	memcpy(rq + 4, "\1\0\0\1\0\0\0\0\0\0", 10);
	/*	00000001
		[1] QR (Query/Response). 0 = Query, 1 = Response.
		[4] OPCODE (kind of query). 0000 = Standard query.
		[1] Authoritative answer. N/A.
		[1] Truncated message. No.
		[1] Recursion desired. Yes.

		00000000
		[1] Recursion available. N/A.
		[3] Reserved. Always zero.
		[4] Response code. N/A.

		[16] QDCOUNT: One question entry (00000000 00000001).
		[16] ANCOUNT: Zero.
		[16] NSCOUNT: Zero.
		[16] ARCOUNT: Zero.
	*/

	// Convert domain name to question format
	const unsigned char *dom = domain;

	while(1) {
		bool final = false;

		const unsigned char *dot = memchr(dom, '.', (domain + lenDomain) - dom);
		if (dot == NULL) {
			dot = domain + lenDomain;
			final = true;
		}

		const size_t sz = dot - dom;

		question[*lenQuestion] = sz;
		memcpy(question + *lenQuestion + 1, dom, sz);

		(*lenQuestion) += sz + 1;
		dom += sz + 1;

		if (final) break;
	}

	memcpy(question + *lenQuestion, "\0\0\1\0\1", 5); // 0: end of name; 01: A record; 01: Internet question class
	(*lenQuestion) += 5;

	memcpy(rq + 14, question, *lenQuestion);

	// TCP DNS messages start with a uint16_t indicating the length of the message (excluding the uint16_t itself)
	rq[0] = 0;
	rq[1] = 14 + *lenQuestion;

	return 16 + *lenQuestion;
}

int dnsCreateAnswer(unsigned char * const answer, const unsigned char * const req, const uint32_t ip) {
	memcpy(answer + 2, req, 2); // ID, copy from request.

	answer[4] = 129;
	/*	10000001
		[1] QR (Query/Response). 0 = Query, 1 = Response.
		[4] OPCODE (kind of query). 0000 = Standard query.
		[1] Authoritative answer. N/A.
		[1] Truncated message. No.
		[1] Recursion desired. Yes.
	*/

	answer[5] = (ip == 0) ? 133 : 128;
	/* 10000x0x
		[1] Recursion available. Yes.
		[3] Reserved. Always zero.
		[4] Response code.
			0000 NoError
			0101 Refused
	*/

	// Entry counts
	memcpy(answer + 6, (ip == 0) ? "\0\1\0\0\0\0\0\0" : "\0\1\0\1\0\0\0\0", 8);
	/*
		[16] QDCOUNT: One  (00000000 00000001).
		[16] ANCOUNT: Zero/One.
		[16] NSCOUNT: Zero (00000000 00000000).
		[16] ARCOUNT: Zero (00000000 00000000).
	*/

	// Question: copy from request
	const size_t questionLen = strlen((char*)req + 12) + 5;
	if (questionLen + 30 > 99) return -8;
	memcpy(answer + 14, req + 12, questionLen);

	size_t totalLen = 14 + questionLen;

	if (ip != 0) {
		memcpy(answer + totalLen,
			(const unsigned char[]) {
				192, 12, // Name (pointer)
				0, 1, // Type A
				0, 1, // Class Internet
				0, 0, 0, 0, // TTL: 0
				0, 4 // 4 Bytes (IP Address)
			}
		, 12);
		memcpy(answer + totalLen + 12, &ip, 4);
		totalLen += 16;
	}

	// TCP DNS messages start with a uint16_t indicating the length of the message (excluding the uint16_t itself)
	answer[0] = 0;
	answer[1] = totalLen - 2;

	return totalLen;
}

// Get the requested domain in the request
size_t dnsRequest_GetDomain(const unsigned char * const req, char * const holder) {
	size_t domainLen = req[12];

	// Convert domain to lowercase
	for (size_t i = 0; i < domainLen; i++)
		holder[i] = tolower(req[13 + i]);

	size_t startLen = 13 + domainLen;
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

static uint32_t dnsResponse_GetIp_get(const unsigned char * const rr, const int rrLen, uint32_t * const ttl) {
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

static int getAnswerCount(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const question, const size_t lenQuestion) {
	if (lenRes < 12 + (int)lenQuestion) {puts("DNS answer too short"); return 0;}
	if (memcmp(res, &reqId, 2) != 0) {puts("ID mismatch"); return 0;}

	// 2: 128=QR: Answer (1); 64+32+16+8=120 OPCODE: Standard query (0000); 4=AA: Authorative Answer; 2=TC: Truncated; 1=RD: Recursion Desired
	// 3: 128=RA: Recursion Available; 64=Z: Zero (Reserved); 32=AD: Authentic Data; 16=CD: Checking Disabled; 15=RCODE: No Error (0000)
	if (res[2] != 129 || (res[3] & 192) != 128) {puts("Invalid DNS answer"); return 0;}
	if ((res[3] & 15) != 0) {printf("DNS Error: %u\n", res[3] & 15); return 0;}

	if (memcmp(res +  4, "\0\1", 2) != 0) {puts("QDCOUNT mismatch"); return 0;}
	// 6,7 ANCOUNT
	if (memcmp(res +  8, "\0\0", 2) != 0) {puts("NSCOUNT mismatch"); return 0;}
	if (memcmp(res + 10, "\0\0", 2) != 0) {puts("ARCOUNT mismatch"); return 0;}
	if (memcmp(res + 12, question, lenQuestion) != 0) {puts("Question mismatch"); return 0;}

	uint16_t answerCount;
	memcpy((unsigned char*)&answerCount + 0, res + 7, 1);
	memcpy((unsigned char*)&answerCount + 1, res + 6, 1);
	return answerCount;
}

uint32_t dnsResponse_GetIp(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const question, const size_t lenQuestion, uint32_t * const ttl) {
	const int answerCount = getAnswerCount(reqId, res, lenRes, question, lenQuestion);
	if (answerCount <= 0) return 0;

	return validIp(dnsResponse_GetIp_get(res + 12 + lenQuestion, lenRes - 12 - lenQuestion, ttl));
}
