// Details of DNS server to use
#define TAPDNS_ADDR_FAMILY AF_INET // IPv4
#define TAPDNS_SERVER_ADDR "1.1.1.1" // Cloudflare DNS
#define TAPDNS_SERVER_PORT 53

#define TAPDNS_BUFLEN 512
#define TAPDNS_OFFSET_TCP 2
#define TAPDNS_OFFSET_UDP 0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "Includes/bit.h"

#include "database.h"
#include "domain.h"
#include "protocol.h"

#include "respond.h"

int dnsSendAnswer(const int sockIn, const char* req, const int ip) {
	char answer[100];
	const int len = dnsCreateAnswer(answer, req, ip);
	if (len < 0) return len;

	const int ret = send(sockIn, answer, len, 0);

	if (ret < 0) {perror("Sending message"); return ret;}
	if (ret != len) return ret;

	return 0;
}

int queryDns(const char* domain, const size_t domainLen, int* ttl) {
	char req[100];
	const int reqLen = dnsCreateRequest(req, domain, domainLen);

	struct sockaddr_in dnsAddr;
	const socklen_t addrlen = sizeof(dnsAddr);
	memset(&dnsAddr, 0, addrlen);
	dnsAddr.sin_port = htons(TAPDNS_SERVER_PORT);
	dnsAddr.sin_family = TAPDNS_ADDR_FAMILY;
	inet_pton(TAPDNS_ADDR_FAMILY, TAPDNS_SERVER_ADDR, &dnsAddr.sin_addr.s_addr);

	const int sockDns = socket(TAPDNS_ADDR_FAMILY, SOCK_STREAM, 0);
	if (sockDns == -1) {perror("Creating socket for connecting to DNS server"); return 1;}
	if (connect(sockDns, (struct sockaddr*)&dnsAddr, addrlen) < 0) {perror("Connecting to DNS server"); return 1;}

	send(sockDns, req, reqLen, 0);

	char res[TAPDNS_BUFLEN + 1];
	const int ret = recv(sockDns, res, TAPDNS_BUFLEN, 0);
	close(sockDns);

	return dnsResponse_GetIp(TAPDNS_OFFSET_TCP, res, ret, ttl);
}

// Respond to a client's DNS request
int respond(const int sock) {
	// Read the request from the client
	char req[TAPDNS_BUFLEN + 1];
	const int reqLen = recv(sock, req, TAPDNS_BUFLEN, 0);

	// Get the domain that was requested
	char domain[TAPDNS_MAXLEN_DOMAIN];
	const size_t domainLen = dnsRequest_GetDomain(req, domain);

	printf("DEBUG: Domain '%s' requested (length: %d bytes)\n", domain, reqLen);

	if (dnsRequest_GetOpcode(req) != 0) {
		puts("DEBUG: Not standard OPCODE");
		dnsSendAnswer(sock, req, 0); // 0.0.0.0
		return 0;
	}

	if (isInvalidDomain(domain, domainLen)) {
		puts("DEBUG: Invalid domain");
		dnsSendAnswer(sock, req, 0);
		return 0;
	}

	if (strcmp(domain, "localhost") == 0 || memcmp(domain + domainLen - 4, ".tap", 4) == 0) {
		dnsSendAnswer(sock, req, 16777343); // 127.0.0.1
		return 0;
	}

	int ip = dbGetIp(domain, domainLen);

	if (ip == 0) {
		// IP does not exist in the database or there was an error getting it
		
		// Query the DNS server for a response
		int ttl;
		ip = queryDns(domain, domainLen, &ttl);
		printf("DEBUG: TTL=%d\n", ttl);

		if (ip == 1) {
			// Server-side error (such as non-existent domain)
			dnsSendAnswer(sock, req, 0); // 0.0.0.0
			puts("DEBUG: Server-side error");
			return -2;
		} else if (ip == 0) {
			// Failed to parse the server's response
			puts("ERROR: Failed to parse the server's response");
			return -3;
		}

		// Successfully got response from the server, save it to the database
		dbSetIp(domain, domainLen, ip);
	}

	// Everything OK, respond to the client
	dnsSendAnswer(sock, req, ip);
	return 0;
}
