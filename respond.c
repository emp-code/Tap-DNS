// Details of DNS server to use
#define TAPDNS_ADDR_FAMILY AF_INET // IPv4
#define TAPDNS_SERVER_ADDR "1.1.1.1" // Cloudflare DNS
#define TAPDNS_SERVER_PORT 53

#define TAPDNS_BUFLEN 512
#define TAPDNS_OFFSET_TCP 2
#define TAPDNS_OFFSET_UDP 0

#define TAPDNS_TYPE_BLOCK1 30

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#include "database.h"
#include "domain.h"
#include "protocol.h"

#include "respond.h"

int dnsSendAnswer(const int sockIn, const char *req, const int ip, const struct sockaddr * const addr, socklen_t addrLen) {
	unsigned char answer[100];
	bzero(answer, 100);
	const int len = dnsCreateAnswer(answer, req, ip, (addr == NULL) ? 2 : 0);
	if (len < 1) return len;

	const int ret = (addr == NULL) ?
		send(sockIn, answer, len, 0)
	:
		sendto(sockIn, answer + 2, len - 2, 0, addr, addrLen);

	return (ret == len) ? 0 : -1;
}

int queryDns(const char * const domain, const size_t domainLen, int * const ttl) {
	unsigned char req[100];
	bzero(req, 100);
	const int reqLen = dnsCreateRequest(req, domain, domainLen);

	struct sockaddr_in dnsAddr;
	const socklen_t addrlen = sizeof(dnsAddr);
	memset(&dnsAddr, 0, addrlen);
	dnsAddr.sin_port = htons(TAPDNS_SERVER_PORT);
	dnsAddr.sin_family = TAPDNS_ADDR_FAMILY;
	inet_pton(TAPDNS_ADDR_FAMILY, TAPDNS_SERVER_ADDR, &dnsAddr.sin_addr.s_addr);

	const int sockDns = socket(TAPDNS_ADDR_FAMILY, SOCK_STREAM, 0);
	if (sockDns != 0) {perror("Creating socket for connecting to DNS server"); return 1;}
	if (connect(sockDns, (struct sockaddr*)&dnsAddr, addrlen) < 0) {perror("Connecting to DNS server"); return 1;}

	send(sockDns, req, reqLen, 0);

	char res[TAPDNS_BUFLEN + 1];
	const int ret = recv(sockDns, res, TAPDNS_BUFLEN, 0);
	close(sockDns);

	return dnsResponse_GetIp(TAPDNS_OFFSET_TCP, res, ret, ttl);
}

// Respond to a client's DNS request
int respond(const int sock, const char *req, const size_t reqLen, const struct sockaddr *addr, socklen_t addrLen) {
	// Get the domain that was requested
	char domain[TAPDNS_MAXLEN_DOMAIN];
	const size_t domainLen = dnsRequest_GetDomain(req, domain, (addr == NULL) ? 2 : 0);

	printf("DEBUG: Domain '%s' requested (length: %zd bytes)\n", domain, reqLen);

	if (dnsRequest_GetOpcode(req) != 0) {
		puts("DEBUG: Non-standard OPCODE");
		dnsSendAnswer(sock, req, 0, addr, addrLen);
		return 0;
	}

	if (isInvalidDomain(domain, domainLen)) {
		puts("DEBUG: Invalid domain");
		dnsSendAnswer(sock, req, 0, addr, addrLen);
		return 0;
	}

	if (strcmp(domain, "localhost") == 0 || (domainLen > 4 && memcmp(domain + domainLen - 4, ".tap", 4) == 0)) {
		dnsSendAnswer(sock, req, 16777343, addr, addrLen); // 127.0.0.1
		return 0;
	}

	sqlite3 *db;
	const int ret = sqlite3_open_v2("Database/Hosts.tap", &db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed to open database: %d\n", ret); sqlite3_close_v2(db); return -1;}

	const int tldLoc = getTldLocation(db, domain);
	if (tldLoc < 2) {
		dnsSendAnswer(sock, req, 0, addr, addrLen);
		puts("DEBUG: TLD not found for domain");
		return 0;
	}

	printf("DEBUG: TLD='%s'\n", domain + tldLoc);

	if (!dbWhitelisted(db, domain, domainLen)) {
		if (dbDomainBlocked(db, domain, domainLen, TAPDNS_TYPE_BLOCK1)) {
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			puts("DEBUG: Domain blocked");
			sqlite3_close_v2(db);
			return 0;
		}

		if (dbParentDomainBlocked(db, domain, tldLoc, TAPDNS_TYPE_BLOCK1)) {
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			puts("DEBUG: Domain blocked");
			sqlite3_close_v2(db);
			return 0;
		}

		if (dbSubdomainBlocked(db, domain, domainLen, tldLoc, TAPDNS_TYPE_BLOCK1)) {
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			puts("DEBUG: Subdomain blocked");
			sqlite3_close_v2(db);
			return 0;
		}

		if (dbTldBlocked(db, domain + tldLoc, TAPDNS_TYPE_BLOCK1)) {
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			puts("DEBUG: TLD blocked");
			sqlite3_close_v2(db);
			return 0;
		}
		
		if (dbKeywordBlocked(db, domain, tldLoc, TAPDNS_TYPE_BLOCK1)) {
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			puts("DEBUG: Keyword blocked");
			sqlite3_close_v2(db);
			return 0;
		}
	}

	int ip = dbGetIp(db, domain, domainLen);

	if (ip == 0) {
		// IP does not exist in the database or there was an error getting it

		// Query the DNS server for a response
		int ttl;
		ip = queryDns(domain, domainLen, &ttl);
		printf("DEBUG: TTL=%d\n", ttl);

		if (ip == 1) {
			// Server-side error (such as non-existent domain)
			dnsSendAnswer(sock, req, 0, addr, addrLen);

			puts("DEBUG: Server-side error");
			sqlite3_close_v2(db);
			return -2;
		} else if (ip == 0) {
			// Failed to parse the server's response
			dnsSendAnswer(sock, req, 0, addr, addrLen);

			puts("ERROR: Failed to parse the server's response");
			sqlite3_close_v2(db);
			return -3;
		}

		// Successfully got response from the server, save it to the database
		dbSetIp(db, domain, domainLen, ip, ttl);
	}

	// Everything OK, respond to the client
	dnsSendAnswer(sock, req, ip, addr, addrLen);

	sqlite3_close_v2(db);
	return 0;
}
