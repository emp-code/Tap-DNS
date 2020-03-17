// Details of DNS server to use
#define TAPDNS_ADDR_FAMILY AF_INET // IPv4
#define TAPDNS_SERVER_ADDR "8.8.8.8" // Google DNS
#define TAPDNS_SERVER_PORT 853
#define TAPDNS_MINTTL 86400
#define TAPDNS_BUFLEN 512

#define UINT32_LOCALHOST 16777343
#define TAPDNS_OFFSET_TCP 2
#define TAPDNS_OFFSET_UDP 0
#define TAPDNS_TYPE_BLOCK_HI 35
#define TAPDNS_TYPE_BLOCK_LO 30

#define ANSI_RED "\x1B[0;31m"
#define ANSI_GRN "\x1B[0;32m"
#define ANSI_YLW "\x1B[0;33m"
#define ANSI_RST "\x1B[m"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "database.h"
#include "domain.h"
#include "protocol.h"

#include "respond.h"

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>

mbedtls_ssl_config conf;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_x509_crt cacert;

void freeTls(void) {
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_x509_crt_free(&cacert);
}

int setupTls(void) {
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) return -1;
	if (mbedtls_x509_crt_parse_path(&cacert, "/etc/ssl/certs/")) return -1;
	if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) return -1;

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_dhm_min_bitlen(&conf, 2048); // Minimum length for DH parameters
	mbedtls_ssl_conf_fallback(&conf, MBEDTLS_SSL_IS_NOT_FALLBACK);
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // Require TLS v1.2+
	mbedtls_ssl_conf_renegotiation(&conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_session_tickets(&conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
	return 0;
}

int dnsSendAnswer(const int sockIn, const unsigned char * const req, const int ip, const struct sockaddr * const addr, socklen_t addrLen) {
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

int dnsSocket(void) {
	struct sockaddr_in addr;
	const socklen_t addrlen = sizeof(addr);
	memset(&addr, 0, addrlen);
	addr.sin_port = htons(TAPDNS_SERVER_PORT);
	addr.sin_family = TAPDNS_ADDR_FAMILY;
	inet_pton(TAPDNS_ADDR_FAMILY, TAPDNS_SERVER_ADDR, &addr.sin_addr.s_addr);

	const int sock = socket(TAPDNS_ADDR_FAMILY, SOCK_STREAM, 0);
	if (sock < 0) {perror("ERROR: Failed creating socket for connecting to DNS server"); return 1;}
	if (connect(sock, (struct sockaddr*)&addr, addrlen) < 0) {perror("ERROR: Failed connecting to DNS server"); return 1;}

	return sock;
}

uint32_t queryDns(const char * const domain, const size_t domainLen, uint32_t * const ttl) {
	unsigned char req[100];
	bzero(req, 100);
	const int reqLen = dnsCreateRequest(req, domain);

	int sock = dnsSocket();
	if (sock < 0) {puts("ERROR: Failed creating socket"); return 1;}

	mbedtls_ssl_context ssl;
	mbedtls_ssl_init(&ssl);
	if (mbedtls_ssl_setup(&ssl, &conf) != 0) {puts("ERROR: Failed setting up TLS"); return 1;}
	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	int ret;
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {puts("ERROR: Failed TLS handshake"); return -1;}
	}

	const uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
	if (flags != 0) {puts("ERROR: Failed verifying cert"); return -1;} // Invalid cert

	do {ret = mbedtls_ssl_write(&ssl, req, reqLen);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	unsigned char res[TAPDNS_BUFLEN];
	do {ret = mbedtls_ssl_read(&ssl, res, TAPDNS_BUFLEN);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);

	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_free(&ssl);
	close(sock);

	return (ret > 0) ? dnsResponse_GetIp(res, ret, ttl) : 1;
}

// Respond to a client's DNS request
void respond(const int sock, const unsigned char * const req, const size_t reqLen, const struct sockaddr * const addr, socklen_t addrLen) {
	// Get the domain that was requested
	char domain[TAPDNS_MAXLEN_DOMAIN];
	const size_t domainLen = dnsRequest_GetDomain(req, domain, (addr == NULL) ? 2 : 0);

	if (dnsRequest_GetOpcode(req) != 0) {
		puts("DEBUG: Non-standard OPCODE");
		dnsSendAnswer(sock, req, 0, addr, addrLen);
		return;
	}

	if (isInvalidDomain(domain, domainLen)) {
		printf("DEBUG: Invalid domain: %.*s\n", (int)domainLen, domain);
		dnsSendAnswer(sock, req, 0, addr, addrLen);
		return;
	}

	if (strcmp(domain, "localhost") == 0 || (domainLen > 4 && memcmp(domain + domainLen - 4, ".tap", 4) == 0)) {
		dnsSendAnswer(sock, req, UINT32_LOCALHOST, addr, addrLen);
		return;
	}

	sqlite3 *db;
	const int ret = sqlite3_open_v2("Database/Hosts.tap", &db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed opening database: %d\n", ret); sqlite3_close_v2(db); return;}

	const int tldLoc = getTldLocation(db, domain);
	if (tldLoc < 2) {
		dnsSendAnswer(sock, req, 0, addr, addrLen);
		printf("DEBUG: TLD not found for domain: %.*s\n", (int)domainLen, domain);
		return;
	}

	if (!dbWhitelisted(db, domain, domainLen)) {
		if (dbDomainBlocked(db, domain, domainLen, TAPDNS_TYPE_BLOCK_LO)) {
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			printf("D %.*s\n", (int)domainLen, domain);
			sqlite3_close_v2(db);
			return;
		}

		if (dbParentDomainBlocked(db, domain, tldLoc, TAPDNS_TYPE_BLOCK_LO)) {
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			printf("P %.*s\n", (int)domainLen, domain);
			sqlite3_close_v2(db);
			return;
		}

		if (dbSubdomainBlocked(db, domain, domainLen, tldLoc, TAPDNS_TYPE_BLOCK_LO)) {
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			printf("S %.*s\n", (int)domainLen, domain);
			sqlite3_close_v2(db);
			return;
		}

		if (dbTldBlocked(db, domain + tldLoc, TAPDNS_TYPE_BLOCK_LO)) {
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			printf("T %.*s\n", (int)domainLen, domain);
			sqlite3_close_v2(db);
			return;
		}
		
		if (dbKeywordBlocked(db, domain, tldLoc, TAPDNS_TYPE_BLOCK_LO)) {
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			printf("K %.*s\n", (int)domainLen, domain);
			sqlite3_close_v2(db);
			return;
		}
	}

	uint32_t ip = dbGetIp(db, domain, domainLen);

	if (ip == 1) {
		// IP does not exist in the database or there was an error getting it
		uint32_t ttl;
		ip = queryDns(domain, domainLen, &ttl);

		if (ip == 1) {
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			printf(ANSI_YLW"E %.*s\n"ANSI_RST, (int)domainLen, domain);
			sqlite3_close_v2(db);
			return;
		}

		// Successfully got response from the server, save it to the database
		dbSetIp(db, domain, domainLen, ip, (ttl < TAPDNS_MINTTL) ? TAPDNS_MINTTL : ttl);
		printf(ANSI_RED"+ %.*s\n"ANSI_RST, (int)domainLen, domain);
	} else printf(ANSI_GRN"  %.*s\n"ANSI_RST, (int)domainLen, domain);

	// Everything OK, respond to the client
	dnsSendAnswer(sock, req, ip, addr, addrLen);
	sqlite3_close_v2(db);
}
