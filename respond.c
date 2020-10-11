// blahdns
//#define TAPDNS_SERVER_ADDR "159.69.198.101"
//#define TAPDNS_SERVER_HOST "dot-de.blahdns.com"

// Cloudflare DNS
//#define TAPDNS_SERVER_ADDR "1.1.1.1"
//#define TAPDNS_SERVER_HOST "cloudflare-dns.com"

// Comcast DNS
//#define TAPDNS_SERVER_ADDR "96.113.151.145"
//#define TAPDNS_SERVER_HOST "dot.xfinity.com"

// Foundation for Applied Privacy
//#define TAPDNS_SERVER_ADDR "93.177.65.183"
//#define TAPDNS_SERVER_HOST "dot1.applied-privacy.net"

// Google DNS
//#define TAPDNS_SERVER_ADDR "8.8.8.8"
//#define TAPDNS_SERVER_HOST "dns.google"

// NixNet Uncensored
//#define TAPDNS_SERVER_ADDR "198.251.90.114"
//#define TAPDNS_SERVER_HOST "uncensored.any.dns.nixnet.xyz"

// Quad9 non-filtering | https://quad9.net
#define TAPDNS_SERVER_ADDR "9.9.9.10"
#define TAPDNS_SERVER_HOST "dns.quad9.net"

// securedns.eu
//#define TAPDNS_SERVER_ADDR "146.185.167.43"
//#define TAPDNS_SERVER_HOST "dot.securedns.eu"

// Snopyta | https://snopyta.org/service/dns/index.html
//#define TAPDNS_SERVER_ADDR "95.216.24.230"
//#define TAPDNS_SERVER_HOST "fi.dot.dns.snopyta.org"

// Switch.ch | https://www.switch.ch/security/info/public-dns/
//#define TAPDNS_SERVER_ADDR "130.59.31.248"
//#define TAPDNS_SERVER_HOST "dns.switch.ch"

// Settings
#define TAPDNS_ADDR_FAMILY AF_INET // IPv4
#define TAPDNS_SERVER_PORT 853 // DNS over TLS
#define TAPDNS_PORT_TOR 9050
#define TAPDNS_SOCKET_TIMEOUT 30
#define TAPDNS_MINTTL 3600 // 1 hour
#define TAPDNS_MAXTTL 86400 // 24 hours

#define TAPDNS_BUFLEN 512
#define UINT32_LOCALHOST 16777343
#define TAPDNS_TYPE_BLOCK_HI 35
#define TAPDNS_TYPE_BLOCK_LO 30

#define ANSI_RED "\x1B[0;31m"
#define ANSI_GRN "\x1B[0;32m"
#define ANSI_YLW "\x1B[0;33m"
#define ANSI_MAG "\x1B[0;35m"
#define ANSI_RST "\x1B[m"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>

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

static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_x509_crt cacert;

static uint16_t get_uint16(const unsigned char * const c) {uint16_t v; memcpy(&v, c, 2); return v;}
static uint32_t get_uint32(const unsigned char * const c) {uint32_t v; memcpy(&v, c, 4); return v;}
static void set_uint16(char * const c, const uint16_t v) {memcpy(c, &v, 2);}
static void set_uint32(char * const c, const uint32_t v) {memcpy(c, &v, 4);}

void freeTls(void) {
	mbedtls_ssl_free(&ssl);
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

	mbedtls_ssl_init(&ssl);
	if (mbedtls_ssl_setup(&ssl, &conf) != 0) {puts("Failed setting up TLS"); return -1;}
	if (mbedtls_ssl_set_hostname(&ssl, TAPDNS_SERVER_HOST) != 0) {puts("Failed setting hostname"); return -1;}	return 0;
}

static int makeTorSocket(void) {
	struct sockaddr_in torAddr;
	torAddr.sin_family = AF_INET;
	torAddr.sin_port = htons(TAPDNS_PORT_TOR);
	torAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	const int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {perror("socket()"); return -1;}

	// Socket Timeout
	struct timeval tv;
	tv.tv_sec = TAPDNS_SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));

	if (connect(sock, (struct sockaddr*)&torAddr, sizeof(struct sockaddr)) == -1) {perror("connect()"); close(sock); return -1;}
	return sock;
}

static int torConnect(void) {
	const int sock = makeTorSocket();
	if (sock < 0) return -1;

	const size_t lenHost = strlen(TAPDNS_SERVER_ADDR);
	const ssize_t lenReq = 10 + lenHost;
	char req[lenReq];

	req[0] = 4; // SOCKS version 4
	req[1] = 1; // Command: connect
	set_uint16(req + 2, htons(TAPDNS_SERVER_PORT)); // Port number
	set_uint32(req + 4, htonl(1)); // IP 0.0.0.1 - let Tor handle DNS
	req[8] = 0; // username (empty)
	memcpy(req + 9, TAPDNS_SERVER_ADDR, lenHost);
	req[9 + lenHost] = '\0';

	if ((send(sock, req, lenReq, 0)) != lenReq) {close(sock); return -1;}

	unsigned char reply[8];
	if (recv(sock, reply, 8, 0) != 8) {close(sock); return -1;}

	if ((uint8_t)reply[0] != 0) {close(sock); return -1;} // version: 0
	if ((uint8_t)reply[1] != 90) {close(sock); return -1;} // status: 90
	if (get_uint16(reply + 2) != 0) {close(sock); return -1;} // port: 0

	return sock;
}

int dnsSendAnswer(const int sockIn, const unsigned char * const req, const uint32_t ip, const struct sockaddr * const addr, socklen_t addrLen) {
	unsigned char answer[100];
	bzero(answer, 100);
	const int len = dnsCreateAnswer(answer, req, ip);
	if (len < 1) return len;

	const int ret = (addr == NULL) ?
		send(sockIn, answer, len, 0)
	:
		sendto(sockIn, answer + 2, len - 2, 0, addr, addrLen);

	return (ret == len) ? 0 : -1;
}

uint32_t queryDns(const char * const domain, const size_t lenDomain, uint32_t * const ttl) {
	size_t lenQuestion = 0;
	unsigned char question[256];

	uint16_t reqId;
	getrandom(&reqId, 2, 0);

	unsigned char req[100];
	int reqLen = dnsCreateRequest(reqId, req, question, &lenQuestion, (unsigned char*)domain, lenDomain);

	int sock = torConnect();
	if (sock < 0) {puts("ERROR: Failed creating socket"); return 0;}
	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	int ret;
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			puts("ERROR: Failed TLS handshake");
			mbedtls_ssl_close_notify(&ssl);
			mbedtls_ssl_session_reset(&ssl);
			close(sock);
			return 0;
		}
	}

	const uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
	if (flags != 0) {
		puts("ERROR: Failed verifying cert");
		mbedtls_ssl_close_notify(&ssl);
		mbedtls_ssl_session_reset(&ssl);
		close(sock);
		return 0;
	}

	do {ret = mbedtls_ssl_write(&ssl, req, reqLen);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	unsigned char res[TAPDNS_BUFLEN];
	do {ret = mbedtls_ssl_read(&ssl, res, TAPDNS_BUFLEN);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);

	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_session_reset(&ssl);
	close(sock);

	return (ret > 0) ? dnsResponse_GetIp(reqId, res + 2, ret - 2, question, lenQuestion, ttl) : 0;
}

// Respond to a client's DNS request
void respond(const int sock, const unsigned char * const req, const size_t reqLen, const struct sockaddr * const addr, socklen_t addrLen) {
	if ((req[3] & 120) != 0) {
		printf("Invalid OPCODE: %u\n", req[3] & 120);
		dnsSendAnswer(sock, req, 0, addr, addrLen);
		return;
	}

	// Get the domain that was requested
	char domain[TAPDNS_MAXLEN_DOMAIN];
	const size_t domainLen = dnsRequest_GetDomain(req, domain);

	if (!isDomainValid(domain, domainLen)) {
		printf("I %.*s\n", (int)domainLen, domain);
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
		printf("I %.*s\n", (int)domainLen, domain);
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

	bool expired = false;
	uint32_t ip = dbGetIp(db, domain, domainLen, &expired);

	if (ip == 0 || expired) {
		// IP does not exist in the database or there was an error getting it
		uint32_t ttl;
		const uint32_t newIp = queryDns(domain, domainLen, &ttl);
		if (ttl < TAPDNS_MINTTL) ttl = TAPDNS_MINTTL;
		else if (ttl > TAPDNS_MAXTTL) ttl = TAPDNS_MAXTTL;

		if (newIp != 0) {
			// Successfully got response from the server, save it to the database
			ip = newIp;
			dbSetIp(db, domain, domainLen, ip, ttl);
			printf(ANSI_RED"+ %.*s"ANSI_RST" (%um)\n", (int)domainLen, domain, ttl / 60);
		} else if (ip == 0) {
			// Failed to get IP, not in database
			dnsSendAnswer(sock, req, 0, addr, addrLen);
			printf(ANSI_YLW"E %.*s"ANSI_RST"\n", (int)domainLen, domain);
			sqlite3_close_v2(db);
			return;
		} else {
			// Failed to get IP, send expired entry from database
			// TODO: Upper limit on age
			printf(ANSI_MAG"X %.*s"ANSI_RST"\n", (int)domainLen, domain);
		}
	} else printf(ANSI_GRN"  %.*s"ANSI_RST"\n", (int)domainLen, domain);

	dnsSendAnswer(sock, req, ip, addr, addrLen);
	sqlite3_close_v2(db);
}
