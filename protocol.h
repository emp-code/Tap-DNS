#ifndef TAPDNS_PROTOCOL_H
#define TAPDNS_PROTOCOL_H

#define TAPDNS_DOMAIN_MAXLEN 99
#define TAPDNS_OFFSET_TCP 2
#define TAPDNS_OFFSET_UDP 0

#include <stddef.h>

int dnsCreateAnswer(char* buffer, const char* req, const int ip);
size_t dnsRequest_GetDomain(const char* req, char* holder);
int dnsResponse_GetIp(const int offset, const char* res, const int resLen);

#endif
