#ifndef TAPDNS_PROTOCOL_H
#define TAPDNS_PROTOCOL_H

#include <stddef.h>

int dnsCreateAnswer(char* buffer, const char* req, const int ip);
int dnsCreateRequest(char rq[100], const char* domain, const size_t domainLen);
size_t dnsRequest_GetDomain(const char* req, char* holder);
int dnsResponse_GetIp(const int offset, const char* res, const int resLen);

#endif
