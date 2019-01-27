#ifndef TAPDNS_PROTOCOL_H
#define TAPDNS_PROTOCOL_H

int dnsCreateAnswer(char* answer, const char* req, const int ip, const size_t offset);
int dnsCreateRequest(char rq[100], const char* domain, const size_t domainLen);
size_t dnsRequest_GetDomain(const char* req, char* holder, const size_t offset);
int dnsRequest_GetOpcode(const char* req);
int dnsResponse_GetIp(const int offset, const char* res, const int resLen, int* ttl);

#endif
