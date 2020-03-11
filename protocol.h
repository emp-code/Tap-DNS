#ifndef TAPDNS_PROTOCOL_H
#define TAPDNS_PROTOCOL_H

int dnsCreateAnswer(unsigned char * const answer, const char * const req, const int ip, const size_t offset);
int dnsCreateRequest(unsigned char * const rq, const char * const domain, const size_t domainLen);
size_t dnsRequest_GetDomain(const char* req, char* holder, const size_t offset);
int dnsRequest_GetOpcode(const char* req);
int dnsResponse_GetIp(const int offset, const char* res, const int resLen, int* ttl);

#endif
