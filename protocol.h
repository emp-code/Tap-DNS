#ifndef TAPDNS_PROTOCOL_H
#define TAPDNS_PROTOCOL_H

int dnsCreateAnswer(unsigned char * const answer, const unsigned char * const req, const int ip, const size_t offset);
int dnsCreateRequest(unsigned char * const rq, const char * const domain);
size_t dnsRequest_GetDomain(const unsigned char * const req, char * const holder, const size_t offset);
int dnsRequest_GetOpcode(const unsigned char * const req);
int dnsResponse_GetIp(const unsigned char * const res, const int resLen, int * const ttl);

#endif
