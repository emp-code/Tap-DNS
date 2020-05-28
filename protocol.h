#ifndef TAPDNS_PROTOCOL_H
#define TAPDNS_PROTOCOL_H

int dnsCreateAnswer(unsigned char * const answer, const unsigned char * const req, const uint32_t ip, const size_t offset);
int dnsCreateRequest(unsigned char * const rq, const char * const domain, const size_t lenDomain);
size_t dnsRequest_GetDomain(const unsigned char * const req, char * const holder, const size_t offset);
int dnsRequest_GetOpcode(const unsigned char * const req);
uint32_t dnsResponse_GetIp(const unsigned char * const res, const int resLen, uint32_t * const ttl);

#endif
