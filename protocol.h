#ifndef TAPDNS_PROTOCOL_H
#define TAPDNS_PROTOCOL_H

int dnsCreateAnswer(unsigned char * const answer, const unsigned char * const req, const uint32_t ip);
int dnsCreateRequest(const uint16_t id, unsigned char * const rq, unsigned char * const question, size_t * const lenQuestion, const unsigned char * const domain, const size_t lenDomain);
size_t dnsRequest_GetDomain(const unsigned char * const req, char * const holder);
int dnsRequest_GetOpcode(const unsigned char * const req);
uint32_t dnsResponse_GetIp(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const question, const size_t lenQuestion);

#endif
