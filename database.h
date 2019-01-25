#ifndef TAPDNS_DATABASE_H
#define TAPDNS_DATABASE_H

uint32_t dbGetIp(const char* domain, const size_t lenDomain);
int dbSetIp(const char* domain, const size_t lenDomain, const uint32_t ip);

#endif
