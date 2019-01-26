#ifndef TAPDNS_DATABASE_H
#define TAPDNS_DATABASE_H

int dbGetIp(const char* domain, const size_t lenDomain);
int dbSetIp(const char* domain, const size_t lenDomain, const int ip, const int ttl);

#endif
