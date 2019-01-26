#ifndef TAPDNS_DATABASE_H
#define TAPDNS_DATABASE_H

#include <stdbool.h>

int dbGetIp(sqlite3* db, const char* domain, const size_t lenDomain);
int dbSetIp(sqlite3* db, const char* domain, const size_t lenDomain, const int ip, const int ttl);

int getTldLocation(sqlite3* db, char* domain);

#endif
