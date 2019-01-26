#ifndef TAPDNS_DATABASE_H
#define TAPDNS_DATABASE_H

#include <stdbool.h>

int dbGetIp(sqlite3* db, const char* domain, const size_t lenDomain);
int dbSetIp(sqlite3* db, const char* domain, const size_t lenDomain, const int ip, const int ttl);

bool dbWhitelisted(sqlite3* db, const char* domain, const size_t len);
bool dbDomainBlocked(sqlite3* db, const char* domain, const size_t len, const int blockType);
bool dbParentDomainBlocked(sqlite3* db, const char* domain, const int tldLoc, const int blockType);
bool dbSubdomainBlocked(sqlite3* db, const char* domain, const size_t domainLen, const size_t tldLoc, const int blockType);
bool dbTldBlocked(sqlite3* db, const char* tld, const int blockType);
bool dbKeywordBlocked(sqlite3* db, const char* domain, const int tldLoc, const int blockType);

int getTldLocation(sqlite3* db, char* domain);

#endif
