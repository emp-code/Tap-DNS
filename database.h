#ifndef TAPDNS_DATABASE_H
#define TAPDNS_DATABASE_H

#include <stdbool.h>

int dbGetIp(sqlite3 * const db, const char * const domain, const size_t lenDomain, bool * const expired);
int dbSetIp(sqlite3 * const db, const char * const domain, const size_t lenDomain, const int ip, const int ttl);

bool dbWhitelisted(sqlite3 * const db, const char * const domain, const size_t len);
bool dbDomainBlocked(sqlite3 * const db, const char * const domain, const size_t len, const int blockType);
bool dbParentDomainBlocked(sqlite3 * const db, const char * const domain, const int tldLoc, const int blockType);
bool dbSubdomainBlocked(sqlite3 * const db, const char * const domain, const size_t domainLen, const size_t tldLoc, const int blockType);
bool dbTldBlocked(sqlite3 * const db, const char * const tld, const int blockType);
bool dbKeywordBlocked(sqlite3 * const db, const char * const domain, const int tldLoc, const int blockType);

int getTldLocation(sqlite3 * const db, char * const domain);

#endif
