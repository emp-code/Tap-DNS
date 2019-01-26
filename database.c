#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <sqlite3.h>

#include "database.h"

int dbGetIp(sqlite3* db, const char* domain, const size_t lenDomain) {
	sqlite3_stmt* query;
	int ret = sqlite3_prepare_v2(db, "SELECT ip FROM dns WHERE domain = ? AND expire > STRFTIME('%s', 'NOW')", 70, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed to prepare SQL query: %d\n", ret); sqlite3_close_v2(db); return 0;}

	sqlite3_bind_text(query, 1, domain, lenDomain, SQLITE_STATIC);
	ret = sqlite3_step(query);

	const int result = (ret == SQLITE_ROW) ? sqlite3_column_int(query, 0) : 0;

	sqlite3_finalize(query);
	return result;
}

int dbSetIp(sqlite3* db, const char* domain, const size_t lenDomain, const int ip, const int ttl) {
	sqlite3_stmt* query;

	// Try insert
	int ret = sqlite3_prepare_v2(db, "INSERT INTO dns (domain, ip, expire) VALUES (?, ?, STRFTIME('%s', 'NOW') + ?)", 77, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed to prepare SQL insert query: %d\n", ret); sqlite3_close_v2(db); return -2;}

	sqlite3_bind_text(query, 1, domain, lenDomain, SQLITE_STATIC);
	sqlite3_bind_int(query, 2, ip);
	sqlite3_bind_int(query, 3, ttl);
	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	
	if (ret == SQLITE_DONE) return 0;

	// Try update
	ret = sqlite3_prepare_v2(db, "UPDATE dns SET ip = ?, expire = STRFTIME('%s', 'NOW') + ?, ts = STRFTIME('%s', 'NOW') WHERE domain = ?", 102, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed to prepare SQL query: %d\n", ret); sqlite3_close_v2(db); return -3;}

	sqlite3_bind_int(query, 1, ip);
	sqlite3_bind_int(query, 2, ttl);
	sqlite3_bind_text(query, 3, domain, lenDomain, SQLITE_STATIC);
	ret = sqlite3_step(query);
	sqlite3_finalize(query);

	if (ret == SQLITE_DONE) return 0;

	printf("ERROR: Failed to insert row: %d\n", ret);
	return -4;
}

bool dbWhitelisted(sqlite3* db, const char* domain, const size_t len) {
	sqlite3_stmt* query;
	int ret = sqlite3_prepare_v2(db, "SELECT 1 FROM hsttype WHERE hst=? AND type=10", 45, &query, NULL);
	if (ret != SQLITE_OK) {
		printf("ERROR: dbWhitelisted - Failed to prepare SQL query: %d\n", ret);
		return false;
	}

	sqlite3_bind_text(query, 1, domain, len, SQLITE_STATIC);
	ret = sqlite3_step(query);
	sqlite3_finalize(query);

	if (ret == SQLITE_ROW) return true;

	if (ret != SQLITE_DONE) printf("ERROR: dbWhitelisted - Failed to execute SQL query: %d\n", ret);
	return false;
}

// Is this domain listed as blocked? (e.g. EVIL.COM)
bool dbDomainBlocked(sqlite3* db, const char* domain, const size_t len, const int blockType) {
	sqlite3_stmt* query;
	int ret = sqlite3_prepare_v2(db, "SELECT 1 FROM hsttype WHERE hst = ? AND type >= ?", 49, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: dbDomainBlocked - Failed to prepare SQL query: %d\n", ret); return true;}

	sqlite3_bind_text(query, 1, domain, len, SQLITE_STATIC);
	sqlite3_bind_int(query, 2, blockType);
	ret = sqlite3_step(query);
	sqlite3_finalize(query);

	if (ret == SQLITE_ROW) return false;	
	if (ret != SQLITE_DONE) printf("ERROR: dbDomainBlocked - Failed to execute SQL query: %d\n", ret);

	// Either the domain is blocked or there was an error -> treat as blocked
	return true;
}

// Does the domain have a disallowed subdomain? (e.g. EVIL.any-domain.tld, including anything.EVIL.any-domain.tld)
bool dbBlockedSubdomain(sqlite3* db, const char* domain, const size_t tldLoc) {
	sqlite3_stmt* query;
	int ret = sqlite3_prepare_v2(db, "SELECT sub FROM subdom", 22, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: dbBlockedSubdomain - Failed to prepare SQL query: %d\n", ret); return true;}

	ret = sqlite3_step(query);
	if (ret == SQLITE_DONE) {
		// No blocked subdomains in database
		sqlite3_finalize(query);
		return false;
	} else if (ret != SQLITE_ROW) {
		printf("ERROR: dbBlockedSubdomain - failed to execute SQL query: %d\n", ret);
		sqlite3_finalize(query);
		return true; // treat as blocked
	}

	const size_t domainLen = strlen(domain);

	while (ret == SQLITE_ROW) {
		const char* sub = (char*)sqlite3_column_text(query, 0);
		const size_t subLen = sqlite3_column_bytes(query, 0);

		if ((subLen + 3) > domainLen) {
			ret = sqlite3_step(query);
			continue;
		}

		char needle[subLen + 3];
		sprintf(needle, ".%s.", sub);
		const char* found = strstr(domain, needle);

		if ((memcmp(domain, needle + 1, subLen + 1) == 0) || (found != NULL && tldLoc != (found - domain + 2 + subLen))) {
			printf("DEBUG: Domain %s has disallowed subdomain '%s'\n", domain, sub);
			sqlite3_finalize(query);
			return true;
		}

		ret = sqlite3_step(query);
	}

	return false;
}
