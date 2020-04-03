#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <sqlite3.h>

#include "database.h"

int dbGetIp(sqlite3 * const db, const char * const domain, const size_t lenDomain, bool * const expired) {
	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT ip, expire > STRFTIME('%s', 'NOW') FROM dns WHERE domain=?", 65, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed preparing SQL query: %d\n", ret); return 1;}

	sqlite3_bind_text(query, 1, domain, lenDomain, SQLITE_STATIC);
	ret = sqlite3_step(query);

	const int result = (ret == SQLITE_ROW) ? sqlite3_column_int(query, 0) : 1;
	*expired = sqlite3_column_int(query, 1);

	sqlite3_finalize(query);
	return result;
}

int dbSetIp(sqlite3 * const db, const char * const domain, const size_t lenDomain, const int ip, const int ttl) {
	sqlite3_stmt *query;

	// Try insert
	int ret = sqlite3_prepare_v2(db, "INSERT INTO dns (domain, ip, expire) VALUES (?, ?, STRFTIME('%s', 'NOW') + ?)", 77, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed preparing SQL insert query: %d\n", ret); sqlite3_close_v2(db); return -2;}

	sqlite3_bind_text(query, 1, domain, lenDomain, SQLITE_STATIC);
	sqlite3_bind_int(query, 2, ip);
	sqlite3_bind_int(query, 3, ttl);
	ret = sqlite3_step(query);
	sqlite3_finalize(query);

	if (ret == SQLITE_DONE) return 0;

	// Try update
	ret = sqlite3_prepare_v2(db, "UPDATE dns SET ip = ?, expire = STRFTIME('%s', 'NOW') + ?, ts = STRFTIME('%s', 'NOW') WHERE domain = ?", 102, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed preparing SQL query: %d\n", ret); sqlite3_close_v2(db); return -3;}

	sqlite3_bind_int(query, 1, ip);
	sqlite3_bind_int(query, 2, ttl);
	sqlite3_bind_text(query, 3, domain, lenDomain, SQLITE_STATIC);
	ret = sqlite3_step(query);
	sqlite3_finalize(query);

	if (ret == SQLITE_DONE) return 0;

	printf("ERROR: Failed inserting row: %d\n", ret);
	return -4;
}

int getTldLocation(sqlite3 * const db, char * const domain) {
	const char *testTld = domain;

	while(1) {
		testTld = strchr(testTld, '.');
		if (testTld == NULL) return -5;
		testTld++;

		sqlite3_stmt *query;
		int ret = sqlite3_prepare_v2(db, "SELECT tld FROM tlds WHERE tld=? OR tld=? OR tld=?", -1, &query, NULL);
		if (ret != SQLITE_OK) {printf("ERROR: TLD - Failed preparing SQL query: %d\n", ret); return -2;}

		char testTldE[strlen(testTld) + 2];
		char testTldA[strlen(testTld) + 3];
		sprintf(testTldE, "!%s", testTld);
		sprintf(testTldA, "*.%s", testTld);

		sqlite3_bind_text(query, 1, testTld, -1, SQLITE_STATIC);
		sqlite3_bind_text(query, 2, testTldE, -1, SQLITE_STATIC);
		sqlite3_bind_text(query, 3, testTldA, -1, SQLITE_STATIC);

		ret = sqlite3_step(query);
		if (ret == SQLITE_DONE) {sqlite3_finalize(query); continue;}
		if (ret != SQLITE_ROW) {printf("ERROR: TLD - Failed executing SQL query: %d\n", ret); return -3;}

		const size_t tldSize = sqlite3_column_bytes(query, 0);
		const char * const foundTld = ((char*)sqlite3_column_text(query, 0));
		const char foundType = *foundTld;

		sqlite3_finalize(query);

		if (foundType == '!') {
			// Go forward to remove the leftmost label
			return testTld - domain + tldSize - 1;
		} else if (foundType == '*') {
			// Go backward to include the previous label
			testTld--;
			while ((testTld != domain) && (*testTld != '.')) testTld--;
			return testTld - domain;
		} else {
			// Return as is
			return testTld - domain;
		}
	}

	return -1;
}

bool dbWhitelisted(sqlite3 * const db, const char * const domain, const size_t len) {
	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT 1 FROM domains WHERE domain=? AND type=10", -1, &query, NULL);
	if (ret != SQLITE_OK) {
		printf("ERROR: dbWhitelisted - Failed preparing SQL query: %d\n", ret);
		return false;
	}

	sqlite3_bind_text(query, 1, domain, len, SQLITE_STATIC);
	ret = sqlite3_step(query);
	sqlite3_finalize(query);

	if (ret == SQLITE_ROW) return true;
	if (ret != SQLITE_DONE) printf("ERROR: dbWhitelisted - Failed executing SQL query: %d\n", ret);

	// Either the domain is not whitelisted or there was an error -> treat as not whitelisted
	return false;
}

// Is this domain listed as blocked? (e.g. EVIL.COM)
bool dbDomainBlocked(sqlite3 * const db, const char * const domain, const size_t len, const int blockType) {
	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT 1 FROM domains WHERE domain=? AND type >= ?", -1, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: dbDomainBlocked - Failed preparing SQL query: %d\n", ret); return true;}

	sqlite3_bind_text(query, 1, domain, len, SQLITE_STATIC);
	sqlite3_bind_int(query, 2, blockType);
	ret = sqlite3_step(query);
	sqlite3_finalize(query);

	if (ret == SQLITE_DONE) return false;
	if (ret != SQLITE_ROW) printf("ERROR: dbDomainBlocked - Failed executing SQL query: %d\n", ret);

	// Either the domain is blocked or there was an error -> treat as blocked
	return true;
}

// Is this domain a subdomain of a blocked (sub)domain? (e.g. anything.at-all.EVIL.COM or anything.EVIL.DOMAIN.TLD)
bool dbParentDomainBlocked(sqlite3 * const db, const char * const domain, const int tldLoc, const int blockType) {
	const char * const tldBegin = domain + tldLoc; // Prevent treating the TLD as a domain

	const char *dot = domain - 1; // Start with the full domain including all subdomains; -1 because there is no leading dot
	while(1) {
		dot++;
		if (dot >= tldBegin) break; // No more subdomains to check

		if (dbDomainBlocked(db, dot, strlen(dot), blockType)) return true; // A 'higher up' part is blocked -> block this subdomain as well
		dot = strchr(dot, '.'); // Remove one subdomain
	}

	return false;
}

// Does the domain have a disallowed subdomain? (e.g. EVIL.any-domain.tld, including anything.EVIL.any-domain.tld)
bool dbSubdomainBlocked(sqlite3 * const db, const char * const domain, const size_t domainLen, const size_t tldLoc, const int blockType) {
	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT sub FROM subdomains WHERE type >= ?", -1, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: dbBlockedSubdomain - Failed preparing SQL query: %d\n", ret); return true;}

	sqlite3_bind_int(query, 1, blockType);

	ret = sqlite3_step(query);
	if (ret == SQLITE_DONE) {
		// No blocked subdomains in database
		sqlite3_finalize(query);
		return false;
	} else if (ret != SQLITE_ROW) {
		printf("ERROR: dbBlockedSubdomain - Failed executing SQL query: %d\n", ret);
		sqlite3_finalize(query);
		return true; // treat as blocked
	}

	while (ret == SQLITE_ROW) {
		const char * const sub = (char*)sqlite3_column_text(query, 0);
		const size_t subLen = sqlite3_column_bytes(query, 0);

		if ((subLen + 3) > domainLen) {
			ret = sqlite3_step(query);
			continue;
		}

		char needle[subLen + 3];
		sprintf(needle, ".%s.", sub);
		const char * const found = strstr(domain, needle);

		if ((memcmp(domain, needle + 1, subLen + 1) == 0) || (found != NULL && tldLoc != (found - domain + 2 + subLen))) {
			sqlite3_finalize(query);
			return true;
		}

		ret = sqlite3_step(query);
	}

	sqlite3_finalize(query);
	return false;
}

// Does the domain have a disallowed TLD? (e.g. anything.any-domain.EVIL)
bool dbTldBlocked(sqlite3 * const db, const char * const tld, const int blockType) {
	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT 1 FROM tlds WHERE tld = ? AND type >= ?", -1, &query, NULL);
	if (ret != SQLITE_OK) {
		printf("ERROR: hasBadSuffix - Failed preparing SQL query: %d\n", ret);
		return true;
	}

	sqlite3_bind_text(query, 1, tld, -1, SQLITE_STATIC);
	sqlite3_bind_int(query, 2, blockType);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);

	if (ret == SQLITE_DONE) return false;

	if (ret != SQLITE_ROW) {
		printf("ERROR: hasBadSuffix - Failed executing SQL query: %d\n", ret);
		return true;
	}

	return true;
}

// Does the domain have blocked keywords in it? (e.g. domain-of-EVIL.tld)
bool dbKeywordBlocked(sqlite3 * const db, const char * const domain, const int tldLoc, const int blockType) {
	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT keyword FROM keywords WHERE type >= ?", -1, &query, NULL);
	if (ret != SQLITE_OK) {
		printf("ERROR: dbKeywordBlocked - Failed preparing SQL query: %d\n", ret);
		return true;
	}

	sqlite3_bind_int(query, 1, blockType);

	ret = sqlite3_step(query);
	if (ret == SQLITE_DONE) {
		// No keywords in database
		sqlite3_finalize(query);
		return false;
	} else if (ret != SQLITE_ROW) {
		printf("ERROR: dbKeywordBlocked - Failed executing SQL query: %d\n", ret);
		sqlite3_finalize(query);
		return true;
	}

	while (ret == SQLITE_ROW) {
		const char * const kw = (char*)sqlite3_column_text(query, 0);

		const char * const match = strstr(domain, kw);
		
		if (match != NULL && (match - domain) < tldLoc) {
			sqlite3_finalize(query);
			return true;
		}

		ret = sqlite3_step(query);
	}

	sqlite3_finalize(query);
	return false;
}
