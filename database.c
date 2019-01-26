#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
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
