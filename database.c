#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <sqlite3.h>

#include "database.h"

uint32_t dbGetIp(const char* domain, const size_t lenDomain) {
	sqlite3* db;
	int ret = sqlite3_open_v2("Database/Hosts.tap", &db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed to open database: %d\n", ret); sqlite3_close_v2(db); return 0;}

	sqlite3_stmt* query;
	ret = sqlite3_prepare_v2(db, "SELECT ip FROM dns WHERE domain = ?", 35, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed to prepare SQL query: %d\n", ret); sqlite3_close_v2(db); return 0;}

	sqlite3_bind_text(query, 1, domain, lenDomain, SQLITE_STATIC);
	ret = sqlite3_step(query);

	uint32_t result = 0;

	if (ret == SQLITE_ROW) {
		result  = (uint32_t)sqlite3_column_int(query, 0);
	}

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return result;
}

int dbSetIp(const char* domain, const size_t lenDomain, const uint32_t ip) {
	sqlite3* db;
	sqlite3_stmt* query;
	int ret = sqlite3_open_v2("Database/Hosts.tap", &db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed to open database: %d\n", ret); sqlite3_close_v2(db); return -1;}

	// Try insert
	ret = sqlite3_prepare_v2(db, "INSERT INTO dns (domain,ip) VALUES (?,?)", 40, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed to prepare SQL insert query: %d\n", ret); sqlite3_close_v2(db); return -2;}

	sqlite3_bind_text(query, 1, domain, lenDomain, SQLITE_STATIC);
	sqlite3_bind_int(query, 2, (int)ip);
	ret = sqlite3_step(query);

	if (ret == SQLITE_DONE) {
		sqlite3_finalize(query);
		sqlite3_close_v2(db);
		return 0;
	}

	// Try update
	ret = sqlite3_prepare_v2(db, "UPDATE dns SET ip = ?, ts = STRFTIME('%s', 'NOW') WHERE domain = ?", 66, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed to prepare SQL query: %d\n", ret); sqlite3_close_v2(db); return -3;}

	sqlite3_bind_int(query, 1, (int)ip);
	sqlite3_bind_text(query, 2, domain, lenDomain, SQLITE_STATIC);
	ret = sqlite3_step(query);

	if (ret == SQLITE_DONE) {
		sqlite3_finalize(query);
		sqlite3_close_v2(db);
		return 0;
	}

	printf("ERROR: Failed to insert row: %d\n", ret);
	return -4;
}
