#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <sqlite3.h>

#include "database.h"

uint32_t dbGetIp(const char* domain) {
	sqlite3* db;
	int ret = sqlite3_open_v2("Database/Hosts.tap", &db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: Failed to open database: %d\n", ret); sqlite3_close_v2(db); return 0;}

	sqlite3_stmt* query;
	ret = sqlite3_prepare_v2(db, "SELECT ip FROM dns WHERE domain = ?", 35, &query, NULL);
	if (ret != SQLITE_OK) {printf("ERROR: DNS: failed to prepare SQL query: %d\n", ret); sqlite3_close_v2(db); return -2;}

	sqlite3_bind_text(query, 1, domain, -1, SQLITE_STATIC);
	ret = sqlite3_step(query);

	uint32_t result = 0;

	if (ret == SQLITE_ROW) {
		result  = (uint32_t)sqlite3_column_int(query, 0);
	}

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return result;
}
