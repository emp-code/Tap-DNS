#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "domain.h"

bool isDomainValid(const char * const domain, const size_t domainLen) {
	if (domain == NULL) return 1;

	if (domainLen < 4 || domainLen > TAPDNS_MAXLEN_DOMAIN) return 2;

	if (strspn(domain, "abcdefghijklmnopqrstuvwxyz0123456789.-") != domainLen) return 3; // Allow only letters/numbers/hyphen/dot

	if (!isalnum(domain[0])) return 4; // First character must be alphanumeric

	if (strstr(domain, "..") != NULL) return 5;
	if (strstr(domain, ".-") != NULL) return 6;
	// Note: -. is valid

//	if (getTldLocation(domain, NULL) < 0) return 8;

	return true;
}
