#define TAPDNS_MAXLEN_DOMAIN 200

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

// Return zero if valid
int isInvalidDomain(const char* domain, const size_t domainLen) {
printf("%zd\n", domainLen);
	if (domain == NULL) return 1;

	if (domainLen < 4 || domainLen > TAPDNS_MAXLEN_DOMAIN) return 2;

	if (strspn(domain, "abcdefghijklmnopqrstuvwxyz0123456789.-_") != domainLen) return 3; // Only letters, numbers, ./-/_ allowed

	if (!isalnum(domain[0])) return 4; // First character must be alphanumeric

	if (strstr(domain, "..") != NULL) return 5;
	if (strstr(domain, ".-") != NULL) return 6;
	// Note: -. is valid

	if ((domainLen > 10) && (strcmp(domain + domainLen - 6, ".onion") == 0)) {
		// Correct format for .onion domains
		if((domainLen == 62 && (memcmp(domain + 56, ".onion", 6) == 0) && (strspn(domain, "abcdefghijklmnopqrstuvwxyz0123456789") == 56))
		|| (domainLen == 22 && (memcmp(domain + 16, ".onion", 6) == 0) && (strspn(domain, "abcdefghijklmnopqrstuvwxyz0123456789") == 16))
		) return 0;

		return 7;
	}

//	if (getTldLocation(domain, NULL) < 0) return 8;

	return 0;
}
