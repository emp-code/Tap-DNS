#ifndef TAPDNS_DOMAIN_H
#define TAPDNS_DOMAIN_H

#define TAPDNS_MAXLEN_DOMAIN 256

#include <stdbool.h>

bool isValidDomain(const char * const domain, const int lenDomain);

#endif
