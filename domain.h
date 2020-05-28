#ifndef TAPDNS_DOMAIN_H
#define TAPDNS_DOMAIN_H

#define TAPDNS_MAXLEN_DOMAIN 256

#include <stdbool.h>

bool isDomainValid(const char * const domain, const size_t domainLen);

#endif
