#ifndef TAPDNS_RESPOND_H
#define TAPDNS_RESPOND_H

void freeTls(void);
int setupTls(void);
void respond(const int sock, const unsigned char * const req, const size_t reqLen, const struct sockaddr * const addr, socklen_t addrLen);

#endif
