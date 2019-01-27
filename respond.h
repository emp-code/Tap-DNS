#ifndef TAPDNS_RESPOND_H
#define TAPDNS_RESPOND_H

int respond(const int sock, const char* req, const size_t reqLen, const struct sockaddr* addr, socklen_t addrLen);

#endif
