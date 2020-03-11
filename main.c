#define TAPDNS_PORT_INTERNAL 60053 // Port to accept connections on
#define TAPDNS_BUFLEN 1024

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <unistd.h>
#include <pwd.h>

#include "respond.h"

int initSocket(const int sock) {
	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	servAddr.sin_port = htons(TAPDNS_PORT_INTERNAL);

	const int ret = bind(sock, (struct sockaddr*)&servAddr, sizeof(servAddr));
	if (ret < 0) return ret;

	listen(sock, 25); // socket, backlog (# of connections to keep in queue)
	return 0;
}

void acceptConnections_tcp() {
	// Create a TCP socket to accept connections on
	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {puts("ERROR: Failed opening TCP socket"); return;}

	// Init the socket
	if (initSocket(sock) != 0) {puts("ERROR: Failed binding TCP socket"); return;}

	// Accept connections on the socket
	while(1) {
		const int newSock = accept(sock, NULL, NULL);
		if (newSock < 0) {puts("ERROR: Failed accepting connection"); return;}

		const int pid = fork();
		if (pid < 0) {puts("ERROR: Failed forking"); return;}

		if (pid == 0) {
			// Child thread: Respond to the client
			close(sock);

			// Read the request from the client
			unsigned char req[TAPDNS_BUFLEN + 1];
			const int reqLen = recv(newSock, req, TAPDNS_BUFLEN, 0);
			if (reqLen < 0) {perror("Failed receiving a connection"); close(newSock); return;}

			respond(newSock, req, reqLen, NULL, 0);

			close(newSock);
			return;
		}

		// Parent thread: Continue loop to accept new clients
		close(newSock);
	}

	close(sock);
}

void acceptConnections_udp() {
	// Create a UDP socket to accept connections on
	const int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {puts("ERROR: Failed opening UDP socket"); return;}

	// Init the socket
	if (initSocket(sock) != 0) {puts("ERROR: Failed binding UDP socket"); return;}

	// Accept connections on the socket
	while(1) {
		struct sockaddr_in addrIn; // Client address
		socklen_t addrlen = sizeof(addrIn);

		unsigned char req[TAPDNS_BUFLEN]; // Request holder
		const int reqLen = recvfrom(sock, req, TAPDNS_BUFLEN, 0, (struct sockaddr*)&addrIn, &addrlen);
		if (reqLen < 0) {perror("ERROR: Failed receiving a connection"); continue;}

		const int pid = fork();
		if (pid < 0) {puts("ERROR: Failed forking connection"); return;}
		else if (pid != 0) continue; // 0 = Child

		respond(sock, req, reqLen, (struct sockaddr*)&addrIn, addrlen);
		return;
	}

	close(sock);
	return;
}

int main() {
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		perror(0);
		return 1;
	}

	puts(">>> Tap:DNS - The Attenuating Proxy: Deadbolt Name Service");

	// Fork once here to accept both UDP and TCP connections
	const int pid = fork();
	if (pid < 0) {puts("ERROR: Failed forking connection"); return 1;}

	if (pid == 0)
		acceptConnections_udp(); // Child thread: Accept UDP connections
	else
		acceptConnections_tcp(); // Parent thread: Accept TCP connections

	return 0;
}
