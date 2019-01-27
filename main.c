// main.h: Init the program and accept clients

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

int acceptConnections_tcp() {
	// Create a TCP socket to accept connections on
	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {puts("ERROR: Opening socket failed"); return 1;}

	// Init the socket
	if (initSocket(sock) != 0) {puts("ERROR: Binding socket failed"); return 1;}

	struct sockaddr_in cliAddr;
	socklen_t cliLen = sizeof(cliAddr);

	// Accept connections on the socket
	while(1) {
		const int newSock = accept(sock, (struct sockaddr*)&cliAddr, &cliLen);
		if (newSock < 0) {puts("ERROR: Failed to create socket for accepting connection"); return -1;}

		const int pid = fork();
		if (pid < 0) {puts("ERROR: Failed to fork"); return -2;}

		if (pid == 0) {
			// Child thread: Respond to the client
			close(sock);

			// Read the request from the client
			char req[TAPDNS_BUFLEN + 1];
			const int reqLen = recv(newSock, req, TAPDNS_BUFLEN, 0);

			respond(newSock, req, reqLen, NULL, 0);

			close(newSock);
			return 0;
		}
		
		// Parent thread: Continue loop to accept new clients
		close(newSock);
	}

	close(sock);
	return 0;
}

int acceptConnections_udp() {
	// Create a UDP socket to accept connections on
	const int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {puts("ERROR: Opening socket failed"); return 1;}

	// Init the socket
	if (initSocket(sock) != 0) {puts("ERROR: Binding socket failed"); return 1;}

	// Accept connections on the socket
	while(1) {
		struct sockaddr_in addrIn; // Client address
		socklen_t addrlen = sizeof(addrIn);

		char req[TAPDNS_BUFLEN]; // Request holder
		const int reqLen = recvfrom(sock, req, TAPDNS_BUFLEN, 0, (struct sockaddr*)&addrIn, &addrlen);
		if (reqLen < 0) {perror("Failed to receive a connection"); continue;}

		const int pid = fork();
		if (pid < 0) {puts("ERROR: Failed to fork connection"); return 1;}
		else if (pid != 0) continue; // 0 = Child

		respond(sock, req, reqLen, (struct sockaddr*)&addrIn, addrlen);
		return 0;
	}

	close(sock);
	return 0;
}

int main() {	
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		perror(0);
		return 1;
	}

	puts(">>> Tap:DNS - The Attenuating Proxy: Deadbolt Name Service");

	// Fork once here to accept both UDP and TCP connections
	const int pid = fork();
	if (pid < 0) {puts("ERROR: Failed to fork connection"); return 1;}

	if (pid == 0)
		acceptConnections_udp(); // Child thread: Accept UDP connections
	else
		acceptConnections_tcp(); // Parent thread: Accept TCP connections

	return 0;
}
