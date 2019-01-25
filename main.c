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
	if (sock < 0) {
		puts("ERROR: Opening socket failed");
		return 1;
	}

	// Init the socket
	if (initSocket(sock) != 0) {
		puts("ERROR: Binding socket failed");
		return 1;
	}

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

			respond(newSock);

			close(newSock);
			return 0;
		}
		
		// Parent thread: Continue loop to accept new clients
		close(newSock);
	}

	close(sock);
	return 0;
}

int main() {	
	puts(">>> Tap:DNS - The Attenuating Proxy: Deadbolt Name Service");

	acceptConnections_tcp();
	return 0;
}
