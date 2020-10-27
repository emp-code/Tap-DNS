CC=gcc
CFLAGS=-Ofast -march=native -pipe -Wall -Wextra -Werror -lsqlite3 -D_FORTIFY_SOURCE=2 -fsanitize=undefined -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wno-error=unused-result -Wno-error=unused-function -Wno-error=unused-parameter -Wno-error=unused-variable -Wno-comment

objects = main.o database.o protocol.o respond.o ValidDomain.o

Tap-DNS: $(objects)
	$(CC) $(CFLAGS) -o Tap-DNS $(objects) -lmbedtls -lmbedcrypto -lmbedx509 -lsqlite3

main: main.c respond.h

database.o: database.c
protocol.o: protocol.c
respond.o: respond.c database.h protocol.h ValidDomain.h
ValidDomain.o: ValidDomain.c

.PHONY: clean
clean:
	-rm $(objects) Tap-DNS
