CC=gcc
CFLAGS=-Ofast -march=native -pipe -Wall -Wextra -Werror -lsqlite3 -D_FORTIFY_SOURCE=2 -fsanitize=undefined -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wno-error=unused-result -Wno-error=unused-function -Wno-error=unused-parameter -Wno-error=unused-variable -Wno-comment

objects = main.o Includes/bit.o database.o domain.o protocol.o respond.o

Tap-DNS: $(objects)
	$(CC) $(CFLAGS) -o Tap-DNS $(objects) -lmbedtls -lmbedcrypto -lmbedx509 -lsqlite3

main: main.c respond.h

Includes/bit.o: Includes/bit.c
database.o: database.c
domain.o: domain.c
protocol.o: protocol.c Includes/bit.h
respond.o: respond.c Includes/bit.h database.h domain.h protocol.h

.PHONY: clean
clean:
	-rm $(objects) Tap-DNS
