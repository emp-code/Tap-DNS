CC=gcc
CFLAGS=-O3 -march=native -pipe -Wall -Werror=array-bounds -Werror=format-overflow=0 -Werror=format -Werror=implicit-function-declaration -Werror=implicit-int -Werror=incompatible-pointer-types -Wno-comment -Wno-switch -Wno-unused-variable -lsqlite3
objects = main.o Includes/bit.o domain.o protocol.o respond.o

Tap-DNS: $(objects)
	$(CC) $(CFLAGS) -o Tap-DNS $(objects)

main: main.c respond.h

Includes/bit.o: Includes/bit.c
database.o: database.c
domain.o: domain.c
protocol.o: protocol.c Includes/bit.h
respond.o: respond.c Includes/bit.h database.h domain.h protocol.h

.PHONY: clean
clean:
	-rm $(objects)
