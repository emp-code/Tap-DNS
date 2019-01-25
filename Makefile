CC=gcc
CFLAGS=-O3 -march=native -pipe -Wall -Werror=array-bounds -Werror=format-overflow=0 -Werror=format -Werror=implicit-function-declaration -Werror=implicit-int -Werror=incompatible-pointer-types -Wno-comment -Wno-switch -Wno-unused-variable
objects = main.o Includes/bit.o domain.o protocol.o respond.o

Tap-DNS: $(objects)
	$(CC) $(CFLAGS) -o Tap-DNS $(objects)

main: main.c respond.h

Includes/bit.o: Includes/bit.c
domain.o: domain.c
respond.o: respond.c domain.h protocol.h
protocol.o: protocol.c

.PHONY: clean
clean:
	-rm $(objects)
