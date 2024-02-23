.DEFAULT_GOAL: prod
CC=gcc
CC_OPTS=-lm -Wall -Wextra -o

dev: src/main.c
	$(CC) src/main.c -Og $(CC_OPTS) ./hash

prod: src/main.c
	$(CC) src/main.c -O3 $(CC_OPTS) ./hash

test: crc

crc: ./hash
	./hash -f ./hash -c
