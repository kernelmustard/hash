CC=gcc
CC_OPTS=-Wall -o

main: src/main.c
	$(CC) src/main.c $(CC_OPTS) ./hash