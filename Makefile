.DEFAULT_GOAL: prod
CC=gcc
CC_OPTS=-Wall -Wextra -Wpedantic -Wformat=2 -Wno-unused-parameter -Wshadow -Wwrite-strings -Wstrict-prototypes -Wold-style-definition -Wredundant-decls -Wnested-externs -Wmissing-include-dirs

dev: src/main.c
	$(CC) src/main.c -Og $(CC_OPTS) -o hash

prod: src/main.c
	$(CC) src/main.c -O3 $(CC_OPTS) -o hash
	strip -s ./hash

clean: 
	rm -f ./hash
	rm -f ./test

test: com_test run_test

com_test: src/test.c
	$(CC) src/test.c -Og $(CC_OPTS) -lcunit -o test
run_test: 
	./test