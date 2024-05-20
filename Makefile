.DEFAULT_GOAL: prod
CC=gcc
CC_OPTS=-Wall -Wextra -Wpedantic -Wformat=2 -Wno-unused-parameter -Wshadow -Wwrite-strings -Wstrict-prototypes -Wold-style-definition -Wredundant-decls -Wnested-externs -Wmissing-include-dirs

dev: src/main.c
	$(CC) src/main.c -Og $(CC_OPTS) ./hash

prod: src/main.c
	$(CC) src/main.c -O3 $(CC_OPTS) ./hash
	strip -s ./hash

test: help crc32 md5 sha1

help: ./hash
	echo "\n\n"
	./hash --help

crc32: ./hash
	echo "\n\n"
	./hash --file ./hash --crc32
	crc32 ./hash
	echo ""
	./hash --string "./hash" --crc32 
	bash -c 'crc32 <(echo -n "./hash")'

md5: ./hash
	echo "\n\n"
	./hash --file ./hash --md5 
	md5sum ./hash
	echo ""
	./hash --string "./hash" --md5 
	bash -c 'md5sum <(echo -n "./hash")'

sha1: ./hash
	echo "\n\n"
	./hash --file ./hash --sha1 
	sha1sum ./hash
	echo ""
	./hash --string "./hash" --sha1 
	bash -c 'sha1sum <(echo -n "./hash")'