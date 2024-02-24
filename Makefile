.DEFAULT_GOAL: prod
CC=gcc
CC_OPTS=-lm -Wall -Wextra -o

dev: src/main.c
	$(CC) src/main.c -Og $(CC_OPTS) ./hash

prod: src/main.c
	$(CC) src/main.c -O3 $(CC_OPTS) ./hash

test: crc32 md5

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
