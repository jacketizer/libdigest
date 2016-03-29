SRC_FILES = md5.c hash.c parse.c digest.c client.c server.c
OBJ_FILES = $(patsubst %.c, %.o, $(SRC_FILES))

CC = gcc
CFLAGS = -c -fPIC -g -Wall
LDFLAGS =-s -shared -fvisibility=hidden -Wl,--exclude-libs=ALL,--no-as-needed,-soname,libdigest.so -ldl -Wall -g
PREFIX ?= /usr

.PHONY: all
all: digest

.PHONY: digest
digest: $(SRC_FILES) $(OBJ_FILES)
	@echo -ne "\e[33mBuilding libdigest.so...\e[0m\n"
	$(CC) $(LDFLAGS) $(OBJ_FILES) -o libdigest.so

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: install
install: all
	install --directory ${PREFIX}/lib
	install --directory ${PREFIX}/include/digest
	install libdigest.so ${PREFIX}/lib/
	install digest.h ${PREFIX}/include/
	install client.h ${PREFIX}/include/digest
	ldconfig -n ${PREFIX}/lib

.PHONY: examples
examples: examples/client.c
	$(CC) examples/client.c -ldigest -o client

.PHONY: check
check:
	$(CC) tests/test_lib.c -ldigest -o test_lib && ./test_lib

.PHONY: clean
clean:
	rm -f *.o

.PHONY: dist-clean
dist-clean: clean
	rm -f libdigest.so
