CC ?= cc
CFLAGS ?= -std=c11 -O2

.PHONY: all clean test

all: yeetdump

yeetdump: yeetdump.c wire.h
	$(CC) $(CFLAGS) -I. yeetdump.c -o $@

test: yeetdump reference-v1.wire reference-v2.wire
	./yeetdump --selftest
	./yeetdump reference-v1.wire reference-v2.wire >/dev/null

clean:
	rm -f yeetdump *.o
