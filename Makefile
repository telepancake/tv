obj-m += proctrace.o

KDIR    ?= /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)
SIGN    := $(KDIR)/scripts/sign-file
MOK_KEY ?= $(PWD)/MOK.priv
MOK_CER ?= $(PWD)/MOK.der

all: tv fv sudtrace yeetdump
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Generate a MOK keypair (one-time).  After this, run:
#   sudo mokutil --import MOK.der
# then reboot and enroll through the MOK manager.
keygen:
	openssl req -new -x509 -newkey rsa:2048 \
	        -keyout $(MOK_KEY) -outform DER -out $(MOK_CER) \
	        -nodes -days 36500 -subj "/CN=Proctrace Module Signing Key/"
	@echo ""
	@echo "Key generated.  Now run:"
	@echo "  sudo mokutil --import $(MOK_CER)"
	@echo "Then reboot and enroll the key in the MOK manager."

# Sign the module (requires MOK.priv + MOK.der from keygen).
sign: all
	$(SIGN) sha256 $(MOK_KEY) $(MOK_CER) proctrace.ko

# Build + sign + load in one step.
load: sign
	-sudo rmmod proctrace 2>/dev/null
	sudo insmod proctrace.ko

unload:
	sudo rmmod proctrace

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f sudtrace sud32 sud64

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

ZSTD_DIR  := deps/zstd/lib
ZSTD_LIB  := $(ZSTD_DIR)/libzstd.a

DUCKDB_DIR := deps/duckdb
DUCKDB_AMAL_DIR := $(DUCKDB_DIR)/src/amalgamation
DUCKDB_HPP := $(DUCKDB_AMAL_DIR)/duckdb.hpp
DUCKDB_CPP := $(DUCKDB_AMAL_DIR)/duckdb.cpp
DUCKDB_INC := $(DUCKDB_DIR)/src/include
DUCKDB_OBJ := build/duckdb.o

CXXFLAGS := -std=c++23 -O2 -I. -I$(ZSTD_DIR) -I$(DUCKDB_INC)
TV_LIBS := -lm -pthread -ldl $(ZSTD_LIB)
SUD_CFLAGS  := -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -ffreestanding -fno-builtin -fno-stack-protector -fno-pie -fomit-frame-pointer -I.
SUD_LDFLAGS := -nostdlib -static -no-pie -Wl,--build-id=none

# Set SIGSYS_DIAG=1 to enable the SIGSYS handler entry/exit diagnostic dumps.
# This prints the saved ucontext (registers, stack pointer, uc_stack) at both
# handler entry and exit so that signal-frame corruption can be detected.
# Example:  make SIGSYS_DIAG=1 sud32
SIGSYS_DIAG ?= 0
ifeq ($(SIGSYS_DIAG),1)
SUD_CFLAGS  += -DSUDTRACE_SIGSYS_DIAG
endif
SUD_SRCS    := sud/wrapper.c sud/libc.c sud/raw.c sud/event.c sud/elf.c sud/handler.c sud/loader.c deps/printf/printf.c
SUD_NATIVE  := $(if $(filter x86_64,$(shell uname -m)),sud64,sud32)

$(ZSTD_LIB):
	$(MAKE) -C $(ZSTD_DIR) libzstd.a

# DuckDB is vendored as a single ~25 MB amalgamation file. The amalgamation
# script is run on demand. The resulting object is ~60 MB and takes ~7 min /
# ~14 GB RAM to build; subsequent tv recompiles only re-link.
$(DUCKDB_CPP): | $(DUCKDB_DIR)/scripts/amalgamation.py
	cd $(DUCKDB_DIR) && python3 scripts/amalgamation.py

$(DUCKDB_OBJ): $(DUCKDB_CPP)
	@mkdir -p build
	g++ -std=c++17 -O2 -I$(DUCKDB_INC) -c $(DUCKDB_CPP) -o $@

TV_SRCS := main.cpp engine.cpp uproctrace.cpp tests.cpp wire_in.cpp tv_db.cpp data_source.cpp
TV_HDRS := engine.h wire_in.h tv_db.h data_source.h wire/wire.h $(DUCKDB_HPP)

tv: $(TV_SRCS) $(TV_HDRS) $(ZSTD_LIB) $(DUCKDB_OBJ)
	g++ $(CXXFLAGS) -o tv $(TV_SRCS) $(DUCKDB_OBJ) $(TV_LIBS)

fv: fv.cpp engine.cpp engine.h
	g++ $(CXXFLAGS) -o fv fv.cpp engine.cpp

sud64: $(SUD_SRCS) sudtrace.lds
	cc -m64 $(SUD_CFLAGS) $(SUD_LDFLAGS) -Wl,-Ttext-segment=0x40000000 -T sudtrace.lds -o sud64 $(SUD_SRCS) -lgcc

sud32: $(SUD_SRCS) sudtrace.lds
	cc -m32 $(SUD_CFLAGS) $(SUD_LDFLAGS) -Wl,-Ttext-segment=0x20000000 -T sudtrace.lds -o sud32 $(SUD_SRCS) -lgcc

sudtrace: sud/sudtrace.c sud32 sud64 wire/wire.h
	cc -O2 -I. -static -o sudtrace sud/sudtrace.c

yeetdump: tools/yeetdump/yeetdump.c wire/wire.h
	cc -std=c99 -O2 -Wall -Wextra -I. -o yeetdump tools/yeetdump/yeetdump.c

.PHONY: wire-test
wire-test: yeetdump
	./yeetdump --selftest

.PHONY: all keygen sign load unload clean clean-bins install test
test: tv
	./tv --test

clean-bins:
	rm -f tv fv yeetdump
	-$(MAKE) -C $(ZSTD_DIR) clean
