obj-m += proctrace.o

KDIR    ?= /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)
SIGN    := $(KDIR)/scripts/sign-file
MOK_KEY ?= $(PWD)/MOK.priv
MOK_CER ?= $(PWD)/MOK.der

all: tv fv sudtrace
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

CXXFLAGS := -std=c++23 -O2 -I$(ZSTD_DIR)
TV_LIBS := -lm -pthread $(ZSTD_LIB)
SUD_COMMON_CFLAGS := -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -ffreestanding -fno-builtin -fno-stack-protector -fno-pie -fomit-frame-pointer
SUD_COMMON_LDFLAGS := -nostdlib -static -no-pie -Wl,--build-id=none
SUD_COMMON_SRCS := sudtrace.c sudmini.c
SUD_NATIVE := $(if $(filter x86_64,$(shell uname -m)),sud64,sud32)

gen_sql_h: gen_sql_h.c
	cc -O2 -o gen_sql_h gen_sql_h.c

tv_sql.h: tv.sql gen_sql_h
	./gen_sql_h tv.sql tv_sql.h

$(ZSTD_LIB):
	$(MAKE) -C $(ZSTD_DIR) libzstd.a

tv: main.cpp engine.cpp engine.h json.cpp json.h uproctrace.cpp tests.cpp $(ZSTD_LIB)
	g++ $(CXXFLAGS) -o tv main.cpp engine.cpp json.cpp uproctrace.cpp tests.cpp -static $(TV_LIBS)

fv: fv.cpp engine.cpp engine.h
	g++ $(CXXFLAGS) -o fv fv.cpp engine.cpp

sudtrace: sudtrace.c sudtrace.lds
	cc -O2 -fno-stack-protector -static -Wl,-Ttext-segment=0x40000000 -T sudtrace.lds -o sudtrace sudtrace.c -lm
sud64: $(SUD_COMMON_SRCS) sudtrace.lds
	cc -m64 $(SUD_COMMON_CFLAGS) $(SUD_COMMON_LDFLAGS) -Wl,-Ttext-segment=0x40000000 -T sudtrace.lds -o sud64 $(SUD_COMMON_SRCS) -lgcc

sud32: $(SUD_COMMON_SRCS) sudtrace.lds
	cc -m32 $(SUD_COMMON_CFLAGS) $(SUD_COMMON_LDFLAGS) -Wl,-Ttext-segment=0x20000000 -T sudtrace.lds -o sud32 $(SUD_COMMON_SRCS) -lgcc

sudtrace: sud32 sud64
	cp $(SUD_NATIVE) sudtrace

.PHONY: all keygen sign load unload clean clean-bins install test
test: tv
	./tv --test

clean-bins:
	rm -f tv fv gen_sql_h
	-$(MAKE) -C $(ZSTD_DIR) clean
