obj-m += proctrace.o

KDIR    ?= /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)
SIGN    := $(KDIR)/scripts/sign-file
MOK_KEY ?= $(PWD)/MOK.priv
MOK_CER ?= $(PWD)/MOK.der

all: tv sudtrace
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

install:
$(MAKE) -C $(KDIR) M=$(PWD) modules_install
depmod -a

CFLAGS := -O2 -flto=auto -DSQLITE_ENABLE_FTS5 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=0

gen_sql_h: gen_sql_h.c
cc -O2 -o gen_sql_h gen_sql_h.c

tv_sql.h: tv.sql gen_sql_h
./gen_sql_h tv.sql tv_sql.h

tv: main.c engine.c engine.h tv_sql.h uproctrace.c
cc $(CFLAGS) -o tv main.c engine.c uproctrace.c sqlite3.c -static -lm

sudtrace: sudtrace.c sudtrace.lds
cc -O2 -fno-stack-protector -static -Wl,-Ttext-segment=0x40000000 -T sudtrace.lds -o sudtrace sudtrace.c -lm

.PHONY: all keygen sign load unload clean install test
test: tv
bash tests/run_tests.sh
