# Makefile for wg-obfuscator (nolibc + wsock.h edition)
# Follows Svarkovsky/whitehttpd freestanding build technique
# Target: nolibc-mips32el (MIPS32r2 Little-Endian, O32 ABI)

APP            := wg-obfuscator
SRC            := wg-obfuscator.c
SSTRIP         := python3 tools/sstrip.py
CHECK_ELF      := python3 tools/check_elf.py

CC_MIPSEL      ?= mipsel-linux-gnu-gcc
CC_MIPSBE      ?= mips-linux-gnu-gcc
CC_NATIVE      ?= gcc

COMMON_CFLAGS  := -Oz -flto -fno-ident -fno-asynchronous-unwind-tables \
                  -fno-unwind-tables -fno-stack-protector -fomit-frame-pointer \
                  -ffunction-sections -fdata-sections -fno-builtin \
                  -Wall -Wextra

# MIPS32 O32 ABI flags:
# -G 0: disable GP-relative small data to avoid SIGBUS when _start does not set $gp
# -mno-abicalls: freestanding non-PIC code without GOT table overhead
MIPS_CFLAGS    := -march=mips32r2 -mabi=32 -G 0 -mno-abicalls -fno-pic -fno-pie -no-pie

# Linker flags: static freestanding without libc/startfiles
MIPS_LDFLAGS   := -nostdlib -nostartfiles -static -no-pie \
                  -Wl,--gc-sections -Wl,--build-id=none \
                  -Wl,-z,noseparate-code -Wl,-z,noexecstack -Wl,-s

X86_LDFLAGS    := -nostdlib -nostartfiles -static -no-pie \
                  -Wl,--gc-sections -Wl,--build-id=none \
                  -Wl,-z,noseparate-code -Wl,-z,noexecstack -Wl,-s

.PHONY: all mips32el mips32be x86_64 test check-elf clean

all: mips32el

mips32el: $(SRC) wsock.h nolibc.h tools/sstrip.py
	$(CC_MIPSEL) $(COMMON_CFLAGS) $(MIPS_CFLAGS) -EL $(SRC) $(MIPS_LDFLAGS) -o $(APP)-nolibc-mips32el
	$(SSTRIP) $(APP)-nolibc-mips32el
	@ls -lh $(APP)-nolibc-mips32el
	@$(CHECK_ELF) $(APP)-nolibc-mips32el

mips32be: $(SRC) wsock.h nolibc.h tools/sstrip.py
	$(CC_MIPSBE) $(COMMON_CFLAGS) $(MIPS_CFLAGS) -EB $(SRC) $(MIPS_LDFLAGS) -o $(APP)-nolibc-mips32be
	$(SSTRIP) $(APP)-nolibc-mips32be
	@ls -lh $(APP)-nolibc-mips32be

x86_64: $(SRC) wsock.h nolibc.h tools/sstrip.py
	$(CC_NATIVE) $(COMMON_CFLAGS) -fno-pie -no-pie $(SRC) $(X86_LDFLAGS) -o $(APP)-nolibc-x86_64
	$(SSTRIP) $(APP)-nolibc-x86_64
	@ls -lh $(APP)-nolibc-x86_64

check-elf:
	$(CHECK_ELF) $(APP)-nolibc-mips32el

test: mips32el
	python3 tools/test_compat.py

clean:
	rm -f $(APP)-nolibc-mips32el $(APP)-nolibc-mips32be $(APP)-nolibc-x86_64 test-oz test-mips
