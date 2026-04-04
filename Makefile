ifndef TARGET_COMPILE
    TARGET_COMPILE = /root/工作/arm-gnu-toolchain-12.2.rel1-aarch64-aarch64-none-elf/bin/aarch64-none-elf-
endif

ifndef KP_DIR
    KP_DIR = ../../KernelPatch
endif

CC  = $(TARGET_COMPILE)gcc
STRIP = $(TARGET_COMPILE)strip

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS_BASE := -Wall -Wextra -Wno-unused-parameter -fno-builtin -std=gnu11 -g

all: release debug

release: fshide_release.kpm

debug: fshide_debug.kpm

fshide_release.kpm: fshide.c
	$(CC) $(CFLAGS_BASE) -O2 $(INCLUDE_FLAGS) -c -o fshide_release.o $<
	$(CC) -r -o $@ fshide_release.o
	$(STRIP) --strip-unneeded $@

fshide_debug.kpm: fshide.c
	$(CC) $(CFLAGS_BASE) -O0 -DFSHIDE_DEBUG $(INCLUDE_FLAGS) -c -o fshide_debug.o $<
	$(CC) -r -o $@ fshide_debug.o

.PHONY: all release debug clean
clean:
	rm -f *.kpm *.o
