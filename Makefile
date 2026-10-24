# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Membangun heideltrace dengan libbpf dan bpftool dari submodule git.
# Kebutuhan sistem: clang (>= 11), make, gcc, libelf-dev, zlib1g-dev, libssl-dev.
#
#   git submodule update --init --recursive
#   make
#
OUTPUT		:= build
CLANG		?= clang
CC		?= cc

LIBBPF_SRC	:= $(abspath libbpf/src)
BPFTOOL_SRC	:= $(abspath bpftool/src)
LIBBPF_OBJ	:= $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT	?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL		?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool

ARCH		?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
VMLINUX_BTF	?= /sys/kernel/btf/vmlinux

INCLUDES	:= -I$(OUTPUT) -Isrc
CFLAGS		:= -g -O2 -Wall
LDLIBS		:= -lelf -lz

ifeq ($(V),1)
	Q =
else
	Q = @
endif

.PHONY: all clean

all: $(OUTPUT)/heideltrace

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(Q)mkdir -p $@

$(LIBBPF_SRC)/Makefile $(BPFTOOL_SRC)/Makefile:
	@echo "Submodule belum diunduh. Jalankan: git submodule update --init --recursive"
	@false

# libbpf statis, header dipasang ke $(OUTPUT)/bpf/
$(LIBBPF_OBJ): $(LIBBPF_SRC)/Makefile $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		\
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		\
		INCLUDEDIR= LIBDIR= UAPIDIR=				\
		install

# bpftool hanya dipakai saat build (vmlinux.h dan skeleton)
$(BPFTOOL): $(BPFTOOL_SRC)/Makefile | $(BPFTOOL_OUTPUT)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Tipe kernel untuk CO-RE. Cukup dibuat sekali pada mesin mana pun yang punya BTF.
$(OUTPUT)/vmlinux.h: | $(BPFTOOL) $(OUTPUT)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(OUTPUT)/heideltrace.bpf.o: src/heideltrace.bpf.c src/heideltrace.h $(OUTPUT)/vmlinux.h $(LIBBPF_OBJ)
	$(Q)$(CLANG) -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH)	\
		$(INCLUDES) -c $< -o $(OUTPUT)/heideltrace.tmp.bpf.o
	$(Q)$(BPFTOOL) gen object $@ $(OUTPUT)/heideltrace.tmp.bpf.o

$(OUTPUT)/heideltrace.skel.h: $(OUTPUT)/heideltrace.bpf.o
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/heideltrace.o: src/heideltrace.c src/heideltrace.h $(OUTPUT)/heideltrace.skel.h $(LIBBPF_OBJ)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/heideltrace: $(OUTPUT)/heideltrace.o $(LIBBPF_OBJ)
	$(Q)$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@
	@echo "Selesai: $@"

clean:
	$(Q)rm -rf $(OUTPUT)

# Tidak ada target install: agen dijalankan langsung dari build/
.DELETE_ON_ERROR:
.SECONDARY:
