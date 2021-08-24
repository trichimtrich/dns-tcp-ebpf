TARGET := main
TARGET_BPF := $(TARGET).bpf.o

BPF_SRC := bpf/*.c

LLC ?= llc
CLANG ?= clang
EXTRA_CFLAGS ?= -O2 -emit-llvm -g

linuxhdrs ?= /lib/modules/`uname -r`/build

LINUXINCLUDE =  \
				-I$(linuxhdrs)/arch/x86/include \
				-I$(linuxhdrs)/arch/x86/include/generated \
				-I$(linuxhdrs)/include \
				-I$(linuxhdrs)/arch/x86/include/uapi \
				-I$(linuxhdrs)/arch/x86/include/generated/uapi \
				-I$(linuxhdrs)/include/uapi \
				-I$(linuxhdrs)/include/generated/uapi \
				-I../include \
				-I/usr/include


.PHONY: all
all: clean build

$(TARGET_BPF): $(BPF_SRC)
	$(CLANG) \
		$(EXTRA_CFLAGS) \
		$(LINUXINCLUDE) \
		-include chim_helpers.h \
		-Wno-deprecated-declarations \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-pragma-once-outside-header \
		-Wno-address-of-packed-member \
		-Wno-unknown-warning-option \
		-fno-unwind-tables \
		-fno-asynchronous-unwind-tables \
		-Wno-unused-value -Wno-pointer-sign -fno-stack-protector \
		-c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@

run: clean $(TARGET_BPF)
	sudo go run .

build: $(TARGET_BPF)
	go build .

.PHONY: clean
clean:
	rm -rf $(TARGET_BPF)