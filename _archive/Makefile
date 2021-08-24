TARGET := main
TARGET_BPF := $(TARGET).bpf.o

BPF_SRC := bpf/*.c


LLC ?= llc
CLANG ?= clang
INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
EXTRA_CFLAGS ?= -O2 -emit-llvm

linuxhdrs ?= /usr/src/linux-headers-`uname -r`
# linuxhdrs = /lib/modules/5.4.0-81-generic/build

# virtual ?= /tmp/lala

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
all: clean $(TARGET_BPF) 

$(TARGET_BPF): $(BPF_SRC)
	$(CLANG) \
		-O0 -O2 -emit-llvm -I $(linuxhdrs) \
		-D __BPF_TRACING__ \
		-Wno-deprecated-declarations \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-pragma-once-outside-header \
		-Wno-address-of-packed-member \
		-Wno-unknown-warning-option \
		-fno-unwind-tables \
		-fno-asynchronous-unwind-tables \
		-x c -c $< \
		\
		-g \
		\
		$(INC_FLAGS) \
		$(LINUXINCLUDE) \
		-include $(linuxhdrs)/include/linux/kconfig.h \
		-D__KERNEL__ \
		-Wno-unused-value -Wno-pointer-sign -fno-stack-protector \
		\
		-o -| $(LLC) -march=bpf -filetype=obj -o $@


# $(TARGET_BPF): $(BPF_SRC)
# 	$(CLANG) \
# 		-O0 -O2 -emit-llvm -I $(linuxhdrs) \
# 		-D __BPF_TRACING__ \
# 		-Wno-deprecated-declarations \
# 		-Wno-gnu-variable-sized-type-not-at-end \
# 		-Wno-pragma-once-outside-header \
# 		-Wno-address-of-packed-member \
# 		-Wno-unknown-warning-option \
# 		-fno-unwind-tables \
# 		-fno-asynchronous-unwind-tables \
# 		-x c -c $< \
# 		\
# 		-g \
# 		\
# 		$(INC_FLAGS) \
# 		$(LINUXINCLUDE) \
# 		-include $(linuxhdrs)/include/linux/kconfig.h \
# 		-D__KERNEL__ \
# 		-Wno-unused-value -Wno-pointer-sign -fno-stack-protector \
# 		\
# 		-include $(virtual)/include/bcc/bpf.h \
# 		\
# 		-o -| $(LLC) -march=bpf -filetype=obj -o /vagrant3/realtiger/dns_udp_recvmsg/main.bpf.o


# $(TARGET_BPF): $(BPF_SRC)
# 	$(CLANG) $(INC_FLAGS) \
# 		-D__TARGET_ARCH_x86 \
# 		-Wno-unused-value -Wno-pointer-sign \
# 		-Wno-compare-distinct-pointer-types \
# 		-Wno-gnu-variable-sized-type-not-at-end \
# 		-Wno-address-of-packed-member -Wno-tautological-compare \
# 		-Wno-unknown-warning-option \
# 		-I../include $(LINUXINCLUDE) \
# 		$(EXTRA_CFLAGS) -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@

go:
	GOPACKAGE=main go run github.com/cilium/ebpf/cmd/bpf2go -cc $(CLANG) DNSProbe ./bpf/main.c -- -I ../include $(LINUXINCLUDE) -D__TARGET_ARCH_x86
	go build .

.PHONY: clean
clean:
	rm -rf $(TARGET_BPF)