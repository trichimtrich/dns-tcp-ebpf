from bcc import BPF
import socket

bpf_text = open("mounts.c").read()
b = BPF(text=bpf_text)

b.trace_print()

