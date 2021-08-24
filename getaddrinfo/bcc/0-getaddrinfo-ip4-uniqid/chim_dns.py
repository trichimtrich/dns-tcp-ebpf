from bcc import BPF
import socket

bpf_text = open("chim_dns.bpf.c").read()
b = BPF(text=bpf_text)
# b = BPF(text=bpf_text, cflags=["-I/usr/include"])
# b = BPF(text=bpf_text, cflags=["-I/usr/include", "-I/usr/include/x86_64-linux-gnu"])

b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="do_entry")
b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="do_return")
# b.attach_uprobe(name="c", sym="gethostbyname", fn_name="do_entry")
# b.attach_uprobe(name="c", sym="gethostbyname2", fn_name="do_entry")

# b.trace_print()


def print_entry_event(cpu, data, size):
    e = b["entry_events"].event(data)
    print(">>> [{:<8d}] {:<7d} {:<16s} {:s}".format(e.uniq_id, e.pid, e.comm, e.host))


def print_return_event(cpu, data, size):
    e = b["return_events"].event(data)
    print(
        "... [{:<8}] {:s}".format(e.uniq_id, socket.inet_ntop(socket.AF_INET, e.addr))
    )


b["entry_events"].open_perf_buffer(print_entry_event)
b["return_events"].open_perf_buffer(print_return_event)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

"""
TODO:
- ignore 0.0.0.0
- de duplicate result
- match entry_event + return_event by uniq_id

"""
