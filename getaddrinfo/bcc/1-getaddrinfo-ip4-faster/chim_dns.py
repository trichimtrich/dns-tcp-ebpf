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


def print_event(cpu, data, size):
    e = b["events"].event(data)
    print(">>> {} - {} - {}".format(e.pid, e.comm, e.host))
    addrs = []
    for i in range(0, 40, 4):
        addr_b = "".join(map(chr, e.addrs[i : i + 4]))
        # addr_b = bytes(bytearray(e.addrs[i : i + 4]))  # weird
        # print(addr_b, type(addr_b))
        if addr_b == "\x00\x00\x00\x00":
            break
        addr = socket.inet_ntop(socket.AF_INET, addr_b)
        if addr not in addrs:
            addrs.append(addr)
            print(addr)


b["events"].open_perf_buffer(print_event)


while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
