from bcc import BPF
import dnslib
from hexdump import hexdump

bpf_text = open("chim_dns.bpf.c").read()
b = BPF(text=bpf_text)

b.attach_uprobe(name="dns", sym="dns_message_parse", fn_name="do_entry")
# b.attach_uretprobe(name="dns", sym="dns_message_parse", fn_name="do_return")

print('running')

# b.trace_print()


def print_event(cpu, data, size):
    e = b["dns_events"].event(data)
    print(">>> {} - {} ".format(e.pid, e.comm))
    pkt = bytearray(e.pkt)
    try:
        dnsrec = dnslib.DNSRecord.parse(pkt)
    except:
        print('... parse error')
        return
    print(dnsrec.questions)
    print(dnsrec.rr)
    print()


b["dns_events"].open_perf_buffer(print_event)


while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
