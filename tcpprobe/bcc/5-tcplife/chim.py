from bcc import BPF
import socket
from struct import pack
import time
from datetime import datetime

bpf_text = open("chim.bpf.c").read()
b = BPF(text=bpf_text)


print('running')

# b.trace_print()

def print_event(cpu, data, size):
    ts_end = time.time()

    e = b["events"].event(data)
    task = e.task.decode()
    laddr = socket.inet_ntoa(pack("<I", e.laddr))
    raddr = socket.inet_ntoa(pack("<I", e.raddr))
    flags = e.flags
    out_str = 'OUT' if flags & 1 else 'IN'
    suc_str = 'True' if flags & 0x10 else 'False'

    ts_start = ts_end - (e.end_ns - e.start_ns)/ 10 **9

    str_start = datetime.fromtimestamp(ts_start).isoformat()
    str_end = datetime.fromtimestamp(ts_end).isoformat()

    print('{:7d} {:16s} {:3s} {:5s} {:15s} {:5d} {:15s} {:5d} {:20d} {:20d} {} {}'.format(e.pid, task, out_str, suc_str, laddr, e.lport, raddr, e.rport, e.rx_b, e.tx_b, str_start, str_end))



b["events"].open_perf_buffer(print_event)


while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
