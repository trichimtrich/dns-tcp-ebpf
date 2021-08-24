from bcc import BPF

bpf_text = r'''
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <net/sock.h>

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    bpf_trace_printk("%p - %d - %d\n", sk, state, bpf_get_current_pid_tgid() >> 32);
    // /usr/src/linux-headers-5.4.0-81/include/net/tcp_states.h
    return 0;
}
'''

b = BPF(text=bpf_text)

print('running')

b.trace_print()