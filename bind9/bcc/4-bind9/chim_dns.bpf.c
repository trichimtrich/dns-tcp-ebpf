#include <linux/sched.h>

#define MAX_PKT 512

struct dns_data_t
{
    u32 pid;
    char comm[TASK_COMM_LEN]; // TODO: for debug, remove pls
    u8 pkt[MAX_PKT];
};

BPF_PERF_OUTPUT(dns_events);

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(dns_data, struct dns_data_t, 1);

struct isc_buffer_t
{
    unsigned int magic;
    void *base;
    /*@{*/
    /*! The following integers are byte offsets from 'base'. */
    unsigned int length;
};

int do_entry(struct pt_regs *ctx, void *a, struct isc_buffer_t *source)
{
    struct isc_buffer_t s = {};
    bpf_probe_read(&s, sizeof(s), source);

    u32 len = s.length;
    if (len > MAX_PKT)
        len = MAX_PKT;

    u32 zero = 0;
    struct dns_data_t *data = dns_data.lookup(&zero);
    if (!data) // this should never happen, just making the verifier happy
        return 0;

    if (bpf_get_current_comm(data->comm, sizeof(data->comm)) != 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;

    // bpf_trace_printk("hola %d - %p\n", len, s.base);
    bpf_probe_read(data->pkt, len, s.base);

    dns_events.perf_submit(ctx, data, 4 + 16 + len);

    return 0;
}
