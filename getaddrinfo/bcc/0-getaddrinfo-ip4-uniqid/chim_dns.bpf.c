#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

struct addrinfo
{
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    unsigned int ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};

struct val_t
{
    u32 uniq_id;
    struct addrinfo **result;
};

struct entry_ev_t
{
    u32 uniq_id;
    u32 pid;
    char comm[TASK_COMM_LEN]; // for debug
    char host[80];            // max is 255
};

struct return_ev_t
{
    u32 uniq_id;
    unsigned char addr[4]; // ignore ipv6
};

BPF_HASH(start, u32, struct val_t);
BPF_PERF_OUTPUT(entry_events);
BPF_PERF_OUTPUT(return_events);

int do_entry(struct pt_regs *ctx)
{
    // hostname
    if (!PT_REGS_PARM1(ctx))
        return 0;

    // result
    if (!PT_REGS_PARM4(ctx))
        return 0;

    struct entry_ev_t data = {};
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0)
    {
        bpf_probe_read_user(&data.host, sizeof(data.host), (void *)PT_REGS_PARM1(ctx));
        struct val_t val = {};

        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        data.pid = pid;

        u32 uniq_id = bpf_get_prandom_u32();
        data.uniq_id = uniq_id;
        val.uniq_id = uniq_id;

        val.result = PT_REGS_PARM4(ctx);

        entry_events.perf_submit(ctx, &data, sizeof(data));
        start.update(&tid, &val);
    }

    return 0;
}

int do_return(struct pt_regs *ctx)
{
    // char hic[TASK_COMM_LEN];
    // bpf_get_current_comm(hic, sizeof(hic));
    // bpf_trace_printk("hehe %s\n", hic);

    struct val_t *valp;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    valp = start.lookup(&tid);
    if (valp == 0)
        return 0; // missed start

    struct addrinfo *res;
    bpf_probe_read_user(&res, sizeof(res), valp->result);

    struct return_ev_t data = {};
    data.uniq_id = valp->uniq_id;

    int i;
    struct addrinfo result;
    struct sockaddr_in sa4 = {};

    for (i = 0; i < 50; i++) // well ebpf check
    {
        if (res == NULL)
            break;

        bpf_probe_read_user(&result, sizeof(result), res);
        if (result.ai_family == AF_INET)
        {
            bpf_probe_read_user(&sa4, sizeof(sa4), result.ai_addr);
            __builtin_memcpy(data.addr, &sa4.sin_addr, 4);
        }

        return_events.perf_submit(ctx, &data, sizeof(data));

        res = result.ai_next;
    }

    start.delete(&tid);
    return 0;
}