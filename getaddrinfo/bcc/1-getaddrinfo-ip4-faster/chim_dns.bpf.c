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
    char host[80];
    struct addrinfo **result;
};

struct event_t
{
    u32 pid;
    char comm[TASK_COMM_LEN]; // for debug
    char host[80];
    unsigned char addrs[40]; // ignore ipv6 + max 10 records
};

BPF_HASH(start, u32, struct val_t);
BPF_PERF_OUTPUT(events);

int do_entry(struct pt_regs *ctx)
{
    // hostname
    if (!PT_REGS_PARM1(ctx))
        return 0;

    // result
    if (!PT_REGS_PARM4(ctx))
        return 0;

    struct val_t val = {};
    bpf_probe_read_user(&val.host, sizeof(val.host), (void *)PT_REGS_PARM1(ctx));

    val.result = PT_REGS_PARM4(ctx);

    u32 tid = (u32)bpf_get_current_pid_tgid();
    start.update(&tid, &val);

    return 0;
}

int do_return(struct pt_regs *ctx)
{
    // char hic[TASK_COMM_LEN];
    // bpf_get_current_comm(hic, sizeof(hic));
    // bpf_trace_printk("hehe %s\n", hic);

    struct val_t *valp;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    valp = start.lookup(&tid);
    if (valp == 0)
        return 0; // missed start

    struct event_t data = {};

    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) != 0)
        return 0; // NOTE: unexpected

    data.pid = pid;
    bpf_probe_read_kernel(&data.host, sizeof(data.host), (void *)valp->host);

    struct addrinfo *res;
    bpf_probe_read_user(&res, sizeof(res), valp->result);

    int i, c = 0;
    struct addrinfo result;
    struct sockaddr_in sa4 = {};

    for (i = 0; i < 10; i++) // well ebpf check
    {
        if (res == NULL)
            break;

        bpf_probe_read_user(&result, sizeof(result), res);
        if (result.ai_family == AF_INET)
        {
            bpf_probe_read_user(&sa4, sizeof(sa4), result.ai_addr);
            __builtin_memcpy(data.addrs + 4 * c, &sa4.sin_addr, 4);
            c++;
        }

        res = result.ai_next;
    }

    events.perf_submit(ctx, &data, sizeof(data));

    start.delete(&tid);
    return 0;
}