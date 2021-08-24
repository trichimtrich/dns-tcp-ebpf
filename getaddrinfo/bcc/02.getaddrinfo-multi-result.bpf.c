#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

// NOTE: constants must be synced with go version
#define MAX_HOST_LEN 250
#define MAX_RESULT 1

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
    char host[MAX_HOST_LEN];
    struct addrinfo **result;
};

struct event_t
{
    u32 pid;
    char comm[TASK_COMM_LEN]; // TODO: remove this
    char host[MAX_HOST_LEN];
    unsigned char addrs[MAX_RESULT * 4]; // limit number of IPV4 results
};

BPF_HASH(start, u64, struct val_t);
BPF_PERF_OUTPUT(events);

int do_entry(struct pt_regs *ctx)
{
    // query host
    if (!PT_REGS_PARM1(ctx))
        return 0;

    // result ptr
    if (!PT_REGS_PARM4(ctx))
        return 0;

    struct val_t val = {};
    bpf_probe_read_str(&val.host, sizeof(val.host), (void *)PT_REGS_PARM1(ctx));

    val.result = PT_REGS_PARM4(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    start.update(&pid_tgid, &val);

    return 0;
}

int do_return(struct pt_regs *ctx)
{
    struct val_t *valp;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    valp = start.lookup(&pid_tgid);
    if (valp == 0)
        return 0; // missed start

    struct event_t data = {};

    // TODO: remove this
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) != 0)
        goto delete_and_return;

    data.pid = pid_tgid >> 32;
    __builtin_memcpy(data.host, valp->host, sizeof(data.host));

    struct addrinfo *res;
    bpf_probe_read(&res, sizeof(res), valp->result);

    int i, c = 0;
    struct addrinfo result;
    struct sockaddr_in sa4 = {};

#pragma unroll
    for (i = 0; i < MAX_RESULT; i++) // well ebpf check
    {
        if (res == NULL)
            break;

        bpf_probe_read(&result, sizeof(result), res);
        if (result.ai_family == AF_INET)
        {
            bpf_probe_read(&sa4, sizeof(sa4), result.ai_addr);
            __builtin_memcpy(data.addrs + 4 * c, &sa4.sin_addr, 4);
            c++;
        }

        res = result.ai_next;
    }
    events.perf_submit(ctx, &data, sizeof(data));

delete_and_return:
    start.delete(&pid_tgid);
    return 0;
}