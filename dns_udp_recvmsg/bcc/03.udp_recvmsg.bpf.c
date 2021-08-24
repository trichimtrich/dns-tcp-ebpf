#include <net/sock.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>

// https://datatracker.ietf.org/doc/html/draft-ietf-dnsind-udp-size
// max udp size for DNS
#define MAX_PKT 512

struct dns_data_t
{
    u32 pid;
    char comm[TASK_COMM_LEN]; // TODO: for debug, remove pls
    u8 pkt[MAX_PKT];
};

BPF_PERF_OUTPUT(dns_events);

// store msghdr pointer captured on syscall entry to parse on syscall return
BPF_HASH(tbl_udp_msg_hdr, u64, struct msghdr *);

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(dns_data, struct dns_data_t, 1);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
// https://github.com/torvalds/linux/blob/v4.1/net/ipv4/udp.c#L1255
int trace_udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msghdr)
#else
// https://github.com/torvalds/linux/blob/v4.0/net/ipv4/udp.c#L1257
int trace_udp_recvmsg(struct pt_regs *ctx, struct kiocb *iocb, struct sock *sk, struct msghdr *msghdr)
#endif
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // only grab port 53 packets, 13568 is ntohs(53)
    if (sk->__sk_common.skc_dport == 13568)
    {
        tbl_udp_msg_hdr.update(&pid_tgid, &msghdr);
    }
    return 0;
}

int trace_udp_ret_recvmsg(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 zero = 0;

    struct msghdr **msgpp = tbl_udp_msg_hdr.lookup(&pid_tgid);
    if (msgpp == 0)
        return 0;

    int copied = (int)PT_REGS_RC(ctx);
    if (copied < 0 || copied > MAX_PKT)
        goto delete_and_return;
    size_t buflen = (size_t)copied;
    if (buflen > MAX_PKT)
        buflen = MAX_PKT;

    struct msghdr *msghdr = (struct msghdr *)*msgpp;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
    // https://github.com/torvalds/linux/blob/v3.19/include/linux/socket.h#L47
    if (msghdr->msg_iter.type != ITER_IOVEC)
        goto delete_and_return;

    if (buflen > msghdr->msg_iter.iov->iov_len)
        goto delete_and_return;

    void *iovbase = msghdr->msg_iter.iov->iov_base;
#else
    // https://github.com/torvalds/linux/blob/v3.18/include/linux/socket.h#L47
    if (buflen > msghdr->msg_iov->iov_len)
        goto delete_and_return;

    // TODO: UNFINISHED !!!
    void *iovbase = msghdr->msg_iov->iov_base;
#endif

    bpf_trace_printk("hehe %p\n", iovbase);

    struct dns_data_t *data = dns_data.lookup(&zero);
    if (!data) // this should never happen, just making the verifier happy
        return 0;

    if (bpf_get_current_comm(data->comm, sizeof(data->comm)) != 0)
        goto delete_and_return;

    bpf_probe_read(data->pkt, buflen, iovbase);

    data->pid = pid_tgid >> 32;

    dns_events.perf_submit(ctx, data, 4 + 16 + buflen);

delete_and_return:
    tbl_udp_msg_hdr.delete(&pid_tgid);
    return 0;
}