#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/sock.h>

#define F_OUTBOUND 0x1
#define F_CONNECTED 0x10

struct event_t
{
    u64 start_ns;
    u64 end_ns;
    u32 pid;
    u32 laddr;
    u16 lport;
    u32 raddr;
    u16 rport;
    u8 flags;
    u64 rx_b;
    u64 tx_b;
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

struct conn_t
{
    u32 pid;
    u64 start_ns;
    u8 flags;
    char task[TASK_COMM_LEN];
};

BPF_HASH(conns, struct sock *, struct conn_t);

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    struct conn_t *pconn;
    pconn = conns.lookup(&sk);

    struct conn_t conn = {};

    if (state == TCP_SYN_SENT)
    {
        // this is the first state of OUTBOUND connection
        if (pconn != NULL)
        {
            // NOTE: weird ? duplicated pointer value
            // other socket is stucked? or somehow hash record is still there
            // just discard it
            conns.delete(&sk);
        }

        //create temp conn
        conn.flags = F_OUTBOUND;
        conn.start_ns = bpf_ktime_get_ns();

        goto attach_pid_and_update_conn;
    }

    if (pconn == NULL)
    {
        if (state == TCP_ESTABLISHED)
        {
            // this is the first state of INBOUND connection

            // create conn
            conn.flags |= F_CONNECTED;
            conn.start_ns = bpf_ktime_get_ns();

            goto update_conn;
        }

        // missed creation
        return 0;
    }

    bpf_probe_read(&conn, sizeof(conn), pconn);

    if (state == TCP_ESTABLISHED)
    {
        // successful outbound connection
        conn.flags |= F_CONNECTED;
        goto update_conn;
    }

    if (state == TCP_LAST_ACK)
        goto attach_pid_and_update_conn;

    if (state != TCP_CLOSE)
        return 0;

    // NOTE: we do filter here at TCP_CLOSE state
    // NOTE: accept IPv4 only
    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET)
        goto delete_conn;

    struct event_t data = {};
    u32 laddr, raddr;
    bpf_probe_read(&data.laddr, sizeof(data.laddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&data.raddr, sizeof(data.raddr), &sk->__sk_common.skc_daddr);

    // NOTE: ignore local <-> local
    if ((data.laddr & 0xff) == 0x7f && (data.raddr & 0xff) == 0x7f)
        goto delete_conn;

    bpf_probe_read(&data.lport, sizeof(data.lport), &sk->__sk_common.skc_num);
    bpf_probe_read(&data.rport, sizeof(data.rport), &sk->__sk_common.skc_dport);

    data.start_ns = conn.start_ns;
    data.end_ns = bpf_ktime_get_ns();
    data.pid = conn.pid;
    __builtin_memcpy(&data.task, &conn.task, sizeof(data.task));

    data.flags = conn.flags;
    data.rport = ntohs(data.rport);

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    data.rx_b = tp->bytes_received;
    data.tx_b = tp->bytes_acked;

    events.perf_submit(ctx, &data, sizeof(data));

delete_conn:
    conns.delete(&sk);
    return 0;

attach_pid_and_update_conn:
    bpf_get_current_comm(&conn.task, sizeof(conn.task));
    conn.pid = bpf_get_current_pid_tgid() >> 32;

update_conn:
    conns.update(&sk, &conn);
    return 0;
}
