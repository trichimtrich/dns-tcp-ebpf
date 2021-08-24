#include <linux/bpf.h>
#include <linux/sched.h>
#include <net/sock.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// NOTE: constants must be synced with go version
#define MAX_HOST_LEN 250
#define MAX_RESULT 15

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
	char host[MAX_HOST_LEN];
	u8 addrs[MAX_RESULT * 4]; // limit number of IPv4 results
	char comm[TASK_COMM_LEN]; // TODO: remove this, for debug only
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct val_t);
	__uint(max_entries, 10240);
} start SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("uprobe/libc_getaddrinfo")
int uprobe_libc_getaddrinfo(struct pt_regs *ctx)
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
	bpf_map_update_elem(&start, &pid_tgid, &val, BPF_ANY);

	return 0;
}

SEC("uretprobe/libc_getaddrinfo")
int uretprobe_libc_getaddrinfo(struct pt_regs *ctx)
{
	struct val_t *valp;

	u64 pid_tgid = bpf_get_current_pid_tgid();

	valp = bpf_map_lookup_elem(&start, &pid_tgid);
	if (valp == NULL)
		return 0; // missed start

	struct event_t data = {};

	data.pid = pid_tgid >> 32;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));	   // TODO: remove this
	bpf_probe_read(&data.host, sizeof(data.host), valp->host); // kernel read

	struct addrinfo *res;
	bpf_probe_read(&res, sizeof(res), valp->result); // userspace

	int i;
	struct addrinfo result;
	struct sockaddr_in sa4 = {};

#pragma unroll MAX_RESULT
	for (i = 0; i < MAX_RESULT; i++) // well ebpf check
	{
		if (res == NULL)
			break;

		bpf_probe_read(&result, sizeof(result), res); // userspace
		if (result.ai_family == AF_INET)
		{
			bpf_probe_read(&sa4, sizeof(sa4), result.ai_addr); // userspace
			// bpf_probe_read(&data.addrs[4 * i], 4, &sa4.sin_addr);
			__builtin_memcpy(&data.addrs[4 * i], &sa4.sin_addr, 4);
		}

		res = result.ai_next;
	}
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

delete_and_return:
	bpf_map_delete_elem(&start, &pid_tgid);
	return 0;
}

char __license[] SEC("license") = "GPL";