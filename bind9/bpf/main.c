#include <linux/bpf.h>
#include <linux/sched.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PKT 512

struct dns_data_t
{
	u32 pid;
	char comm[TASK_COMM_LEN]; // TODO: for debug, remove pls
	u8 pkt[MAX_PKT];
};

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} dns_events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct dns_data_t);
	__uint(max_entries, 1);
} dns_data SEC(".maps");

struct isc_buffer_t
{
	unsigned int magic;
	void *base;
	unsigned int length;
};

SEC("uprobe/bind9__dns_message_parse")
int uprobe__dns_message_parse(struct pt_regs *ctx)
{
	struct isc_buffer_t *source = (struct isc_buffer_t *)PT_REGS_PARM2(ctx);

	if (!source)
		return 0;

	struct isc_buffer_t s = {};
	bpf_probe_read(&s, sizeof(s), source); // userspace

	u32 len = s.length;
	if (len > MAX_PKT)
		len = MAX_PKT;

	u32 zero = 0;

	struct dns_data_t *data = bpf_map_lookup_elem(&dns_data, &zero);
	if (!data) // this should never happen, just making the verifier happy
		return 0;

	// TODO: debug
	bpf_get_current_comm(data->comm, sizeof(data->comm));

	u64 pid_tgid = bpf_get_current_pid_tgid();
	data->pid = pid_tgid >> 32;

	bpf_probe_read(data->pkt, len, s.base);

	bpf_perf_event_output(ctx, &dns_events, BPF_F_CURRENT_CPU, data, 4 + 16 + len);

	return 0;
}

char __license[] SEC("license") = "GPL";