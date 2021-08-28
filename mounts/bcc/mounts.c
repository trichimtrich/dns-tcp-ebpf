
TRACEPOINT_PROBE(syscalls, sys_exit_mount)
{
    bpf_trace_printk("mounted\n");
}

TRACEPOINT_PROBE(syscalls, sys_exit_umount)
{
    bpf_trace_printk("umounted\n");
}