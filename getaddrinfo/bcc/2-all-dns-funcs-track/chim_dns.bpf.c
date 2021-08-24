#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

static inline amazing(char *name)
{
    bpf_trace_printk("%s ---\n", name);
}

#define HOHO(name)                           \
    int do_entry_##name(struct pt_regs *ctx) \
    {                                        \
        char p[] = #name;                    \
        amazing(p);                          \
        return 0;                            \
    }

// HOHO(getaddrinfo);
// HOHO(gethostbyname);
// HOHO(gethostbyname2);
// HOHO(gethostent);
// HOHO(gethostent_r);
// HOHO(gethostbyname_r);
// HOHO(gethostbyname2_r);
// HOHO(gethostbyaddr);
// HOHO(gethostbyaddr_r);
