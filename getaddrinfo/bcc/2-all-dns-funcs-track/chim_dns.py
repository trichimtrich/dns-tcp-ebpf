from bcc import BPF
import socket

f_c = [
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname2",
    "gethostent",
    "gethostent_r",
    "gethostbyname_r",
    "gethostbyname2_r",
    "gethostbyaddr",
    "gethostbyaddr_r",
    # "getaddrinfo_a",
]

f_resolv = [
    "__res_query",
    "__res_send",
    "__res_search",
    "res_send",
    "res_query",
    "__res_init",
    "res_gethostbyname",
    "res_gethostbyname2",
    "res_gethostbyaddr",
]

f_dns = [
    "dns_request_getresponse",
    "dns_lib_init",
    "dns_client_create",
    "dns_client_resolve",
    "dns_message_peekheader",
    "dns_message_parse",
]

f = [] + f_c + f_resolv + f_dns

bpf_text = open("chim_dns.bpf.c").read()
for fn in f:
    bpf_text += "HOHO({});\n".format(fn)
print(bpf_text)

b = BPF(text=bpf_text)
# b = BPF(text=bpf_text, cflags=["-I/usr/include"])
# b = BPF(text=bpf_text, cflags=["-I/usr/include", "-I/usr/include/x86_64-linux-gnu"])

libs = {
    'c': f_c,
    'dns': f_dns,
    'resolv': f_resolv,
}

for ln, fs in libs.items():
    for fn in fs:
        print(fn)
        try:
            b.attach_uprobe(name=ln, sym=fn, fn_name="do_entry_" + fn)
        except:
            print('[!] error')

b.trace_print()
