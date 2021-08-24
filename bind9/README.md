Capture DNS via user hook at `libdns` binary and `dns_message_parse` function

https://github.com/isc-projects/bind9/blob/2ceca6f24dbdf4b1754efd5055ff189266cf1707/lib/dns/message.c#L1628

- Response packet
- Parse with rawdns module

## NOTES

- Works with all kernel
- Containers create new file via overlayfs => need to attach them too
- `libdns` version compatible is a concern