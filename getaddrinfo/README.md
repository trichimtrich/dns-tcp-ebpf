Capture DNS via user hook at `libc` binary and `getaddrinfo` function

- Uprobe => save the pointer to responses
- Uretprobe => extract the data from responses

# Notes

- Works with all kernel
- Need keeping track other libc binaries in mount namespace (container)