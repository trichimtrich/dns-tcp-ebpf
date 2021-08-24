Capture TCP connection via `kprobe` + `tcp_set_state`
+ Timestamp
+ In/out bound connection
+ Attempt / successful connection
+ Local host port
+ Remote host port
+ Tx / Rx bytes
+ PID / Process name

---

Use `tracepoint` maybe better compatible with future kernel than using `kprobe`