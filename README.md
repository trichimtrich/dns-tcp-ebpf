Learning eBPF and some kernel tracing, probe DNS + TCP connection with portable bpf prog.

## DevEnv

Ubuntu 20.04

- Install go
- Install `make`, `clang`, `llvm`
- Install libbpf (for helpers header)

```bash
wget https://golang.org/dl/go1.17.linux-amd64.tar.gz
tar xvf go1.17.linux-amd64.tar.gz
sudo mv go /usr/lib/go-1.17
sudo ln -s /usr/lib/go-1.17/bin/go /usr/bin/go
echo 'export GOPATH=~/go' >> ~/.profile
echo 'export PATH=$GOPATH/bin:$PATH' >> ~/.profile

sudo apt update
sudo apt install -y make clang llvm

sudo apt install -y libelf-dev
git clone https://github.com/libbpf/libbpf
cd libbpf/src
make -j
sudo make install
```

- Optional: install `bcc` / `gobpf` for playing with python/go binding
    + Read their INSTRUCTION
    + Critical: consider clang+llvm 7 , ver 10 breaks something IDK

- Optional: download kernel header if needed
    + Check `linuxhdrs` in Makefile
    + Critical: LINUXHEADERS order is important !!

- Compile each projects with `make`

- Run with root

---

## Notes, Refs

- `include/types.h` from `tools/include/linux/types.h`
```
https://blogs.oracle.com/linux/post/bpf-in-depth-building-bpf-programs
```

- https://zwischenzugs.com/2018/06/08/anatomy-of-a-linux-dns-lookup-part-i/

- https://github.com/isc-projects/bind9/blob/main/lib/dns/message.c

- `uprobe` needs tracking current state of binaries => inotify

- DONT FORGET the struct alignment needs to be consistent between C and GO
```
sizeof(event_t)
unsafe.Sizeof(Event)
```

https://stackoverflow.com/questions/53324158/golang-ebpf-and-functions-duration

https://dave.cheney.net/2015/10/09/padding-is-hard

https://go101.org/article/memory-layout.html

https://medium.com/@liamkelly17/working-with-packed-c-structs-in-cgo-224a0a3b708b

- `uprobe` will have problem with container, because of the new binaries (new inode) overwritten in `overlayfs`, this can be solved on userspace

- `llvm-objdump` to verify the asm. `__builtin_memcpy` converts to a series of `load` and `store` opcode, compare to the call to `bpf_probe_read` helper, might be better in performance but cost extra space

