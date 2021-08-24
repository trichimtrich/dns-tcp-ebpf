package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

const (
	MAX_HOST_LEN = 250
	MAX_RESULT   = 15
)

type Event struct {
	Pid   uint32
	Host  [MAX_HOST_LEN]byte
	Addrs [MAX_RESULT]uint32
	Comm  [16]byte
}

const symbol = "getaddrinfo"

func inet_ntop(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func getLibc() string {
	paths := []string{"/lib64/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func main() {
	binPath := getLibc()
	if binPath == "" {
		log.Fatal("libc not found")
	}

	// Increase rlimit so the eBPF map and program can be loaded.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := DNSProbeObjects{}
	if err := LoadDNSProbeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Open an ELF binary and read its symbols.
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	// Open Uprobe and attach
	up, err := ex.Uprobe(symbol, objs.UprobeLibcGetaddrinfo)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up.Close()

	// Open Uretprobe and attach
	urp, err := ex.Uretprobe(symbol, objs.UretprobeLibcGetaddrinfo)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
	}
	defer urp.Close()

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	log.Printf("Listening for events..")

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into an Event structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}
		fmt.Printf(">>> %d - %s - %s\n", event.Pid, string(event.Comm[:]), string(event.Host[:]))
		count := 0
		for i := 0; i < MAX_RESULT; i++ {
			if event.Addrs[i] == 0 {
				continue
			}
			fmt.Printf("... %s\n", inet_ntop(event.Addrs[i]))
			count += 1
		}
		if count == 0 {
			fmt.Println("... NO RESULT")
		}
	}
}
