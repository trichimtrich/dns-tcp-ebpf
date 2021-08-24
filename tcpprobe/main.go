package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

type Event struct {
	StartNS uint64
	EndNS   uint64
	PID     uint32
	LAddr   uint32
	LPort   uint16
	RAddr   uint32
	RPort   uint16
	Flags   uint8
	Rx      uint64
	Tx      uint64
	Comm    [16]byte
}

func deserialize(b []byte, e *Event) (err error) {
	buf := bytes.NewBuffer(b)

	if err = binary.Read(buf, binary.LittleEndian, &e.StartNS); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.EndNS); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.LAddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.LPort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.RAddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.RPort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Flags); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Rx); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Tx); err != nil {
		return
	}

	err = binary.Read(buf, binary.LittleEndian, &e.Comm)
	return
}

func inet_ntop(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func main() {
	// Increase rlimit so the eBPF map and program can be loaded.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := TCPProbeObjects{}
	if err := LoadTCPProbeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("tcp_set_state", objs.KprobeTCPSetState)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

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

	var e Event
	for {
		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
		}
		t_end := time.Now()

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		if err := deserialize(record.RawSample, &e); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		lAddr := inet_ntop(e.LAddr)
		rAddr := inet_ntop(e.RAddr)
		outStr := "OUT"
		if e.Flags&1 == 0 {
			outStr = "IN"
		}

		sucStr := "True"
		if e.Flags&0x10 == 0 {
			sucStr = "False"
		}

		t_start := t_end.Add(-time.Nanosecond * (time.Duration(e.EndNS - e.StartNS)))

		fmt.Printf("%-7d %-16s %-3s %-5s %-15s %-5d %-15s %-5d %-20d %-20d %s %s\n", e.PID, e.Comm, outStr, sucStr, lAddr, e.LPort, rAddr, e.RPort, e.Rx, e.Tx, t_start.String(), t_end.String())

	}
}
