package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	dns "github.com/cirocosta/rawdns/lib"
	"golang.org/x/sys/unix"
)

func inet_ntop(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
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
	objs := DNSProbeObjects{}
	if err := LoadDNSProbeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("udp_recvmsg", objs.KprobeUDPRecvmsg)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	krp, err := link.Kretprobe("udp_recvmsg", objs.KretprobeUDPRecvmsg)
	if err != nil {
		log.Fatalf("opening kretprobe: %s", err)
	}
	defer krp.Close()

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	rd, err := perf.NewReader(objs.DNSEvents, os.Getpagesize())
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

		data := record.RawSample
		var pid uint32
		err = binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &pid)
		if err != nil {
			fmt.Printf("failed to decode received data: %s\n", err)
			continue
		}
		comm := string(data[4:20])
		packet := data[20:]
		fmt.Printf("\n>>> %d - %s - %d\n", pid, comm, len(packet))
		var m dns.Message
		err = dns.UnmarshalMessage(packet, &m)
		if err != nil {
			fmt.Printf("failed to decode packet: %s\n", err)
			continue
		}
		for i := 0; i < len(m.Questions); i++ {
			q := m.Questions[i]
			fmt.Println("===ASK===", q.QNAME, q.QCLASS, q.QTYPE)
		}

		for i := 0; i < len(m.Answers); i++ {
			r := m.Answers[i]
			if r.TYPE == dns.QTypeA {
				fmt.Println("[A]", inet_ntop(r.RDATA))
			} else if r.TYPE == dns.QTypeCNAME {
				// fmt.Println("[CNAME]", string(r.RDATA))
				fmt.Println("[CNAME]")
				fmt.Println(hex.Dump(r.RDATA))
			} else {
				fmt.Println("===ANS===", r.CLASS, r.NAME, r.TYPE, r.RDATA)
			}
		}

	}
}
