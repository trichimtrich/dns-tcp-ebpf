package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"

	dns "github.com/cirocosta/rawdns/lib"
	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

func inet_ntop(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func main() {
	bs, _ := ioutil.ReadFile("03.udp_recvmsg.bpf.c")
	source := string(bs)

	m := bpf.NewModule(source, []string{})
	defer m.Close()

	recvmsgKprobe, err := m.LoadKprobe("trace_udp_recvmsg")
	if err != nil {
		panic(err)
	}

	recvmsgKretprobe, err := m.LoadKprobe("trace_udp_ret_recvmsg")
	if err != nil {
		panic(err)
	}

	err = m.AttachKprobe("udp_recvmsg", recvmsgKprobe, -1)
	if err != nil {
		panic(err)
	}

	err = m.AttachKretprobe("udp_recvmsg", recvmsgKretprobe, -1)
	if err != nil {
		panic(err)
	}

	table := bpf.NewTable(m.TableId("dns_events"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		for {
			data := <-channel
			var pid uint32
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &pid)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			comm := string(data[4:20])
			packet := data[20:]
			fmt.Println(hex.Dump(packet))
			continue
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
					fmt.Println("[CNAME]", string(r.RDATA))
				} else {
					fmt.Println("===ANS===", r.CLASS, r.NAME, r.TYPE, r.RDATA)
				}
			}

		}
	}()

	fmt.Println("listening...")

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
