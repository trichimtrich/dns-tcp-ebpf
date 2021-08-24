package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

const (
	MAX_HOST_LEN = 250
	MAX_RESULT   = 1
)

type Event struct {
	Pid   uint32
	Comm  [16]byte
	Host  [MAX_HOST_LEN]byte
	Addrs [MAX_RESULT]uint32
}

func inet_ntop(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func main() {
	bs, _ := ioutil.ReadFile("02.getaddrinfo-multi-result.bpf.c")
	source := string(bs)

	m := bpf.NewModule(source, []string{})
	defer m.Close()

	entryUprobe, err := m.LoadUprobe("do_entry")
	if err != nil {
		panic(err)
	}

	retUprobe, err := m.LoadUprobe("do_return")
	if err != nil {
		panic(err)
	}

	err = m.AttachUprobe("c", "getaddrinfo", entryUprobe, -1)
	if err != nil {
		panic(err)
	}

	err = m.AttachUretprobe("c", "getaddrinfo", retUprobe, -1)
	if err != nil {
		panic(err)
	}

	table := bpf.NewTable(m.TableId("events"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event Event
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			fmt.Printf(">>> %d - %s - %s\n", event.Pid, string(event.Comm[:]), string(event.Host[:]))
			count := 0
			for i := 0; i < MAX_RESULT && event.Addrs[i] != 0; i++ {
				fmt.Printf("... %s\n", inet_ntop(event.Addrs[i]))
				count += 1
			}
			if count == 0 {
				fmt.Println("... NO RESULT")
			}
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
