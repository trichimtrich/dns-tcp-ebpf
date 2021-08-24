package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// LoadDNSProbe returns the embedded CollectionSpec for DNSProbe.
func LoadDNSProbe() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_DNSProbeBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load DNSProbe: %w", err)
	}

	return spec, err
}

// LoadDNSProbeObjects loads DNSProbe and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *DNSProbeObjects
//     *DNSProbePrograms
//     *DNSProbeMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadDNSProbeObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadDNSProbe()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// DNSProbeSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type DNSProbeSpecs struct {
	DNSProbeProgramSpecs
	DNSProbeMapSpecs
}

// DNSProbeSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type DNSProbeProgramSpecs struct {
	UprobeLibcGetaddrinfo    *ebpf.ProgramSpec `ebpf:"uprobe_libc_getaddrinfo"`
	UretprobeLibcGetaddrinfo *ebpf.ProgramSpec `ebpf:"uretprobe_libc_getaddrinfo"`
}

// DNSProbeMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type DNSProbeMapSpecs struct {
	Events *ebpf.MapSpec `ebpf:"events"`
	Start  *ebpf.MapSpec `ebpf:"start"`
}

// DNSProbeObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadDNSProbeObjects or ebpf.CollectionSpec.LoadAndAssign.
type DNSProbeObjects struct {
	DNSProbePrograms
	DNSProbeMaps
}

func (o *DNSProbeObjects) Close() error {
	return _DNSProbeClose(
		&o.DNSProbePrograms,
		&o.DNSProbeMaps,
	)
}

// DNSProbeMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadDNSProbeObjects or ebpf.CollectionSpec.LoadAndAssign.
type DNSProbeMaps struct {
	Events *ebpf.Map `ebpf:"events"`
	Start  *ebpf.Map `ebpf:"start"`
}

func (m *DNSProbeMaps) Close() error {
	return _DNSProbeClose(
		m.Events,
		m.Start,
	)
}

// DNSProbePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadDNSProbeObjects or ebpf.CollectionSpec.LoadAndAssign.
type DNSProbePrograms struct {
	UprobeLibcGetaddrinfo    *ebpf.Program `ebpf:"uprobe_libc_getaddrinfo"`
	UretprobeLibcGetaddrinfo *ebpf.Program `ebpf:"uretprobe_libc_getaddrinfo"`
}

func (p *DNSProbePrograms) Close() error {
	return _DNSProbeClose(
		p.UprobeLibcGetaddrinfo,
		p.UretprobeLibcGetaddrinfo,
	)
}

func _DNSProbeClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

//go:embed main.bpf.o
var _DNSProbeBytes []byte
