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
	UprobeBind9DnsMessageParse *ebpf.ProgramSpec `ebpf:"uprobe__dns_message_parse"`
}

// DNSProbeMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type DNSProbeMapSpecs struct {
	DNSEvents *ebpf.MapSpec `ebpf:"dns_events"`
	DNSData   *ebpf.MapSpec `ebpf:"dns_data"`
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
	DNSEvents *ebpf.Map `ebpf:"dns_events"`
	DNSData   *ebpf.Map `ebpf:"dns_data"`
}

func (m *DNSProbeMaps) Close() error {
	return _DNSProbeClose(
		m.DNSData,
		m.DNSEvents,
	)
}

// DNSProbePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadDNSProbeObjects or ebpf.CollectionSpec.LoadAndAssign.
type DNSProbePrograms struct {
	UprobeBind9DnsMessageParse *ebpf.Program `ebpf:"uprobe__dns_message_parse"`
}

func (p *DNSProbePrograms) Close() error {
	return _DNSProbeClose(
		p.UprobeBind9DnsMessageParse,
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
