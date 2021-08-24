package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// LoadTCPProbe returns the embedded CollectionSpec for TCPProbe.
func LoadTCPProbe() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TCPProbeBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load TCPProbe: %w", err)
	}

	return spec, err
}

// LoadTCPProbeObjects loads TCPProbe and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *TCPProbeObjects
//     *TCPProbePrograms
//     *TCPProbeMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadTCPProbeObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadTCPProbe()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// TCPProbeSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TCPProbeSpecs struct {
	TCPProbeProgramSpecs
	TCPProbeMapSpecs
}

// TCPProbeSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TCPProbeProgramSpecs struct {
	KprobeTCPSetState *ebpf.ProgramSpec `ebpf:"kprobe__tcp_set_state"`
}

// TCPProbeMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TCPProbeMapSpecs struct {
	Events *ebpf.MapSpec `ebpf:"events"`
	Conns  *ebpf.MapSpec `ebpf:"conns"`
}

// TCPProbeObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadTCPProbeObjects or ebpf.CollectionSpec.LoadAndAssign.
type TCPProbeObjects struct {
	TCPProbePrograms
	TCPProbeMaps
}

func (o *TCPProbeObjects) Close() error {
	return _TCPProbeClose(
		&o.TCPProbePrograms,
		&o.TCPProbeMaps,
	)
}

// TCPProbeMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadTCPProbeObjects or ebpf.CollectionSpec.LoadAndAssign.
type TCPProbeMaps struct {
	Events *ebpf.Map `ebpf:"events"`
	Conns  *ebpf.Map `ebpf:"conns"`
}

func (m *TCPProbeMaps) Close() error {
	return _TCPProbeClose(
		m.Events,
		m.Conns,
	)
}

// TCPProbePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadTCPProbeObjects or ebpf.CollectionSpec.LoadAndAssign.
type TCPProbePrograms struct {
	KprobeTCPSetState *ebpf.Program `ebpf:"kprobe__tcp_set_state"`
}

func (p *TCPProbePrograms) Close() error {
	return _TCPProbeClose(
		p.KprobeTCPSetState,
	)
}

func _TCPProbeClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

//go:embed main.bpf.o
var _TCPProbeBytes []byte
