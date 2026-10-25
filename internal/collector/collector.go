//go:build linux

// Package collector reads events from the ring buffer shared by every eBPF
// program and decodes them.
package collector

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/sonix03/heideltrace/internal/abi"
	"github.com/sonix03/heideltrace/internal/event"
)

// Collector is a decoding reader of the events map.
type Collector struct {
	rd  *ringbuf.Reader
	rec ringbuf.Record
}

// New opens a reader on the events ring buffer.
func New(events *ebpf.Map) (*Collector, error) {
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	return &Collector{rd: rd}, nil
}

// Next waits up to timeout for one event. It returns (nil, nil) on timeout.
func (c *Collector) Next(timeout time.Duration) (event.Event, error) {
	c.rd.SetDeadline(time.Now().Add(timeout))
	return c.read()
}

// Drain passes every event still in the ring buffer to fn without waiting.
func (c *Collector) Drain(fn func(event.Event)) error {
	c.rd.SetDeadline(time.Now())
	for {
		ev, err := c.read()
		if err != nil || ev == nil {
			return err
		}
		fn(ev)
	}
}

func (c *Collector) read() (event.Event, error) {
	if err := c.rd.ReadInto(&c.rec); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, nil
		}
		return nil, err
	}
	raw, err := abi.DecodeRaw(c.rec.RawSample)
	if err != nil {
		return nil, err
	}
	return event.Decode(&raw), nil
}

// Close releases the reader.
func (c *Collector) Close() error { return c.rd.Close() }
