//go:build linux

// Package agent wires the components together and runs the main loop:
//
//	loader -> probes -> collector -> target tracker -> output
//
// The correlator, analyzer and report exporter from the proposal will plug
// in between the collector and the output.
package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/sonix03/heideltrace/internal/abi"
	"github.com/sonix03/heideltrace/internal/collector"
	"github.com/sonix03/heideltrace/internal/config"
	"github.com/sonix03/heideltrace/internal/event"
	"github.com/sonix03/heideltrace/internal/loader"
	"github.com/sonix03/heideltrace/internal/output"
	"github.com/sonix03/heideltrace/internal/probes"
	"github.com/sonix03/heideltrace/internal/target"
)

// Version is written into the meta record.
const Version = "0.2.0"

const (
	pollInterval   = 200 * time.Millisecond
	scanInterval   = 500 * time.Millisecond // look for dead targets and libcuda.so
	reportInterval = 10 * time.Second       // flush output and print counters
)

// Logger is satisfied by *log.Logger.
type Logger = target.Logger

// Run observes the targets in cfg until ctx is cancelled.
func Run(ctx context.Context, cfg *config.Config, log Logger) error {
	if os.Geteuid() != 0 {
		return errors.New("heideltrace must run as root (sudo)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}
	nsIno, err := target.PIDNamespaceInode()
	if err != nil {
		return err
	}

	objs, err := loader.Load(loader.Options{
		Probes:     cfg.Probes,
		Port:       uint16(cfg.Port),
		PIDNSInode: nsIno,
		Warn:       log.Printf,
	})
	if err != nil {
		if vlog, ok := loader.VerifierLog(err); ok && cfg.Verbose {
			log.Printf("verifier log:\n%s", vlog)
		}
		return fmt.Errorf("the kernel rejected the eBPF programs: %w", err)
	}
	defer objs.Close()
	if cfg.Check {
		log.Printf("all eBPF programs passed the verifier, no probes were attached")
		return nil
	}

	out, err := output.Open(cfg.Output)
	if err != nil {
		return err
	}
	defer out.Close()

	if err := objs.WriteControl(cfg.Probes, cfg.Detailed); err != nil {
		return err
	}

	tracker, err := target.New(objs, target.Options{
		Probes:     cfg.Probes,
		LibCUDA:    cfg.LibCUDA,
		PIDNSInode: nsIno,
		Verbose:    cfg.Verbose,
		Log:        log,
	})
	if err != nil {
		return err
	}
	defer tracker.Close()
	for _, pid := range cfg.PIDs {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
			return fmt.Errorf("PID %d not found", pid)
		}
		if _, err := tracker.Add(pid, 0); err != nil {
			return err
		}
	}

	kernelLinks, err := probes.AttachKernel(objs)
	if err != nil {
		return err
	}
	defer kernelLinks.Close()
	// Look for existing children only after P6 is attached so none is missed.
	tracker.AddDescendants()

	col, err := collector.New(objs.Events)
	if err != nil {
		return err
	}
	defer col.Close()

	if err := out.Write(newMeta(cfg)); err != nil {
		return err
	}
	return loop(ctx, cfg, log, objs, tracker, col, out)
}

func loop(ctx context.Context, cfg *config.Config, log Logger, objs *loader.Objects,
	tracker *target.Tracker, col *collector.Collector, out *output.Writer) error {
	toggle := make(chan os.Signal, 1)
	signal.Notify(toggle, syscall.SIGUSR1)
	defer signal.Stop(toggle)

	var n uint64
	handle := func(ev event.Event) {
		tracker.Observe(ev)
		if err := out.Write(ev); err != nil {
			log.Printf("write event: %v", err)
		}
		n++
	}
	stats := func(prefix string) {
		dropped, _ := objs.DroppedEvents()
		log.Printf("%sevents=%d dropped=%d", prefix, n, dropped)
	}

	detailed := cfg.Detailed
	lastScan, lastReport := time.Now(), time.Now()
	log.Printf("running, press Ctrl-C to stop")

	for ctx.Err() == nil {
		ev, err := col.Next(pollInterval)
		if err != nil {
			return fmt.Errorf("read ring buffer: %w", err)
		}
		if ev != nil {
			handle(ev)
		}

		select {
		case <-toggle:
			detailed = !detailed
			if err := objs.SetControl(abi.ControlMode, detailed); err != nil {
				log.Printf("switch mode: %v", err)
			} else {
				log.Printf("mode %s", config.Mode(detailed))
			}
		default:
		}

		now := time.Now()
		if now.Sub(lastScan) >= scanInterval {
			tracker.Scan()
			lastScan = now
		}
		if now.Sub(lastReport) >= reportInterval {
			out.Flush()
			stats("")
			lastReport = now
		}
	}

	// Write what is still in the ring buffer.
	if err := col.Drain(handle); err != nil {
		log.Printf("drain ring buffer: %v", err)
	}
	stats("done: ")
	return nil
}

func newMeta(cfg *config.Config) *event.Meta {
	// Event timestamps are CLOCK_MONOTONIC; this offset converts them to
	// wall time so they can be matched with the load generator's records.
	var mono, real unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono)
	_ = unix.ClockGettime(unix.CLOCK_REALTIME, &real)

	m := &event.Meta{
		Type:         event.TypeMeta,
		Version:      Version,
		MonoToRealNs: real.Nano() - mono.Nano(),
		Port:         cfg.Port,
		Mode:         config.Mode(cfg.Detailed),
		Probes:       []string{},
	}
	for _, p := range cfg.Probes.List() {
		m.Probes = append(m.Probes, p.String())
	}
	return m
}
