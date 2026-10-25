// Package config parses the command line of the agent.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/sonix03/heideltrace/internal/abi"
)

// Config holds every option of a run.
type Config struct {
	PIDs     []int         // target PIDs; child processes are followed
	Output   string        // JSON Lines file, "" or "-" for stdout
	Port     int           // API server port for P1, 0 = all ports
	Probes   ProbeSet      // enabled observation points
	Detailed bool          // start in detailed mode
	LibCUDA  string        // libcuda.so path override
	Duration time.Duration // stop after this long, 0 = run until interrupted
	Check    bool          // load the programs into the verifier and exit
	Verbose  bool
}

// ErrHelp is returned when -h was given; usage has been printed.
var ErrHelp = flag.ErrHelp

const usage = `Usage: heideltrace -p PID [options]

Observes an inference server (for example vLLM) and all of its child
processes, and writes the events as JSON Lines. Must run as root.

Options:
  -p, --pid PID        target PID, may be repeated or comma separated
  -o, --output FILE    JSON Lines output file (default: stdout)
      --port N         API server port for P1 (default 8000, 0 = all)
      --enable LIST    enable observation points, e.g. P7,P8
      --disable LIST   disable observation points, e.g. P1,P5
      --detailed       start in detailed mode (every kernel launch is sent)
      --libcuda PATH   libcuda.so location if it is not found automatically
  -d, --duration T     stop after T (seconds, or a Go duration such as 2m)
      --check          only load the eBPF programs into the verifier, then exit
  -v, --verbose        print more diagnostics
  -h, --help           show this help

While running, send SIGUSR1 to switch between summary and detailed mode.
`

// Parse parses args (without the program name). Usage is printed to stderr
// only for -h; other errors are returned for the caller to report.
func Parse(args []string, stderr io.Writer) (*Config, error) {
	cfg := &Config{Port: 8000, Probes: DefaultProbes()}

	fs := flag.NewFlagSet("heideltrace", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	pids := (*pidList)(&cfg.PIDs)
	fs.Var(pids, "p", "")
	fs.Var(pids, "pid", "")
	fs.StringVar(&cfg.Output, "o", "", "")
	fs.StringVar(&cfg.Output, "output", "", "")
	fs.IntVar(&cfg.Port, "port", cfg.Port, "")
	fs.Func("enable", "", func(s string) error { return cfg.Probes.Set(s, true) })
	fs.Func("disable", "", func(s string) error { return cfg.Probes.Set(s, false) })
	fs.BoolVar(&cfg.Detailed, "detailed", false, "")
	fs.StringVar(&cfg.LibCUDA, "libcuda", "", "")
	dur := (*duration)(&cfg.Duration)
	fs.Var(dur, "d", "")
	fs.Var(dur, "duration", "")
	fs.BoolVar(&cfg.Check, "check", false, "")
	fs.BoolVar(&cfg.Verbose, "v", false, "")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stderr, usage)
		}
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if !cfg.Check && len(cfg.PIDs) == 0 {
		return nil, errors.New("at least one target PID is required (-p)")
	}
	if len(cfg.PIDs) > abi.MaxTargets {
		return nil, fmt.Errorf("at most %d target PIDs are supported", abi.MaxTargets)
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d", cfg.Port)
	}
	return cfg, nil
}

// ProbeSet records which observation points are enabled, indexed by probe.
type ProbeSet [abi.P8Ioctl + 1]bool

// DefaultProbes enables P1-P6. P7 and P8 are optional.
func DefaultProbes() ProbeSet {
	var s ProbeSet
	for _, p := range abi.Probes {
		s[p] = p != abi.P7Alloc && p != abi.P8Ioctl
	}
	return s
}

// Enabled reports whether p is on.
func (s ProbeSet) Enabled(p abi.Probe) bool { return p.Valid() && s[p] }

// Set switches every probe in a comma-separated list such as "P7,8".
func (s *ProbeSet) Set(list string, on bool) error {
	for _, tok := range strings.Split(list, ",") {
		tok = strings.TrimSpace(tok)
		n, err := strconv.Atoi(strings.TrimLeft(tok, "Pp"))
		if err != nil || !abi.Probe(n).Valid() {
			return fmt.Errorf("unknown observation point %q", tok)
		}
		s[n] = on
	}
	return nil
}

// List returns the enabled probes in order.
func (s ProbeSet) List() []abi.Probe {
	var out []abi.Probe
	for _, p := range abi.Probes {
		if s[p] {
			out = append(out, p)
		}
	}
	return out
}

// Mode returns the name of the mode for the given detailed flag.
func Mode(detailed bool) string {
	if detailed {
		return "detailed"
	}
	return "summary"
}

type pidList []int

func (l *pidList) String() string { return fmt.Sprint(*l) }

func (l *pidList) Set(s string) error {
	for _, tok := range strings.Split(s, ",") {
		pid, err := strconv.Atoi(strings.TrimSpace(tok))
		if err != nil || pid <= 0 {
			return fmt.Errorf("invalid PID %q", tok)
		}
		*l = append(*l, pid)
	}
	return nil
}

type duration time.Duration

func (d *duration) String() string { return time.Duration(*d).String() }

// Set accepts plain seconds ("120") or a Go duration ("2m").
func (d *duration) Set(s string) error {
	if n, err := strconv.Atoi(s); err == nil {
		*d = duration(time.Duration(n) * time.Second)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	*d = duration(v)
	return nil
}
