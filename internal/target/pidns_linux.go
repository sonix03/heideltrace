package target

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/sonix03/heideltrace/internal/abi"
)

// initPIDNSInode is PROC_PID_INIT_INO, the inode of the initial PID namespace.
const initPIDNSInode = 0xEFFFFFFC

// PIDNamespaceInode returns the inode of the agent's PID namespace, or 0
// when the agent runs in the initial (host) namespace. eBPF programs always
// see kernel PIDs, so a non-zero value means PIDs must be translated.
func PIDNamespaceInode() (uint64, error) {
	fi, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		return 0, fmt.Errorf("read PID namespace of the agent: %w", err)
	}
	ino := fi.Sys().(*syscall.Stat_t).Ino
	if ino == initPIDNSInode {
		return 0, nil
	}
	return ino, nil
}

// kernelPID translates a PID from the agent's namespace into the kernel PID
// by running the xlate_pid task iterator (bpf/proc.bpf.c).
func (t *Tracker) kernelPID(pid int) (uint32, error) {
	if t.xlate == nil {
		return uint32(pid), nil
	}
	req := abi.XlateReq{Want: uint32(pid)}
	if err := t.objs.Xlate.Put(uint32(0), req); err != nil {
		return 0, err
	}
	rc, err := t.xlate.Open()
	if err != nil {
		return 0, err
	}
	_, err = io.Copy(io.Discard, rc)
	rc.Close()
	if err != nil {
		return 0, err
	}
	if err := t.objs.Xlate.Lookup(uint32(0), &req); err != nil {
		return 0, err
	}
	if req.Got == 0 {
		return 0, fmt.Errorf("PID %d has no kernel PID", pid)
	}
	return req.Got, nil
}
