package target

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Small helpers around /proc. PIDs here are as seen by the agent.

func exists(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

func readComm(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}

func readPPID(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return -1
	}
	return parsePPID(string(b))
}

// parsePPID extracts the parent PID from a /proc/PID/stat line. The process
// name may contain spaces and parentheses, so parsing starts after the last
// ')'.
func parsePPID(stat string) int {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return -1
	}
	fields := strings.Fields(stat[i+1:])
	if len(fields) < 2 {
		return -1
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return -1
	}
	return ppid
}

// listPIDs returns every process ID in /proc.
func listPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}
