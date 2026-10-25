package probes

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// FindLibCUDA returns the libcuda.so mapped by pid, reached through
// /proc/PID/root so that it also works for processes in containers.
// ok is false when the process has not loaded libcuda yet.
func FindLibCUDA(pid int) (path string, ok bool, err error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return "", false, err
	}
	defer f.Close()

	lib := libCUDAFromMaps(f)
	if lib == "" {
		return "", false, nil
	}
	return fmt.Sprintf("/proc/%d/root%s", pid, lib), true, nil
}

// libCUDAFromMaps returns the first libcuda.so path in a /proc/PID/maps
// listing, or "".
func libCUDAFromMaps(r io.Reader) string {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, '/')
		if i < 0 {
			continue
		}
		if path := line[i:]; strings.Contains(path, "/libcuda.so") {
			return path
		}
	}
	return ""
}
