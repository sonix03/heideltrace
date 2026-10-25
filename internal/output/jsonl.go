// Package output writes events as JSON Lines, one object per line.
package output

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
)

// Writer buffers JSON Lines output. Call Flush periodically and Close at
// the end.
type Writer struct {
	buf  *bufio.Writer
	enc  *json.Encoder
	file *os.File // nil when writing to stdout or a caller's io.Writer
}

// New writes to w.
func New(w io.Writer) *Writer {
	buf := bufio.NewWriterSize(w, 1<<16)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	return &Writer{buf: buf, enc: enc}
}

// Open writes to path, or to stdout when path is "" or "-".
func Open(path string) (*Writer, error) {
	if path == "" || path == "-" {
		return New(os.Stdout), nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := New(f)
	w.file = f
	return w, nil
}

// Write appends v as one line.
func (w *Writer) Write(v any) error { return w.enc.Encode(v) }

// Flush writes buffered lines to the underlying file.
func (w *Writer) Flush() error { return w.buf.Flush() }

// Close flushes and closes the file.
func (w *Writer) Close() error {
	err := w.Flush()
	if w.file != nil {
		if cerr := w.file.Close(); err == nil {
			err = cerr
		}
	}
	return err
}
