// Package logger provides a thin wrapper around the standard library logger
// that is safe for concurrent use. It is primarily used by scanning
// components to record events and errors to disk.
package logger

import (
	"log"
	"os"
	"sync"
)

// Logger wraps the standard library logger and writes log entries to a file.
// A mutex is used to ensure writes from multiple goroutines do not interleave.
type Logger struct {
	// Logger is the underlying logger used to format entries.
	Logger *log.Logger
	// Prefix is prepended to every log entry.
	Prefix string
	// File is the handle to the log file on disk.
	File *os.File
	mu   sync.Mutex
}

// New creates a Logger that writes to the provided file. The prefix string is
// added to each log entry to help identify the source of the message.
func New(filename, prefix string) *Logger {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("log file could not be created: %v\n", err)
	}
	prefix = prefix + ": "
	logger := log.New(f, prefix, log.Default().Flags())
	return &Logger{
		Logger: logger,
		Prefix: prefix,
		File:   f,
		mu:     sync.Mutex{},
	}
}

// Log writes a single log entry to the underlying file. It is safe for
// concurrent use by multiple goroutines.
func (l *Logger) Log(message string) error {
	l.mu.Lock()
	l.Logger.Print(message)
	l.mu.Unlock()
	return nil
}

// Close closes the underlying log file. After calling Close the Logger should
// no longer be used.
func (l *Logger) Close() {
	l.File.Close()
}
