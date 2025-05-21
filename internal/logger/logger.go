package logger

import (
	"bytes"
	"fmt"
	"log"
	"os"
)

type Logger struct {
	logger   *log.Logger
	Buffer      bytes.Buffer
	File     *os.File
	prefix   string
	filename string
}

func New(filename string, prefix string) *Logger {
	var Buffer bytes.Buffer
	f, err := os.OpenFile(filename+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("log file could not be created: %v", err)
	}
	return &Logger{
		Buffer:      Buffer,
		File:     f,
		prefix:   prefix + ": ",
		filename: filename,
	}
}

func (l *Logger) Log(message string) error {
	if l.logger == nil {
		l.logger = log.New(&l.Buffer, l.prefix, log.Default().Flags())
	}
	l.logger.Print(message)
	_, err := l.File.Write(l.Buffer.Bytes())
	if err != nil {
		return fmt.Errorf("could not print to log file %v: ", err)
	}
	l.Buffer.Reset()
	return nil
}
