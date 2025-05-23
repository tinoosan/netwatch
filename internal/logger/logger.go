package logger

import (
	"bytes"
	"fmt"
	"log"
	"os"
)

type Logger struct {
	Logger   *log.Logger
	Buffer   *bytes.Buffer
	Prefix   string
	Filename string
}

func New(prefix string) *Logger {
  var	buffer bytes.Buffer
	prefix =  prefix + ": "
	logger := log.New(&buffer, prefix, log.Default().Flags())
	return &Logger{
		Logger: logger,
		Buffer:   &buffer,
		Prefix:   prefix,
	}
}


func (l *Logger) Log(filename, message string) error {
	l.Logger.Print(message)
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("log file could not be created: %v", err)
	}

	defer func() error {
		err := f.Close()
		if err != nil {
			return fmt.Errorf("could not close file %v: %w", f.Name(), err)
		}
		return nil
	}()

	_, err = f.Write(l.Buffer.Bytes())
	if err != nil {
		return fmt.Errorf("could not print to log file %v: %w",f.Name(), err)
	}
	l.Buffer.Reset()
	return nil
}
