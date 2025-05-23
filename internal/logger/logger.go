package logger

import (
	"fmt"
	"log"
	"os"
	"sync"
)

type Logger struct {
	Logger   *log.Logger
	Prefix   string
	File     *os.File
	mu sync.Mutex
}

func New(filename, prefix string) *Logger {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("log file could not be created: %v", err)
	}
	prefix =  prefix + ": "
	logger := log.New(f, prefix, log.Default().Flags())
	return &Logger{
		Logger: logger,
		Prefix:   prefix,
		File: f,
		mu: sync.Mutex{},
	}
}


func (l *Logger) Log(message string) error {
	l.mu.Lock()
	l.Logger.Print(message)
	l.mu.Unlock()
	return nil
}

func (l *Logger) Close(){
	l.File.Close()
}
