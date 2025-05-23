package logger_test

import (
	"os"
	"testing"

	"github.com/tinoosan/netwatch/internal/logger"
)

func TestLog(t *testing.T) {
	t.Run("test", func(t *testing.T) {
    
		fileName := "logging_test.log"
		fileDir := "./"+fileName

		logger := logger.New(fileName, "test")
		err := logger.Log(fileName, "This is a test message")
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
		dat, err := os.ReadFile(fileDir)
		if err != nil {
			t.Errorf("error reading file: %v", err)
		}

		if len(dat) == 0 {
			t.Error("no contents in file")
		}

		if err != nil {
			t.Errorf("want nil got %s", err)
		}

		err = os.Remove(fileDir)
		if err != nil {
			t.Error("could not remove file")
		}
	})
}
