package logger_test

import (
	"os"
	"testing"

	"github.com/tinoosan/netwatch/internal/logger"
)

func TestLog(t *testing.T) {
	t.Run("test", func(t *testing.T) {

		file := "./logging_test.log"

		logger := logger.New("logging_test", "test")
		err := logger.Log("This is a test message")
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
		dat, err := os.ReadFile(file)

		defer logger.File.Close()
		if len(dat) == 0 {
			t.Error("no contents in file")
		}

		if len(logger.Buffer.Bytes()) != 0 {
			t.Errorf("buffer not cleared. expected 0 got %d", len(logger.Buffer.Bytes()))
		}

		if err != nil {
			t.Errorf("want nil got %s", err)
		}

		err = os.Remove(file)
		if err != nil {
			t.Error("could not remove file")
		}
	})
}
