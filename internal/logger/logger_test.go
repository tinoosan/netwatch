package logger_test

import (
	"testing"

	"github.com/tinoosan/netwatch/internal/logger"
)

func TestLog(t *testing.T) {
	t.Run("test", func(t *testing.T) {
		logger := logger.New("logging_test", "test")
		err := logger.Log("This is a test message")
		if err != nil {
			t.Errorf("want nil got %s", err)
		}

	})
}
