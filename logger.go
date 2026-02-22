package openauth

import "github.com/go-logr/logr"

func resolveLogger(logger logr.Logger) logr.Logger {
	if logger.GetSink() == nil {
		return logr.Discard()
	}
	return logger
}
