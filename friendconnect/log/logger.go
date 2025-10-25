package log

import (
	"io"
	"log"
	"os"
	"sync"
)

// LoggingOptions controls what types of messages are logged by the service.
type LoggingOptions struct {
	LogConnections bool
	LogTransfers   bool
	LogFriends     bool
	LogSessions    bool
	LogNetherNet   bool
	LogErrors      bool
	Logger         *log.Logger // Optional custom logger instance
}

// ConditionalLogger wraps a standard logger with conditional logging based on categories.
type ConditionalLogger struct {
	*log.Logger
	Opts LoggingOptions
}

var (
	globalLoggingInitialized bool
	initMutex                sync.Mutex
)

// NewConditionalLogger creates a new conditional logger with the specified options.
func NewConditionalLogger(w io.Writer, prefix string, flag int, opts LoggingOptions) *ConditionalLogger {
	initMutex.Lock()
	if !globalLoggingInitialized {
		log.SetOutput(io.Discard)
		os.Stderr, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		globalLoggingInitialized = true
	}
	initMutex.Unlock()

	logger := log.New(os.Stdout, "friendconnect: ", 0)

	return &ConditionalLogger{
		Logger: logger,
		Opts:   opts,
	}
}

// LogConnection logs a connection-related message if LogConnections is enabled.
func (l *ConditionalLogger) LogConnection(format string, v ...interface{}) {
	if l.Opts.LogConnections {
		l.Printf(format, v...)
	}
}

// LogTransfer logs a transfer-related message if LogTransfers is enabled.
func (l *ConditionalLogger) LogTransfer(format string, v ...interface{}) {
	if l.Opts.LogTransfers {
		l.Printf(format, v...)
	}
}

// LogFriend logs a friend-related message if LogFriends is enabled.
func (l *ConditionalLogger) LogFriend(format string, v ...interface{}) {
	if l.Opts.LogFriends {
		l.Printf(format, v...)
	}
}

// LogSession logs a session-related message if LogSessions is enabled.
func (l *ConditionalLogger) LogSession(format string, v ...interface{}) {
	if l.Opts.LogSessions {
		l.Printf(format, v...)
	}
}

// LogNetherNet logs a NetherNet-related message if LogNetherNet is enabled.
func (l *ConditionalLogger) LogNetherNet(format string, v ...interface{}) {
	if l.Opts.LogNetherNet {
		l.Printf(format, v...)
	}
}

// LogError logs an error message if LogErrors is enabled.
func (l *ConditionalLogger) LogError(format string, v ...interface{}) {
	if l.Opts.LogErrors {
		l.Printf(format, v...)
	}
}
