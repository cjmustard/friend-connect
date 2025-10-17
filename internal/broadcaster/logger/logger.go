package logger

import (
	"fmt"
	"log"
	"os"
	"sync"
)

type Level int

const (
	LevelInfo Level = iota
	LevelDebug
	LevelTrace
)

type Logger struct {
	std    *log.Logger
	level  Level
	prefix string
	mu     sync.RWMutex
}

func New() *Logger {
	return &Logger{std: log.New(os.Stdout, "", log.LstdFlags)}
}

func (l *Logger) Prefixed(prefix string) *Logger {
	copy := *l
	if prefix != "" {
		copy.prefix = joinPrefix(l.prefix, prefix)
	}
	return &copy
}

func joinPrefix(existing, new string) string {
	if existing == "" {
		return fmt.Sprintf("[%s]", new)
	}
	return fmt.Sprintf("%s[%s]", existing, new)
}

func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	l.level = level
	l.mu.Unlock()
}

func (l *Logger) Info(format string, args ...any) {
	l.output(LevelInfo, "INFO", format, args...)
}

func (l *Logger) Warn(format string, args ...any) {
	l.output(LevelInfo, "WARN", format, args...)
}

func (l *Logger) Error(format string, args ...any) {
	l.output(LevelInfo, "ERROR", format, args...)
}

func (l *Logger) Warnf(format string, args ...any) {
	l.Warn(format, args...)
}

func (l *Logger) Infof(format string, args ...any) {
	l.Info(format, args...)
}

func (l *Logger) Debugf(format string, args ...any) {
	l.Debug(format, args...)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.Error(format, args...)
}

func (l *Logger) ErrorErr(err error, message string, args ...any) {
	args = append(args, err)
	l.output(LevelInfo, "ERROR", message+": %v", args...)
}

func (l *Logger) Debug(format string, args ...any) {
	l.output(LevelDebug, "DEBUG", format, args...)
}

func (l *Logger) Trace(format string, args ...any) {
	l.output(LevelTrace, "TRACE", format, args...)
}

func (l *Logger) output(level Level, lvl string, format string, args ...any) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.level < level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if l.prefix != "" {
		msg = fmt.Sprintf("%s %s", l.prefix, msg)
	}
	l.std.Printf("%s %s", lvl, msg)
}
