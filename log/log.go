package log

import (
	"fmt"
	"os"
)

// DebugEnabled controls whether debug logging is enabled
var DebugEnabled bool

// Debug prints debug messages to stdout when logging is enabled
func Debug(format string, args ...interface{}) {
	if DebugEnabled {
		fmt.Fprintf(os.Stdout, format+"\n", args...)
	}
}

// Info prints info messages to stdout
func Info(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

// Error prints error messages to stderr
func Error(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// Fatal prints error messages to stderr and exits with code 1
func Fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
