package log

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
}

var Log Logger = Logger{logrus.New()}

func init() {

}

type LoggerConfig struct {
	ShowColors bool
	Verbosity  string
}

func ConfigureLogger(config LoggerConfig) {
	SetLevelString(config.Verbosity)

	Log.Formatter = &logrus.TextFormatter{
		ForceColors:     config.ShowColors,
		PadLevelText:    true,
		FullTimestamp:   true,
		TimestampFormat: "01-02|15:04:05.000",
	}
	Log.SetOutput(os.Stdout)
}

func SetLevelString(level string) {
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		Log.Error("Invalid log level: ", level)
		return
	}
	Log.SetLevel(logLevel)
}

// Uses of the global logger will use the following static method.
func Trace(msg string, args ...interface{}) {
	Log.Trace(constructLogMessage(msg, args...))
}

// Individual logging instances will use the following method.
func (l Logger) Trace(msg string, args ...interface{}) {
	l.Logger.Trace(constructLogMessage(msg, args...))
}

func Debug(msg string, args ...interface{}) {
	Log.Debug(constructLogMessage(msg, args...))
}
func (l Logger) Debug(msg string, args ...interface{}) {
	l.Logger.Debug(constructLogMessage(msg, args...))
}

func Info(msg string, args ...interface{}) {
	Log.Info(constructLogMessage(msg, args...))
}
func (l Logger) Info(msg string, args ...interface{}) {
	l.Logger.Info(constructLogMessage(msg, args...))
}

func Warn(msg string, args ...interface{}) {
	Log.Warn(constructLogMessage(msg, args...))
}
func (l Logger) Warn(msg string, args ...interface{}) {
	l.Logger.Warn(constructLogMessage(msg, args...))
}

func Error(msg string, args ...interface{}) {
	Log.Error(constructLogMessage(msg, args...))
}
func (l Logger) Error(msg string, args ...interface{}) {
	l.Logger.Error(constructLogMessage(msg, args...))
}

func Fatal(msg string, args ...interface{}) {
	Log.Fatal(constructLogMessage(msg, args...))
}
func (l Logger) Fatal(msg string, args ...interface{}) {
	l.Logger.Fatal(constructLogMessage(msg, args...))
}

func Panic(msg string, args ...interface{}) {
	Log.Panic(constructLogMessage(msg, args...))
}
func (l Logger) Panic(msg string, args ...interface{}) {
	l.Logger.Panic(constructLogMessage(msg, args...))
}

func Lazy(fn func() string, logLevel string) {
	level, err := logrus.ParseLevel(logLevel)
	if err == nil && Log.IsLevelEnabled(level) {
		callCorrectLevel(level, fn())
	}
}

func reportLineNumber(skiplevel int) string {
	if Logger.GetLevel(Log) < logrus.DebugLevel {
		return ""
	}
	_, file, line, ok := runtime.Caller(skiplevel + 1)
	fileAndDir := filepath.Join(filepath.Base(filepath.Dir(file)), filepath.Base(file))
	if !ok || fileAndDir == "log/logger.go" {
		return ""
	}
	return fmt.Sprintf("%s:%d", fileAndDir, line)
}

func callCorrectLevel(level logrus.Level, msg string, args ...interface{}) {
	switch level {
	case logrus.TraceLevel:
		Trace(msg, args...)
	case logrus.DebugLevel:
		Debug(msg, args...)
	case logrus.InfoLevel:
		Info(msg, args...)
	case logrus.WarnLevel:
		Warn(msg, args...)
	case logrus.ErrorLevel:
		Error(msg, args...)
	case logrus.FatalLevel:
		Fatal(msg, args...)
	case logrus.PanicLevel:
		Panic(msg, args...)
	default:
		Error("Unknown log level: %v", level)
	}
}

func constructLogMessage(msg string, fields ...interface{}) string {
	var pairs []string

	lineInfo := reportLineNumber(2)

	if len(fields) != 1 {
		// Sometimes we want to log a single string,
		if len(fields)%2 != 0 {
			fields = append(fields, "MISSING VALUE")
		}

		for i := 0; i < len(fields); i += 2 {
			key := fields[i]
			value := fields[i+1]
			pairs = append(pairs, fmt.Sprintf("%v=%v", key, value))
		}
	}

	if lineInfo != "" {
		return fmt.Sprintf("%-40s %-40s %s", lineInfo, msg, strings.Join(pairs, " "))
	} else {
		return fmt.Sprintf("%-40s %s", msg, strings.Join(pairs, " "))
	}
}

func (l Logger) GetLevel() logrus.Level {
	return l.Logger.GetLevel()
}
