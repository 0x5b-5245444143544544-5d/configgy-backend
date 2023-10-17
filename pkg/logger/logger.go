package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger logger instance
type logger struct {
	slogger *zap.SugaredLogger
}

type Logger interface {
	Debugf(format string, args ...interface{})
	Debugw(msg string, args ...interface{})
	Debug(args ...interface{})
	Infof(format string, args ...interface{})
	Infow(msg string, args ...interface{})
	Info(args ...interface{})
	Warnf(format string, args ...interface{})
	Warnw(msg string, args ...interface{})
	Warn(args ...interface{})
	Errorf(format string, args ...interface{})
	Errorw(msg string, args ...interface{})
	Error(args ...interface{})
	Fatalf(format string, args ...interface{})
	Fatalw(msg string, args ...interface{})
	Fatal(args ...interface{})
	Printf(format string, args ...interface{})
	Print(args ...interface{})
	Println(args ...interface{})
}

var singletonLogger *logger

func init() {
	var config zap.Config
	if os.Getenv("ENVIRONMENT") == "local" {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		config = zap.NewProductionConfig()
	}
	config.DisableCaller = true
	l, err := config.Build()
	if err != nil {
		panic(err)
	}
	defer func() {
		// flushes buffer, if any
		// this fails, but it should be safe to ignore according
		// to https://github.com/uber-go/zap/issues/328#issuecomment-284337436
		_ = l.Sync()
	}()
	singletonLogger = &logger{
		slogger: l.Sugar(),
	}
}

// Debugf displays a message with formatting, level DEBUG
func (l *logger) Debugf(format string, args ...interface{}) {
	l.slogger.Debugf(format, args...)
}

// Debugw displays a message with typed context args, level DEBUG
func (l *logger) Debugw(msg string, args ...interface{}) {
	l.slogger.Debugw(msg, args...)
}

// Debug displays a message, level DEBUG
func (l *logger) Debug(args ...interface{}) {
	l.slogger.Debug(args...)
}

// Infof displays a message with formatting, level INFO
func (l *logger) Infof(format string, args ...interface{}) {
	l.slogger.Infof(format, args...)
}

// Infow displays a message with typed context args, level INFO
func (l *logger) Infow(msg string, args ...interface{}) {
	l.slogger.Infow(msg, args...)
}

// Info displays a message, level INFO
func (l *logger) Info(args ...interface{}) {
	l.slogger.Info(args...)
}

// Warnf displays a message with formatting, level WARN
func (l *logger) Warnf(format string, args ...interface{}) {
	l.slogger.Warnf(format, args...)
}

// Warnw displays a message with typed context args, level WARN
func (l *logger) Warnw(msg string, args ...interface{}) {
	l.slogger.Warnw(msg, args...)
}

// Warn displays a message, level WARN
func (l *logger) Warn(args ...interface{}) {
	l.slogger.Warn(args...)
}

// Errorf displays a message with formatting, level ERROR
func (l *logger) Errorf(format string, args ...interface{}) {
	l.slogger.Errorf(format, args...)
}

// Errorw displays a message with typed context args, level ERROR
func (l *logger) Errorw(msg string, args ...interface{}) {
	l.slogger.Errorw(msg, args...)
}

// Error displays a message, level ERROR
func (l *logger) Error(args ...interface{}) {
	l.slogger.Error(args...)
}

// Fatalf displays a message with formatting, level FATAL
func (l *logger) Fatalf(format string, args ...interface{}) {
	l.slogger.Fatalf(format, args...)
}

// Fatalw displays a message with typed context args, level FATAL
func (l *logger) Fatalw(msg string, args ...interface{}) {
	l.slogger.Fatalw(msg, args...)
}

// Fatal displays a message, level FATAL
func (l *logger) Fatal(args ...interface{}) {
	l.slogger.Fatal(args...)
}

// Printf is deprecated.
func (l *logger) Printf(format string, args ...interface{}) {
	l.Infof(format, args...)
}

// Print is deprecated.
func (l *logger) Print(args ...interface{}) {
	l.Info(args...)
}

// Println is deprecated.
func (l *logger) Println(args ...interface{}) {
	l.Info(args...)
}

/* static methods */

// Debugf displays a message with formatting, level DEBUG
func Debugf(format string, args ...interface{}) {
	singletonLogger.Debugf(format, args...)
}

// Debugw displays a message with typed context args, level DEBUG
func Debugw(msg string, args ...interface{}) {
	singletonLogger.Debugw(msg, args...)
}

// Debug displays a message, level DEBUG
func Debug(args ...interface{}) {
	singletonLogger.Debug(args...)
}

// Infof displays a message with formatting, level INFO
func Infof(format string, args ...interface{}) {
	singletonLogger.Infof(format, args...)
}

// Infow displays a message with typed context args, level INFO
func Infow(msg string, args ...interface{}) {
	singletonLogger.Infow(msg, args...)
}

// Info displays a message, level INFO
func Info(args ...interface{}) {
	singletonLogger.Info(args...)
}

// Warnf displays a message with formatting, level WARN
func Warnf(format string, args ...interface{}) {
	singletonLogger.Warnf(format, args...)
}

// Warnw displays a message with typed context args, level WARN
func Warnw(msg string, args ...interface{}) {
	singletonLogger.Warnw(msg, args...)
}

// Warn displays a message, level WARN
func Warn(args ...interface{}) {
	singletonLogger.Warn(args...)
}

// Errorf displays a message with formatting, level ERROR
func Errorf(format string, args ...interface{}) {
	singletonLogger.Errorf(format, args...)
}

// Errorw displays a message with typed context args, level ERROR
func Errorw(msg string, args ...interface{}) {
	singletonLogger.Errorw(msg, args...)
}

// Error displays a message, level ERROR
func Error(args ...interface{}) {
	singletonLogger.Error(args...)
}

// Fatalf displays a message with formatting, level FATAL
func Fatalf(format string, args ...interface{}) {
	singletonLogger.Fatalf(format, args...)
}

// Fatalw displays a message with typed context args, level FATAL
func Fatalw(msg string, args ...interface{}) {
	singletonLogger.Fatalw(msg, args...)
}

// Fatal displays a message, level FATAL
func Fatal(args ...interface{}) {
	singletonLogger.Fatal(args...)
}

// Printf is deprecated.
func Printf(format string, args ...interface{}) {
	singletonLogger.Printf(format, args...)
}

// Print is deprecated.
func Print(args ...interface{}) {
	singletonLogger.Print(args...)
}

// Println is deprecated.
func Println(args ...interface{}) {
	singletonLogger.Println(args...)
}

// GetInstance returns logger instance
func GetInstance(args ...interface{}) Logger {
	return &logger{
		slogger: singletonLogger.slogger.With(args...),
	}
}
