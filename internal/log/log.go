package log

import (
	"fmt"
	"log"
	"os"
)

const LOG_OUTPUT_BUFFER = 1024

const (
	// LevelDebug represents a debug level message.
	LevelDebug = iota
	// LevelInfo represents an informational level message.
	LevelInfo
	// LevelNotice represents a notice level message.
	LevelNotice
	// LevelWarn represents a warning level message.
	LevelWarn
	// LevelError represents an error level message.
	LevelError
)

// logMesg is a struct to hold a log message and its corresponding level.
type logMesg struct {
	Level int
	Mesg  string
}

// LoggerHandler is the interface that all log output handlers must implement.
// It defines the methods for setting up the handler and writing a log message.
type LoggerHandler interface {
	Setup(config map[string]interface{}) error
	Write(mesg *logMesg)
}

// GoDNSLogger is a custom logger that manages message levels and output handlers.
// It uses a channel to handle log messages asynchronously.
type GoDNSLogger struct {
	level   int
	mesgs   chan *logMesg
	outputs map[string]LoggerHandler
}

// NewLogger creates a new GoDNSLogger instance.
// It starts the logger's Run method in a separate goroutine.
func NewLogger() *GoDNSLogger {
	logger := &GoDNSLogger{
		mesgs:   make(chan *logMesg, LOG_OUTPUT_BUFFER),
		outputs: make(map[string]LoggerHandler),
	}
	go logger.Run()
	return logger
}

// SetLogger registers a new LoggerHandler for the specified handler type.
// It panics if the handlerType is not "console" or "file".
func (l *GoDNSLogger) SetLogger(handlerType string, config map[string]interface{}) {
	var handler LoggerHandler
	switch handlerType {
	case "console":
		handler = NewConsoleHandler()
	case "file":
		handler = NewFileHandler()
	default:
		panic("Unknown log handler.")
	}

	handler.Setup(config)
	l.outputs[handlerType] = handler
}

// SetLevel sets the current logging level. Messages with a lower level will be discarded.
func (l *GoDNSLogger) SetLevel(level int) {
	l.level = level
}

// Run is the main loop for the logger. It listens for messages on the
// message channel and writes them to all registered handlers.
func (l *GoDNSLogger) Run() {
	for {
		select {
		case mesg := <-l.mesgs:
			for _, handler := range l.outputs {
				handler.Write(mesg)
			}
		}
	}
}

// writeMesg is an internal helper function that sends a formatted message
// to the logger's message channel if its level is high enough.
func (l *GoDNSLogger) writeMesg(mesg string, level int) {
	if l.level > level {
		return
	}

	lm := &logMesg{
		Level: level,
		Mesg:  mesg,
	}

	l.mesgs <- lm
}

// Debug logs a message with the LevelDebug level.
func (l *GoDNSLogger) Debug(format string, v ...interface{}) {
	mesg := fmt.Sprintf("[DEBUG] "+format, v...)
	l.writeMesg(mesg, LevelDebug)
}

// Info logs a message with the LevelInfo level.
func (l *GoDNSLogger) Info(format string, v ...interface{}) {
	mesg := fmt.Sprintf("[INFO] "+format, v...)
	l.writeMesg(mesg, LevelInfo)
}

// Notice logs a message with the LevelNotice level.
func (l *GoDNSLogger) Notice(format string, v ...interface{}) {
	mesg := fmt.Sprintf("[NOTICE] "+format, v...)
	l.writeMesg(mesg, LevelNotice)
}

// Warn logs a message with the LevelWarn level.
func (l *GoDNSLogger) Warn(format string, v ...interface{}) {
	mesg := fmt.Sprintf("[WARN] "+format, v...)
	l.writeMesg(mesg, LevelWarn)
}

// Error logs a message with the LevelError level.
func (l *GoDNSLogger) Error(format string, v ...interface{}) {
	mesg := fmt.Sprintf("[ERROR] "+format, v...)
	l.writeMesg(mesg, LevelError)
}

// ConsoleHandler is a LoggerHandler that writes log messages to the standard output.
type ConsoleHandler struct {
	level  int
	logger *log.Logger
}

// NewConsoleHandler creates a new ConsoleHandler instance.
func NewConsoleHandler() LoggerHandler {
	return new(ConsoleHandler)
}

// Setup configures the ConsoleHandler with settings from the provided map.
// It initializes a standard log.Logger to write to os.Stdout.
func (h *ConsoleHandler) Setup(config map[string]interface{}) error {
	if _level, ok := config["level"]; ok {
		level := _level.(int)
		h.level = level
	}
	h.logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	return nil
}

// Write checks the message level and writes it to the console if it meets the handler's level.
func (h *ConsoleHandler) Write(lm *logMesg) {
	if h.level <= lm.Level {
		h.logger.Println(lm.Mesg)
	}
}

// FileHandler is a LoggerHandler that writes log messages to a file.
type FileHandler struct {
	level  int
	file   string
	logger *log.Logger
}

// NewFileHandler creates a new FileHandler instance.
func NewFileHandler() LoggerHandler {
	return new(FileHandler)
}

// Setup configures the FileHandler with settings from the provided map.
// It opens the specified file and initializes a standard log.Logger to write to it.
func (h *FileHandler) Setup(config map[string]interface{}) error {
	if level, ok := config["level"]; ok {
		h.level = level.(int)
	}

	if file, ok := config["file"]; ok {
		h.file = file.(string)
		output, err := os.OpenFile(h.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}

		h.logger = log.New(output, "", log.Ldate|log.Ltime)
	}

	return nil
}

// Write checks the message level and writes it to the file if it meets the handler's level.
func (h *FileHandler) Write(lm *logMesg) {
	if h.logger == nil {
		return
	}

	if h.level <= lm.Level {
		h.logger.Println(lm.Mesg)
	}
}

// --- Global Logger Instance and Helper Functions ---
// The following code provides a public, package-level interface for logging,
// making it easy to use the custom logger without needing to manage an instance.

// logger is the global, package-level logger instance.
var logger *GoDNSLogger

// init is a special Go function that runs automatically when the package is imported.
// It initializes the global logger instance.
func init() {
	logger = NewLogger()
}

// Debug logs a message with the LevelDebug level using the global logger.
func Debug(format string, v ...interface{}) {
	logger.Debug(format, v...)
}

// Info logs a message with the LevelInfo level using the global logger.
func Info(format string, v ...interface{}) {
	logger.Info(format, v...)
}

// Notice logs a message with the LevelNotice level using the global logger.
func Notice(format string, v ...interface{}) {
	logger.Notice(format, v...)
}

// Warn logs a message with the LevelWarn level using the global logger.
func Warn(format string, v ...interface{}) {
	logger.Warn(format, v...)
}

// Error logs a message with the LevelError level using the global logger.
func Error(format string, v ...interface{}) {
	logger.Error(format, v...)
}
