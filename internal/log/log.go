package log

import (
	"fmt"
	"log"
	"os"
)

// LOG_OUTPUT_BUFFER specifies the size of the channel buffer for log messages.
// A buffered channel prevents blocking when log messages are sent, especially
// during high-traffic periods.
const LOG_OUTPUT_BUFFER = 1024

// Log levels define the severity of a log message.
// The higher the value, the more severe the log level.
const (
	LevelDebug = iota // Used for fine-grained informational events.
	LevelInfo         // Used for general operational messages.
	LevelNotice       // Used for noteworthy events that are not errors.
	LevelWarn         // Used for potential problems or non-critical issues.
	LevelError        // Used for critical errors that require immediate attention.
)

// logMesg represents a log message, containing its severity level and the message string.
type logMesg struct {
	Level int
	Mesg  string
}

// LoggerHandler is an interface that defines the contract for any log output handler.
// Handlers are responsible for writing log messages to specific destinations,
// such as the console, a file, or a network service.
type LoggerHandler interface {
	Setup(config map[string]interface{}) error
	Write(mesg *logMesg)
}

// GoDNSLogger is the core logging component. It manages multiple handlers
// and dispatches log messages to them based on their configuration.
type GoDNSLogger struct {
	level   int
	mesgs   chan *logMesg
	outputs map[string]LoggerHandler
}

// NewLogger creates and returns a new GoDNSLogger instance.
// It initializes the message channel and the handler map, and starts
// the main logger goroutine to process messages.
func NewLogger() *GoDNSLogger {
	logger := &GoDNSLogger{
		mesgs:   make(chan *logMesg, LOG_OUTPUT_BUFFER),
		outputs: make(map[string]LoggerHandler),
	}
	go logger.Run()
	return logger
}

// SetLogger registers a new LoggerHandler with the GoDNSLogger.
// It configures the handler and adds it to the output map.
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

// SetLevel sets the minimum log level for the logger.
// Messages with a level lower than this value will be ignored.
func (l *GoDNSLogger) SetLevel(level int) {
	l.level = level
}

// Run is the main event loop for the logger. It continuously reads
// messages from the channel and dispatches them to all registered handlers.
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

// writeMesg formats a log message and sends it to the internal message channel.
// It first checks if the message's level is high enough to be processed.
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

// Debug logs a message at the Debug level.
func (l *GoDNSLogger) Debug(format string, v ...interface{}) {
	mesg := fmt.Sprintf("[DEBUG] "+format, v...)
	l.writeMesg(mesg, LevelDebug)
}

// Info logs a message at the Info level.
func (l *GoDNSLogger) Info(format string, v ...interface{}) {
	mesg := fmt.Sprintf("[INFO] "+format, v...)
	l.writeMesg(mesg, LevelInfo)
}

// Notice logs a message at the Notice level.
func (l *GoDNSLogger) Notice(format string, v ...interface{}) {
	mesg := fmt.Sprintf("[NOTICE] "+format, v...)
	l.writeMesg(mesg, LevelNotice)
}

// Warn logs a message at the Warn level.
func (l *GoDNSLogger) Warn(format string, v ...interface{}) {
	mesg := fmt.Sprintf("[WARN] "+format, v...)
	l.writeMesg(mesg, LevelWarn)
}

// Error logs a message at the Error level.
func (l *GoDNSLogger) Error(format string, v ...interface{}) {
	mesg := fmt.Sprintf("[ERROR] "+format, v...)
	l.writeMesg(mesg, LevelError)
}

// ConsoleHandler handles log output to the console (os.Stdout).
type ConsoleHandler struct {
	level  int
	logger *log.Logger
}

// NewConsoleHandler creates a new ConsoleHandler.
func NewConsoleHandler() LoggerHandler {
	return new(ConsoleHandler)
}

// Setup initializes the ConsoleHandler, setting up the output destination and log level.
func (h *ConsoleHandler) Setup(config map[string]interface{}) error {
	if _level, ok := config["level"]; ok {
		level := _level.(int)
		h.level = level
	}
	h.logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	return nil
}

// Write checks if the message's level is sufficient and writes it to the console.
func (h *ConsoleHandler) Write(lm *logMesg) {
	if h.level <= lm.Level {
		h.logger.Println(lm.Mesg)
	}
}

// FileHandler handles log output to a file.
type FileHandler struct {
	level  int
	file   string
	logger *log.Logger
}

// NewFileHandler creates a new FileHandler.
func NewFileHandler() LoggerHandler {
	return new(FileHandler)
}

// Setup initializes the FileHandler, opening the log file and setting the log level.
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

// Write checks the message level and writes it to the file.
func (h *FileHandler) Write(lm *logMesg) {
	if h.logger == nil {
		return
	}

	if h.level <= lm.Level {
		h.logger.Println(lm.Mesg)
	}
}

// --- Global Logger Interface ---

// Logger is the single, global instance of the GoDNSLogger.
// It provides a convenient way to access logging functions from any part of the application.
var Logger *GoDNSLogger

// init is a special Go function that runs automatically when the package is imported.
// It initializes the global Logger instance.
func init() {
	Logger = NewLogger()
}

// Debug logs a message using the global logger at the Debug level.
func Debug(format string, v ...interface{}) {
	Logger.Debug(format, v...)
}

// Info logs a message using the global logger at the Info level.
func Info(format string, v ...interface{}) {
	Logger.Info(format, v...)
}

// Notice logs a message using the global logger at the Notice level.
func Notice(format string, v ...interface{}) {
	Logger.Notice(format, v...)
}

// Warn logs a message using the global logger at the Warn level.
func Warn(format string, v ...interface{}) {
	Logger.Warn(format, v...)
}

// Error logs a message using the global logger at the Error level.
func Error(format string, v ...interface{}) {
	Logger.Error(format, v...)
}
