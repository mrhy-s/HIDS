package events

import (
	"os"
	"sync"
)

type SecurityLogger struct {
	file    *os.File
	mu      sync.Mutex
	format  LogFormat
	filters []EventFilter
}

type LogFormat int

const (
	FormatText LogFormat = iota
	FormatJSON
	FormatCEF // Common Event Format
)

type EventFilter func(*AccessEvent) bool

func NewSecurityLogger(path string, format LogFormat) (*SecurityLogger, error)
func (sl *SecurityLogger) Log(event *AccessEvent)
func (sl *SecurityLogger) LogJSON(event *AccessEvent)
func (sl *SecurityLogger) LogCEF(event *AccessEvent)
func (sl *SecurityLogger) AddFilter(filter EventFilter)
func (sl *SecurityLogger) Rotate() error
func (sl *SecurityLogger) Close() error
