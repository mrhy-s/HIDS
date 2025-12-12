package core

import (
	"HIDS/config"
	"HIDS/events"
)

type FileWatcher struct {
	fd          int
	target      config.WatchTarget
	config      *config.HIDSConfig
	eventChan   chan *events.AccessEvent
	stopChan    chan struct{}
	decisionMgr *DecisionManager
}

func NewFileWatcher(target config.WatchTarget, cfg *config.HIDSConfig, eventChan chan *events.AccessEvent) (*FileWatcher, error)
func (fw *FileWatcher) Start()
func (fw *FileWatcher) Stop()
func (fw *FileWatcher) processEvents()
func (fw *FileWatcher) handleEvents(data []byte)
func (fw *FileWatcher) sendResponse(fd int32, allow bool) error
