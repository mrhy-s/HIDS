package core

import (
	"HIDS/config"
	"HIDS/events"
	"sync"
)

type HIDS struct {
	config    *config.HIDSConfig
	watchers  []*FileWatcher
	eventChan chan *events.AccessEvent
	logger    *events.SecurityLogger
	wg        sync.WaitGroup
	stopChan  chan struct{}
}

func NewHIDS(cfg *config.HIDSConfig) (*HIDS, error)
func (h *HIDS) Start() error
func (h *HIDS) Stop()
func (h *HIDS) startEventProcessor()
