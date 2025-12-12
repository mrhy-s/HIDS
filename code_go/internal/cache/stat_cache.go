package cache

import (
	"os"
	"sync"
	"time"
)

type StatCache struct {
	mu      sync.RWMutex
	entries map[string]*statEntry
	ttl     time.Duration
}

type statEntry struct {
	info      os.FileInfo
	timestamp time.Time
}

func NewStatCache(ttl time.Duration) *StatCache
func (sc *StatCache) Get(path string) (os.FileInfo, bool)
func (sc *StatCache) Set(path string, info os.FileInfo)
func (sc *StatCache) Invalidate(path string)
func (sc *StatCache) Cleanup()
