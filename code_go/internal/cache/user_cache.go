package cache

import (
	"sync"
	"time"
)

type UserCache struct {
	mu    sync.RWMutex
	users map[uint32]*userEntry
	ttl   time.Duration
}

type userEntry struct {
	username  string
	timestamp time.Time
}

func NewUserCache(ttl time.Duration) *UserCache
func (uc *UserCache) Get(uid uint32) (string, bool)
func (uc *UserCache) Set(uid uint32, username string)
func (uc *UserCache) Cleanup()
