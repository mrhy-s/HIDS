package events

import (
	"HIDS/policy"
	"time"
)

type AccessEvent struct {
	Timestamp time.Time
	PID       int32
	UID       uint32
	GID       uint32
	Username  string
	Path      string
	Operation policy.Operations
	Allowed   bool
	Reason    string
	Duration  time.Duration // Temps de décision
}

func NewAccessEvent(pid int32, uid, gid uint32, path string, op policy.Operations) *AccessEvent
func (e *AccessEvent) SetDecision(allowed bool, reason string)
func (e *AccessEvent) String() string
