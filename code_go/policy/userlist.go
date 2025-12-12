package policy

import "sync"

type UserList struct {
	mu    sync.RWMutex
	users map[uint32]*UserPolicy
}

func NewUserList() *UserList
func (ul *UserList) Add(uid uint32, policy *UserPolicy)
func (ul *UserList) Remove(uid uint32)
func (ul *UserList) Get(uid uint32) *UserPolicy
func (ul *UserList) Contains(uid uint32) bool
func (ul *UserList) List() []*UserPolicy
func (ul *UserList) Reload(policies []*UserPolicy)
