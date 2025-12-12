package core

import (
	"HIDS/config"
	"HIDS/internal/cache"
	"HIDS/policy"
)

type DecisionManager struct {
	config    *config.HIDSConfig
	whitelist *policy.UserList
	blacklist *policy.UserList
	statCache *cache.StatCache
}

type Decision struct {
	Allow  bool
	Reason string
}

func NewDecisionManager(cfg *config.HIDSConfig) *DecisionManager
func (dm *DecisionManager) MakeDecision(uid, gid uint32, path string, op policy.Operations) Decision
func (dm *DecisionManager) checkBlacklist(uid uint32) *Decision
func (dm *DecisionManager) checkWhitelist(uid uint32, path string, op policy.Operations) *Decision
func (dm *DecisionManager) checkSystemPermissions(uid, gid uint32, path string, op policy.Operations) Decision
