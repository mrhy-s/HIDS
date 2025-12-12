package core

import (
	"HIDS/policy"
	"os"
)

type PermissionChecker struct{}

func NewPermissionChecker() *PermissionChecker
func (pc *PermissionChecker) CheckOwnerPerms(mode os.FileMode, op policy.Operations) Decision
func (pc *PermissionChecker) CheckGroupPerms(mode os.FileMode, op policy.Operations) Decision
func (pc *PermissionChecker) CheckOthersPerms(mode os.FileMode, op policy.Operations) Decision
func (pc *PermissionChecker) HasPermission(fileMode os.FileMode, uid, fileUID, gid, fileGID uint32, op policy.Operations) Decision
