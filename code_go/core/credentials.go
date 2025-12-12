package core

type ProcessInfo struct {
	PID      int32
	UID      uint32
	GID      uint32
	Username string
	Comm     string
	Cmdline  string
}

func GetProcessInfo(pid int32) (*ProcessInfo, error)
func GetProcessCreds(pid int32) (uid, gid uint32, err error)
func GetProcessUsername(uid uint32) string
func GetProcessComm(pid int32) (string, error)
func GetProcessCmdline(pid int32) (string, error)
