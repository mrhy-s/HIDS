package utils

func ReadProcStatus(pid int32) (map[string]string, error)
func ReadProcCmdline(pid int32) (string, error)
func GetFilePathFromFD(fd int32) (string, error)
func GetProcessOwner(pid int32) (uid, gid uint32, err error)
