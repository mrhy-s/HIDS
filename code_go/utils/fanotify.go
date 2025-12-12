package utils

func InitFanotify(blocking bool) (int, error)
func MarkPath(fd int, path string, recursive bool, events uint64) error
func MaskToString(mask uint64) string
func SendResponse(fd int, eventFd int32, allow bool) error
