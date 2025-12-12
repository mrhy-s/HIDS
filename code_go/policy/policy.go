package policy

type UserPolicy struct {
	UID        uint32
	Username   string
	AllowedOps Operations
	Exceptions []PathException
}

type PathException struct {
	Pattern    string // /home/user/* ou regex
	Operations Operations
	IsRegex    bool
}

func NewUserPolicy(uid uint32, username string, ops Operations) *UserPolicy
func (up *UserPolicy) HasPermission(op Operations) bool
func (up *UserPolicy) CheckException(path string, op Operations) bool
