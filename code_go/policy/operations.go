package policy

type Operations uint8

const (
	OpNone Operations = 0
	OpRead Operations = 1
	OpWrite
	OpExec
	OpDelete
	OpAll = OpRead | OpWrite | OpExec | OpDelete
)

func (o Operations) String() string
func (o Operations) Has(op Operations) bool
func ParseOperations(ops []string) (Operations, error)
