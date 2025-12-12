package config

type HIDSConfig struct {
	LogFile      string
	LogFormat    string
	Workers      int
	WatchedPaths []WatchTarget
	Whitelist    WhitelistConfig
	Blacklist    BlacklistConfig
	Performance  PerformanceConfig
}

type WatchTarget struct {
	Path        string
	Recursive   bool
	MinUID      uint32
	AllowedGIDs []uint32
	Events      []string // open, read, write, exec
}

type WhitelistConfig struct {
	Users []UserPolicyConfig
}

type BlacklistConfig struct {
	UIDs []uint32
}

type UserPolicyConfig struct {
	UID        uint32
	Username   string
	AllowedOps []string
	Exceptions []ExceptionConfig
}

type ExceptionConfig struct {
	Pattern    string
	Operations []string
	IsRegex    bool
}

type PerformanceConfig struct {
	StatCacheTTL      int // secondes
	UserCacheTTL      int
	MaxEventQueueSize int
}
