package config

func Load(path string) (*HIDSConfig, error)
func LoadYAML(path string) (*HIDSConfig, error)
func LoadJSON(path string) (*HIDSConfig, error)
func (cfg *HIDSConfig) Validate() error
func (cfg *HIDSConfig) ApplyDefaults()
